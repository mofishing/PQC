"""
符号执行层：精确参数推导和影响面分析
整合原 analysis/{dataflow, wrapper, custom} 的功能
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import os
import re

from pqscan.analysis.candidate import Candidate, Location
from pqscan.analysis.base import infer_profile_reason
from pqscan.reporting.model import Finding
from pqscan.symbolic.ir_builder import build_ssa
from pqscan.symbolic.executor import SymbolicExecutor


@dataclass
class AnalysisResult:
    """符号分析结果"""
    algorithm: Optional[str] = None
    key_bits: Optional[int] = None
    mode: Optional[str] = None
    paths: List[str] = None
    constraints: List[str] = None
    confidence: float = 0.0
    
    def __post_init__(self):
        if self.paths is None:
            self.paths = []
        if self.constraints is None:
            self.constraints = []


class SymbolicAnalyzer:
    """
    符号执行分析器
    
    职责：
    1. 常量传播：推导参数值
    2. 数据流分析：追踪变量定义-使用
    3. Wrapper 展开：内联包装函数
    4. 路径探索：影响面分析
    """
    
    def __init__(self, kb: Dict[str, Any]):
        self.kb = kb
        self.executor = SymbolicExecutor()
        # ValueGraph 缓存（避免重复构建）
        self._value_graph_cache = None
        self._cached_features_hash = None
        
        # [Task 13.2.2] 函数内联器（处理 calc_keysize(64) → 1024）
        from pqscan.symbolic.function_inliner import SimpleFunctionInliner
        functions = kb.get('features', {}).get('functions', [])
        self.function_inliner = SimpleFunctionInliner(functions)
    
    def analyze_candidates(
        self,
        candidates: List[Candidate],
        code: str,
        lang: str
    ) -> List[Finding]:
        """
        Phase 2: 对候选集进行精确分析
        
        Args:
            candidates: Phase 1 输出的候选列表
            code: 源代码
            lang: 语言类型
        
        Returns:
            精确的漏洞报告列表
        """
        findings = []
        
        # 构建 SSA/IR
        ssa = build_ssa(code, lang)
        
        for candidate in candidates:
            # 对每个候选进行深度分析
            result = self._analyze_single(candidate, ssa)
            
            # 转换为 Finding
            finding = self._to_finding(candidate, result)
            findings.append(finding)
        
        return findings
    
    def analyze(self, candidate: Candidate) -> AnalysisResult:
        """
        分析单个候选点的简化接口（用于测试和独立分析）
        
        只使用 Layer 1 功能：
        - 字面量提取
        - 算法推导
        - 变量追踪
        
        Args:
            candidate: 候选点
        
        Returns:
            分析结果
        """
        result = AnalysisResult()
        
        # 1. 从字面量提取
        if candidate.literal_args:
            result = self._extract_literals(candidate)
        
        # 2. 从 API 名推导算法
        if not result.algorithm:
            inferred_algo = self._infer_algorithm_from_name(candidate.symbol)
            if inferred_algo:
                result.algorithm = inferred_algo
                result.confidence = 0.9
                # 如果算法名包含密钥长度信息（例如 AES-128），填充 key_bits
                # [Task 12.3] 不使用字面量，读规则：委托给 crypto_constants
                try:
                    from pqscan.analysis.crypto_constants import get_cipher_key_bits
                    bits = get_cipher_key_bits(inferred_algo)
                    if bits is None and candidate.symbol:
                        # fallback: 从符号名推导（如 EVP_aes_256_gcm）
                        bits = get_cipher_key_bits(candidate.symbol)
                    if bits is not None:
                        result.key_bits = bits
                        result.confidence = max(result.confidence, 0.9)
                except Exception:
                    pass
        
        # 3. 变量追踪（Layer 1 的核心功能）——只补充 _extract_literals 未能确定的字段
        if not result.key_bits or not result.algorithm:
            traced = self._trace_variables_from_candidate(candidate)
            if traced:
                # key_bits: 只在尚未确定时才更新，且只接受整数（防止用未解析字符串覆盖）
                if 'bits' in traced and not result.key_bits:
                    tv = traced['bits']
                    if isinstance(tv, int):
                        result.key_bits = tv
                    elif isinstance(tv, str):
                        ev = self._evaluate_expression(tv, candidate)
                        if isinstance(ev, int) and self._is_key_bits(ev, candidate.symbol):
                            result.key_bits = ev
                if 'key_size' in traced and not result.key_bits:
                    tv = traced['key_size']
                    if isinstance(tv, int):
                        result.key_bits = tv
                if 'mode' in traced and not result.mode:
                    result.mode = traced['mode']
                if 'algorithm' in traced and not result.algorithm:
                    result.algorithm = traced['algorithm']

        # 4. 最后兜底：若已经识别出算法，但 key_bits 仍为空，尝试从算法名直接推导
        # 例如 DES / 3DES / SM4 / ChaCha20 这类固定长度算法。
        if result.algorithm and not result.key_bits:
            try:
                from pqscan.analysis.crypto_constants import get_cipher_key_bits, get_algorithm_key_bits
                algo_name = str(result.algorithm)
                if algo_name.upper().startswith('ALG.'):
                    algo_name = algo_name.split('.', 1)[1]
                bits = get_cipher_key_bits(algo_name)
                if bits is None:
                    bits = get_algorithm_key_bits(algo_name)
                if bits is None and candidate.symbol:
                    bits = get_cipher_key_bits(candidate.symbol)
                if bits is not None:
                    result.key_bits = bits
            except Exception:
                pass
        
        return result
    
    def _analyze_single(
        self,
        candidate: Candidate,
        ssa: Any
    ) -> AnalysisResult:
        """
        分析单个候选点
        
        步骤：
        1. 常量传播：获取参数字面值
        2. 数据流分析：追踪变量来源
        3. Wrapper 分析：识别包装函数
        4. 路径探索：构建影响路径
        """
        result = AnalysisResult()

        # 0. 对于椭圆曲线构造器这类“无字面量但符号本身携带曲线信息”的场景，
        # 先直接从符号推导 key_bits，避免后续 wrapper / symbolic execution 回退到默认值。
        if candidate.symbol:
            try:
                from pqscan.analysis.crypto_constants import get_ec_curve_bits
                bits = get_ec_curve_bits(candidate.symbol)
                if bits is not None:
                    result.key_bits = bits
                    result.confidence = 0.95
            except Exception:
                pass
        
        # 1. 尝试从字面量直接获取
        if candidate.literal_args:
            literal_result = self._extract_literals(candidate)
            if literal_result.algorithm and not result.algorithm:
                result.algorithm = literal_result.algorithm
            if literal_result.key_bits and not result.key_bits:
                result.key_bits = literal_result.key_bits
            if literal_result.mode and not result.mode:
                result.mode = literal_result.mode
            if literal_result.confidence > result.confidence:
                result.confidence = literal_result.confidence
        
        # 2. 如果仍然缺少信息，进行符号执行 (合并而非覆盖)
        if not result.key_bits or not result.algorithm:
            sym_result = self._symbolic_execution(candidate, ssa)
            # 只将 symbolic 结果中存在的值填充到 result 中
            if not result.algorithm and sym_result.algorithm:
                result.algorithm = sym_result.algorithm
            if not result.key_bits and sym_result.key_bits:
                result.key_bits = sym_result.key_bits
        
        # 3. Wrapper 函数分析（检查标签而不是context）
        # 不直接覆盖已有的字面量/符号执行结果；wrapper 只补充缺失字段，避免
        # 把更精确的直接推导（例如 EC 曲线 256 位）退化成 wrapper 的默认值。
        if 'wrapper' in candidate.tags or 'is_wrapper' in candidate.tags:
            wrapper_result = self._analyze_wrapper(candidate, ssa)
            if wrapper_result.algorithm and not result.algorithm:
                result.algorithm = wrapper_result.algorithm
            if wrapper_result.key_bits and not result.key_bits:
                result.key_bits = wrapper_result.key_bits
            if wrapper_result.mode and not result.mode:
                result.mode = wrapper_result.mode
            if wrapper_result.confidence > result.confidence:
                result.confidence = wrapper_result.confidence
            if wrapper_result.paths:
                existing_paths = set(result.paths)
                for path in wrapper_result.paths:
                    if path not in existing_paths:
                        result.paths.append(path)
        
        # 4. 路径探索（影响面）
        result.paths = self._explore_paths(candidate, ssa)
        
        return result
    
    def _extract_literals(self, candidate: Candidate) -> AnalysisResult:
        """
        从字面量提取参数（基于 AST 提取的结构化数据）
        
        场景覆盖：
        1. 直接字面量：RSA_generate_key(rsa, 2048, ...)
        2. 算法名推导：EVP_aes_256_cbc() -> AES-256-CBC
        3. 多参数组合：Cipher.new(AES.MODE_CBC, key_128) -> AES-128-CBC
        4. 变量回溯：size=1024; RSA_generate_key(rsa, size, ...) -> 1024
        """
        result = AnalysisResult(confidence=1.0)
        is_hash_like = self._is_hash_like_candidate(candidate)
        
        # 1. 从 literal_args 提取（Phase 1 已提取的字面量）
        if candidate.literal_args:
            for arg_name, arg_value in candidate.literal_args.items():
                if isinstance(arg_value, int):
                    if self._is_key_bits(arg_value, candidate.symbol):
                        result.key_bits = arg_value
                    elif not is_hash_like and self._is_key_bytes(arg_value, candidate.symbol):
                        result.key_bits = arg_value * 8
                elif isinstance(arg_value, str):
                    # 字符串字面量 — 尝试识别算法名 (包括 "RSA"/"AES" 等单词标识符)
                    algo = self._infer_algorithm_from_string(arg_value)
                    if algo and not result.algorithm:
                        result.algorithm = algo
                    parsed_bits = self._parse_from_ast_or_fallback(arg_value)
                    if isinstance(parsed_bits, int) and self._is_key_bits(parsed_bits, candidate.symbol):
                        result.key_bits = parsed_bits
        
        # 2. 变量回溯（如果还没有找到密钥长度）
        if not result.key_bits and candidate.literal_args:
            traced_values = self._trace_variables_from_candidate(candidate)
            for arg_name, arg_value in traced_values.items():
                if isinstance(arg_value, int):
                    if self._is_key_bits(arg_value, candidate.symbol):
                        result.key_bits = arg_value
                        result.confidence = 0.9  # 回溯的置信度略低
                        break
                elif isinstance(arg_value, str):
                    # [Task 13.2.2] 尝试求值算术表达式 (如 "SECURITY_LEVEL * 8")
                    evaluated = self._evaluate_expression(arg_value, candidate)
                    if isinstance(evaluated, int) and self._is_key_bits(evaluated, candidate.symbol):
                        result.key_bits = evaluated
                        result.confidence = 0.85  # 表达式求值置信度略低
                        break
                    parsed_bits = self._parse_from_ast_or_fallback(arg_value)
                    if isinstance(parsed_bits, int) and self._is_key_bits(parsed_bits, candidate.symbol):
                        result.key_bits = parsed_bits
                        result.confidence = 0.85
                        break
                    if not result.algorithm:
                        algo = self._infer_algorithm_from_string(arg_value)
                        if algo:
                            result.algorithm = algo
                            result.confidence = max(result.confidence, 0.85)

        # 3. 从函数名推导算法
        if not result.algorithm:
            result.algorithm = self._infer_algorithm_from_name(candidate.symbol)
        
        # 4. 从模式常量推导
        if candidate.literal_args:
            mode = self._extract_mode(candidate.literal_args)
            if mode:
                result.mode = mode

        # 5. EC 曲线补充位数：SECP256R1 / ECGenParameterSpec("secp256r1")
        # 这类参数不是“密钥长度常量”，不能回退到 EC 的默认 192。
        if self._is_ec_like_candidate(candidate):
            try:
                from pqscan.analysis.crypto_constants import get_ec_curve_bits

                curve_hints: list[str] = []
                if candidate.symbol:
                    curve_hints.append(candidate.symbol)
                for value in (candidate.literal_args or {}).values():
                    if isinstance(value, str):
                        curve_hints.append(value)

                for hint in curve_hints:
                    bits = get_ec_curve_bits(hint)
                    if bits is not None:
                        if result.key_bits is None or result.key_bits < bits:
                            result.key_bits = bits
                        break
            except Exception:
                pass
        
        return result
    
    def _is_key_bits(self, value: int, api_name: str) -> bool:
        """判断整数是否为密钥位数（读规则，不用字面量）"""
        from pqscan.analysis.crypto_constants import get_all_valid_key_sizes
        if value in get_all_valid_key_sizes():
            return True
        # 若 API 名称提示是密钥相关，扩展到合理范围内的任意值
        if any(kw in api_name.lower() for kw in ['bits', 'key', 'size', 'length']):
            return 128 <= value <= 16384
        return False

    def _is_key_bytes(self, value: int, api_name: str) -> bool:
        """判断整数是否为密钥字节数（读规则，不用字面量）"""
        from pqscan.analysis.crypto_constants import get_all_valid_key_sizes
        valid_bytes = frozenset(s // 8 for s in get_all_valid_key_sizes() if s % 8 == 0)
        return value in valid_bytes
    
    def _infer_algorithm_from_name(self, api_name: str) -> Optional[str]:
        """
        从 API 名称推导算法（KB 优先，启发式备用）

        示例：
        - EVP_aes_256_cbc -> AES-256-CBC
        - RSA_generate_key -> RSA
        - SM4_set_key -> SM4
        """
        api_name = str(api_name or '').strip()
        if not api_name:
            return None

        # 对 digest/update/doFinal 这类过于通用的裸方法名，不做全局算法映射，
        # 避免把 Java 的 MessageDigest helper 错误映射成 hmac.digest 等其它库 API。
        generic_bare_method_names = {
            'digest', 'update', 'dofinal', 'final', 'init', 'initialize',
            'getinstance', 'generatekeypair', 'generatekey',
            'generatesecret', 'encrypt', 'decrypt', 'sign', 'verify',
            'wrap', 'unwrap',
        }
        bare_name = api_name.lower()
        if '.' not in api_name and '::' not in api_name and bare_name in generic_bare_method_names:
            return None

        # 1. KB 精确匹配优先（无字面量，读规则文件）
        try:
            from pqscan.loader import get_algorithm
            algo_info = get_algorithm(api_name)
            if algo_info and algo_info.family and algo_info.family != 'UNKNOWN':
                return algo_info.to_string()
        except Exception:
            pass

        # 2. 启发式匹配（仅作备用，覆盖 KB 未收录的 API）
        name_lower = api_name.lower()
        tokens = [t for t in re.split(r'[^a-z0-9]+', name_lower) if t]

        # RSA 变体
        if 'rsa' in name_lower:
            return 'RSA'

        # AES 变体（带密钥长度）
        if 'aes' in name_lower:
            algo = 'AES'
            # 从已有常量字典键名提取长度，避免写死字面量
            from pqscan.analysis.crypto_constants import CIPHER_KEY_BITS
            for key in CIPHER_KEY_BITS:
                if key.startswith('aes'):
                    suffix = key[3:].lstrip('-_')
                    part = suffix.split('-')[0].split('_')[0]
                    if part.isdigit() and part in api_name:
                        algo = f'AES-{part}'
                        break
            # 提取模式
            for mode in ['CBC', 'ECB', 'CFB', 'OFB', 'CTR', 'GCM', 'CCM']:
                if mode.lower() in name_lower:
                    algo = f'{algo}-{mode}'
                    break
            return algo

        # DES 变体
        has_des_token = any(t in {'des', 'des3', 'desede'} for t in tokens)
        has_3des_token = any(t in {'3des', 'des3', 'desede', 'tripledes', 'ede3'} for t in tokens)
        if has_des_token or has_3des_token:
            if has_3des_token:
                return '3DES'
            return 'DES'

        # SM 系列（中国商密）
        if 'sm2' in name_lower:
            return 'SM2'
        if 'sm3' in name_lower:
            return 'SM3'
        if 'sm4' in name_lower:
            return 'SM4'

        # 其他常见算法（注意：ECDSA 必须在 DSA 之前匹配）
        heuristic_map = [
            ('ecdsa', 'ECDSA'), ('ecdh', 'ECDH'),
            ('sha1', 'SHA1'), ('sha256', 'SHA256'),
            ('sha384', 'SHA384'), ('sha512', 'SHA512'),
            ('md5', 'MD5'), ('dsa', 'DSA'), ('dh', 'DH'),
            ('chacha', 'ChaCha20'), ('poly1305', 'Poly1305'),
        ]
        for key, algo in heuristic_map:
            if key in name_lower:
                return algo

        return None
    
    def _infer_algorithm_from_string(self, arg: str) -> Optional[str]:
        """从字符串参数推导算法名（KB 优先）"""
        # 1. Try KB algorithm_by_name (handles "AES", "RSA", "DES", ...)
        try:
            from pqscan.loader.algorithm_mapper import get_global_mapper
            mapper = get_global_mapper()
            algo_info = mapper.get_algorithm_by_name(arg)
            if algo_info and algo_info.family:
                return algo_info.family
        except Exception:
            pass

        # 2. Substring heuristic fallback (for compound strings like "AES/CBC/PKCS5Padding")
        arg_upper = arg.upper()
        # Order matters: longer names first to avoid partial-match shadowing
        for algo in ['ECDSA', 'ECDH', '3DES', 'CHACHA20', 'SHA256', 'SHA512',
                     'SHA384', 'SHA224', 'SHA1', 'RSA', 'AES', 'DES',
                     'SM2', 'SM3', 'SM4', 'MD5', 'DSA', 'DH']:
            if algo in arg_upper:
                return algo

        return None
    
    def _extract_mode(self, arguments: Dict[str, Any]) -> Optional[str]:
        """从参数字典中提取加密模式"""
        for arg_name, arg_value in arguments.items():
            if 'mode' in arg_name.lower():
                if isinstance(arg_value, str):
                    mode_upper = arg_value.upper()
                    for mode in ['CBC', 'ECB', 'CFB', 'OFB', 'CTR', 'GCM', 'CCM']:
                        if mode in mode_upper:
                            return mode
        
        return None

    def _is_hash_like_candidate(self, candidate: Candidate) -> bool:
        symbol_text = str(getattr(candidate, 'symbol', '') or '').lower()
        profile_text = str(getattr(candidate, 'profile_id', '') or '').upper()
        if profile_text.startswith('ALG.SHA') or profile_text.startswith('ALG.MD5'):
            return True
        return any(
            token in symbol_text
            for token in (
                'hashlib.', '.hexdigest', '.digest', 'md5', 'sha1', 'sha224',
                'sha256', 'sha384', 'sha512', 'hashes.sha', 'hashes.md5',
            )
        )

    def _is_ec_like_candidate(self, candidate: Candidate) -> bool:
        symbol_text = str(getattr(candidate, 'symbol', '') or '').lower()
        profile_text = str(getattr(candidate, 'profile_id', '') or '').upper()
        if profile_text.startswith('ALG.EC') or 'ECDH' in profile_text or 'ECDSA' in profile_text:
            return True
        return any(
            token in symbol_text
            for token in ('ecdh', 'ecdsa', 'ec_key', 'curve', 'secp', 'x25519', 'x448', 'ed25519', 'ed448')
        )
    
    def _evaluate_expression(self, expression: str, candidate: Candidate) -> Any:
        """
        求值算术表达式（如 "SECURITY_LEVEL * 8"）
        
        策略：
        1. 提取表达式中的变量
        2. 追踪变量值
        3. 替换变量后求值
        
        Args:
            expression: 算术表达式字符串
            candidate: 候选点（用于获取上下文）
        
        Returns:
            求值结果（int）或原表达式（str）
        """
        import re
        
        # 提取表达式中的标识符（变量名）
        identifiers = re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', expression)
        if not identifiers:
            # 没有变量，尝试直接求值
            try:
                return eval(expression, {"__builtins__": {}})
            except:
                return expression
        
        # 获取特征数据
        features = self.kb.get('features', {})
        var_assignments = features.get('var_assignments', [])
        
        # 追踪每个变量的值
        var_values = {}
        for var_name in identifiers:
            # 在var_assignments中查找变量定义
            for item in var_assignments:
                if item.get('name') == var_name:
                    value = item.get('value')
                    # 尝试将value转为整数
                    if isinstance(value, int):
                        var_values[var_name] = value
                    elif isinstance(value, str):
                        try:
                            var_values[var_name] = int(value)
                        except ValueError:
                            pass
                    break
        
        # 如果所有变量都找到了值，求值表达式
        if len(var_values) == len(identifiers):
            try:
                # 安全求值：只允许基本算术运算
                safe_dict = {"__builtins__": {}}
                safe_dict.update(var_values)
                result = eval(expression, safe_dict)
                return result
            except Exception:
                return expression
        else:
            return expression
    
    def _trace_variables_from_candidate(self, candidate: Candidate) -> Dict[str, Any]:
        """
        从候选点回溯变量定义（多层策略）
        
        **策略层次：**
        1. SSA def-use 链（最精确，自动 scope-aware）
        1.5. ValueGraph Partial SSA（后向切片 + 稀疏求值）
        2. AST var_assignments（回退方案）
        3. 跨函数参数追踪（深度追踪）
        
        Args:
            candidate: 候选点
        
        Returns:
            {参数名: 回溯到的值} 映射
        """
        traced_values = {}
        
        # 从 kb 获取 AST 提取的特征（Phase 1 的输出）
        features = self.kb.get('features')
        if not features:
            # 降级：如果没有 features，尝试重新提取
            code = self.kb.get('code', '')
            lang = candidate.language or self.kb.get('lang', 'c')
            if code:
                from pqscan.abstract_syntax_tree import extract_features
                features = extract_features(code, lang)
                self.kb['features'] = features
            else:
                return traced_values
        
        # 尝试构建 SSA（如果可用）
        ssa_function = self._try_build_ssa_for_candidate(candidate)
        
        # 【层1.5】尝试构建 ValueGraph（Partial SSA）
        value_graph = self._try_build_value_graph(candidate, features)
        # print(f"[DEBUG] ValueGraph built: {value_graph is not None}, nodes: {len(value_graph.nodes) if value_graph else 0}")
        
        # 从 literal_args 中找到变量名，然后回溯
        for arg_name, arg_value in candidate.literal_args.items():
            # print(f"[DEBUG] Tracing arg: {arg_name} = {arg_value}")
            
            if not isinstance(arg_value, str) or not arg_value.isidentifier():
                continue
            
            # 【层1】尝试 SSA def-use 链（最精确）
            if ssa_function:
                constant_value = ssa_function.get_constant_value(arg_value, candidate.location.line)
                if constant_value is not None:
                    traced_values[arg_name] = constant_value
                    continue
            
            # 【层1.5】尝试 ValueGraph 后向切片
            if value_graph:
                traced_value = self._trace_with_value_graph(
                    value_graph, 
                    arg_value, 
                    candidate.location.line
                )
                if traced_value is not None:
                    # [Task 13.2.2] 检测函数调用：如果ValueGraph返回函数名，跳过让Layer 3处理
                    if isinstance(traced_value, str):
                        # 检查是否是已知函数
                        functions = features.get('functions', [])
                        func_names = [f.get('name') for f in functions]
                        if traced_value not in func_names:
                            # 字符串值：保存为备选，但继续让 Layer 2 尝试 ast_info 精化
                            # 例如 'make([]byte, keySize)' 可被精化为 128（整数）
                            traced_values[arg_name] = traced_value
                            # 不 continue，让 Layer 2 有机会覆盖为更精确的整数结果
                        # 是函数名，让Layer 3处理
                    else:
                        # 数值结果，正常保存并跳过后续层
                        traced_values[arg_name] = traced_value
                        continue
            
            # 【层2】从 var_assignments 直接查找（AST 提取）
            var_assignments = features.get('var_assignments', {})
            traced_value = self._lookup_variable_in_assignments(
                arg_value, 
                var_assignments, 
                candidate.location.line
            )
            
            if traced_value is not None:
                traced_values[arg_name] = traced_value
                continue
            
            # 【层3】从 calls 中查找赋值（例如：size = get_key_size()）
            calls = features.get('calls', [])
            traced_value = self._lookup_variable_from_calls(
                arg_value,
                calls,
                candidate.location.line
            )
            
            if traced_value is not None:
                traced_values[arg_name] = traced_value
                continue
            
            # 【层4】跨函数参数追踪（函数参数从调用点传递）
            traced_value = self._trace_parameter(candidate, arg_value)
            
            if traced_value is not None:
                traced_values[arg_name] = traced_value
        
        return traced_values
    
    def _try_build_ssa_for_candidate(self, candidate: Candidate) -> Optional[Any]:
        """
        尝试为候选点所在的函数构建 SSA
        
        Args:
            candidate: 候选点
        
        Returns:
            SSAFunction 对象，如果失败则返回 None
        """
        try:
            # 查找候选点所在的函数
            features = self.kb.get('features', {})
            functions = features.get('functions', [])
            
            if not functions:
                return None
            
            # 找到包含候选点的函数
            target_func = None
            for func in functions:
                start_line = func.get('start_line', 0)
                end_line = func.get('end_line', 0)
                if start_line <= candidate.location.line <= end_line:
                    target_func = func
                    break
            
            if not target_func:
                return None
            
            # 尝试构建 SSA
            from pqscan.symbolic.ir_builder import build_ssa
            code = self.kb.get('code', '')
            lang = candidate.language or self.kb.get('lang', 'c')
            
            if not code:
                return None
            
            # 构建完整的 SSA，然后查找目标函数
            ssa_module = build_ssa(code, lang)
            
            if hasattr(ssa_module, 'functions'):
                func_name = target_func.get('name', '')
                for ssa_func in ssa_module.functions:
                    if ssa_func.name == func_name:
                        return ssa_func
            elif hasattr(ssa_module, 'name'):
                # 单函数模式
                if ssa_module.name == target_func.get('name', ''):
                    return ssa_module
            
            return None
            
        except Exception as e:
            # SSA 构建失败，静默回退到 AST 方法
            # print(f"[DEBUG] SSA build failed: {e}")
            return None
    
    def _try_build_value_graph(self, candidate: Candidate, features: Dict) -> Optional[Any]:
        """
        尝试为候选点构建 ValueGraph（Partial SSA）- 带缓存优化
        
        缓存策略：
        - 如果 features 未变化，复用上次构建的 ValueGraph
        - 避免为同一文件的多个候选重复构建
        
        Args:
            candidate: 候选点
            features: AST 提取的特征
        
        Returns:
            ValueGraph 对象，如果失败则返回 None
        """
        try:
            from pqscan.symbolic.value_graph import ASTValueGraphBuilder
            
            # 计算 features 哈希（用于缓存判断）
            var_assignments = features.get('var_assignments', [])
            if not isinstance(var_assignments, list):
                return None
            
            if not var_assignments:
                return None
            
            # 简单哈希：var_assignments 长度 + 前几个变量名
            features_hash = len(var_assignments)
            if var_assignments:
                features_hash = (features_hash, 
                                tuple((a.get('name'), a.get('line')) 
                                      for a in var_assignments[:5]))
            
            # 检查缓存
            if (self._value_graph_cache is not None and 
                self._cached_features_hash == features_hash):
                # print(f"[DEBUG] ValueGraph: Using cached graph")
                return self._value_graph_cache
            
            # 构建 ValueGraph
            builder = ASTValueGraphBuilder()
            lang = candidate.language or 'c'
            graph = builder.build(features, lang)
            
            if not graph.nodes:
                return None
            
            # 更新缓存
            self._value_graph_cache = graph
            self._cached_features_hash = features_hash
            
            # print(f"[DEBUG] ValueGraph: Built successfully with {len(graph.nodes)} nodes")
            return graph
            
        except Exception as e:
            # ValueGraph 构建失败，静默回退
            # print(f"[DEBUG] ValueGraph build failed: {e}")
            # import traceback
            # traceback.print_exc()
            return None
    
    def _trace_with_value_graph(
        self, 
        graph: Any, 
        var_name: str, 
        target_line: int
    ) -> Optional[Any]:
        """
        使用 ValueGraph 后向切片追踪变量值
        
        流程：
        1. 找到目标变量的定义节点（作为 slice criterion）
        2. 后向切片获取依赖子图
        3. 稀疏求值计算最终值
        
        Args:
            graph: ValueGraph 对象
            var_name: 变量名
            target_line: 目标行号
        
        Returns:
            追踪到的值，失败返回 None
        """
        try:
            # 找到目标变量的定义节点
            target_node = None
            for node in graph.nodes:
                if node.node_type.name == 'VAR_DEF' and node.name == var_name:
                    # 确保是目标行之前的定义
                    node_line = node.metadata.get('line', 0) if node.metadata else 0
                    if not node_line and hasattr(node, 'location') and node.location:
                        node_line = node.location.line
                    
                    if node_line < target_line:
                        target_node = node
            
            if not target_node:
                # Debug: 没找到目标节点
                # print(f"[DEBUG] ValueGraph: No VAR_DEF node found for '{var_name}' before line {target_line}")
                # print(f"[DEBUG] Available nodes: {[(node.node_type.name, node.name, getattr(node, 'location', None)) for node in graph.nodes]}")
                return None
            
            # 后向切片
            slice_nodes = graph.backward_slice(target_node, max_depth=10)
            
            if not slice_nodes:
                # print(f"[DEBUG] ValueGraph: Backward slice for node {target_node} is empty")
                return None
            
            # 稀疏求值
            values = graph.sparse_evaluate_slice(slice_nodes)
            
            # 返回目标变量的值
            result = values.get(target_node)
            
            # 尝试解析 crypto 调用
            if isinstance(result, dict):
                # 例如：{"bytes": 16, "bits": 128}
                if 'bits' in result:
                    return result['bits']
                elif 'key_bits' in result:
                    return result['key_bits']
            
            # 如果返回的是字符串表达式，尝试解析
            if isinstance(result, str):
                parsed = self._parse_crypto_expression(result)
                if parsed:
                    return parsed
            
            # Debug: 显示原始结果
            # if result and not isinstance(result, (int, float)):
            #     print(f"[DEBUG] ValueGraph: Got non-numeric result: {result} (type={type(result)})")
            
            return result
            
        except Exception as e:
            # 失败则返回 None
            # print(f"[DEBUG] ValueGraph trace failed: {e}")
            # import traceback
            # traceback.print_exc()
            return None
    
    def _lookup_variable_in_assignments(
        self, 
        var_name: str, 
        var_assignments: Any,
        target_line: int
    ) -> Optional[Any]:
        """
        从 AST 提取的 var_assignments 中查找变量值（支持 scope-aware）
        
        Args:
            var_name: 变量名
            var_assignments: AST 提取的变量赋值数据（dict 或 list）
            target_line: 目标行号（只查找此行之前的赋值）
        
        Returns:
            变量值（如果找到），否则 None
        """
        # 首先找到目标行所在的函数
        features = self.kb.get('features', {})
        functions = features.get('functions', [])
        target_func_name = None
        
        for func in functions:
            start_line = func.get('start_line', 0)
            end_line = func.get('end_line', 999999)
            if start_line <= target_line <= end_line:
                target_func_name = func.get('name', '')
                break
        
        # 处理两种格式
        if isinstance(var_assignments, dict):
            # 格式1（旧格式）：{"var_name": value}
            value = var_assignments.get(var_name)
            
            if value is None:
                return None
            
            # [Task 13.2.2] 检测函数调用：如果value看起来像函数名且在functions中，跳过
            if isinstance(value, str):
                # 检查是否是已知函数
                func_names = [f.get('name') for f in functions]
                if value in func_names:
                    return None
            
            # 如果 AST 已解析为 int/str，直接返回
            if isinstance(value, (int, str)):
                return value
            
            # 否则尝试解析文本（后备方案）
            return self._parse_value_from_text(str(value))
        
        elif isinstance(var_assignments, list):
            # 格式2（新格式）：[{"name": "var_name", "value": ..., "line": 10, "function": "main"}]
            # 优先查找同一函数内的赋值
            candidates = []
            
            for assignment in var_assignments:
                if not isinstance(assignment, dict):
                    continue
                
                name = assignment.get('name')
                line = assignment.get('line', 0)
                func = assignment.get('function', '')
                
                # 只查找目标行之前或同一行更早表达式中的赋值。Go 短声明常见于
                # `key := make([]byte, 32); aes.NewCipher(key)` 这种同一行代码。
                if name == var_name and line <= target_line:
                    candidates.append(assignment)
            
            # 如果有多个候选，优先选择同一函数内的，且离目标行最近的
            if not candidates:
                return None
            
            # 过滤出同一函数内的赋值
            same_func_candidates = [c for c in candidates if c.get('function') == target_func_name]
            
            # 如果同一函数内有赋值，使用最近的
            if same_func_candidates:
                # 按行号降序排序，取第一个（最接近的）
                same_func_candidates.sort(key=lambda x: x.get('line', 0), reverse=True)
                assignment = same_func_candidates[0]
            else:
                # 否则使用最近的任意赋值
                candidates.sort(key=lambda x: x.get('line', 0), reverse=True)
                assignment = candidates[0]
            
            value = assignment.get('value')
            
            # [Task 13.2.2] 检测函数调用：如果assignment有'_call_node'，跳过让Layer 3处理
            if '_call_node' in assignment:
                # 这是函数调用赋值（如 bits = calc_keysize(64)），让Layer 3处理
                return None
            
            # [Task 13.2.2] 另一个检测：value是字符串且是已知函数名
            if isinstance(value, str):
                functions = self.kb.get('features', {}).get('functions', [])
                func_names = [f.get('name') for f in functions]
                if value in func_names:
                    return None
            
            # [Task 12.3] 优先尝试 AST 结构化解析
            ast_info = assignment.get('ast_info')
            if ast_info:
                info_type = ast_info.get('type', '')

                # 【字典下标访问】rsa_bits = cfg["rsa_bits"]
                if info_type == 'subscript':
                    resolved = self._resolve_subscript_ast_info(ast_info, var_assignments, target_line)
                    if resolved is not None:
                        return resolved

                parsed = self._parse_call_from_ast_info(ast_info)
                if parsed is not None:
                    return parsed
            
            # 如果 AST 已解析，直接返回
            if isinstance(value, (int, str)):
                return value
            
            # 否则尝试从文本解析
            value_text = assignment.get('value_text', str(value))
            return self._parse_from_ast_or_fallback(value_text, ast_info)
        
        return None

    def _resolve_subscript_ast_info(
        self,
        ast_info: Dict,
        var_assignments: Any,
        target_line: int
    ) -> Optional[Any]:
        """
        解析字典下标访问：rsa_bits = cfg["rsa_bits"]

        策略：
        1. 从 ast_info 提取 object 名称 (cfg) 和 key ("rsa_bits")
        2. 在 var_assignments 中查找 cfg 的赋值
        3. 如果 cfg 的 ast_info 是字典类型，提取 key 对应的值
        4. 回退：用 ast.literal_eval 解析字符串形式的字典

        Args:
            ast_info: {"type": "subscript", "object": "cfg", "key": "rsa_bits"}
            var_assignments: AST 提取的变量赋值列表
            target_line: 目标行号

        Returns:
            key 对应的值（int/str），失败返回 None
        """
        dict_var = ast_info.get('object', '')
        key = ast_info.get('key', '')
        if not dict_var or not key:
            return None

        # 查找 dict_var 的赋值
        dict_assignment = self._lookup_variable_in_assignments(dict_var, var_assignments, target_line)

        if isinstance(dict_assignment, dict):
            # 直接是解析好的字典
            val = dict_assignment.get(key)
            if val is not None:
                return val

        if isinstance(dict_assignment, str):
            # 尝试把字符串形式的字典解析为 Python dict（无字面量，使用 ast.literal_eval）
            import ast as _ast
            try:
                parsed = _ast.literal_eval(dict_assignment)
                if isinstance(parsed, dict):
                    val = parsed.get(key)
                    if val is not None:
                        return val
            except Exception:
                pass

        # 从 var_assignments 直接查找 dict_var 的 ast_info.value
        raw_assignments = var_assignments if isinstance(var_assignments, list) else []
        for a in raw_assignments:
            if a.get('name') == dict_var and a.get('line', 0) < target_line:
                ai = a.get('ast_info', {})
                if isinstance(ai, dict) and ai.get('type') == 'dictionary':
                    dict_val = ai.get('value', {})
                    if isinstance(dict_val, dict):
                        val = dict_val.get(key)
                        if val is not None:
                            return val

        return None

    def _lookup_variable_from_calls(
        self,
        var_name: str,
        calls: List[Dict],
        target_line: int
    ) -> Optional[Any]:
        """
        从函数调用结果中查找变量值
        
        场景：size = get_key_size(128)  # 如果 get_key_size 返回参数
        
        [Task 13.2.2] 新增：支持简单函数内联
        场景：bits = calc_keysize(64) → 内联为 64 * 16 → 求值为 1024
        
        Args:
            var_name: 变量名
            calls: AST 提取的调用列表
            target_line: 目标行号
        
        Returns:
            推导的值，否则 None
        """
        # 查找赋值语句：var_name = some_call(...)
        for call in calls:
            call_line = call.get('line', 0)
            if call_line >= target_line:
                continue  # 只查找之前的调用
            
            # 检查是否赋值给目标变量
            # 某些 extractor 可能提供 assigned_to 字段
            assigned_to = call.get('assigned_to')
            
            if assigned_to == var_name:
                # [Task 13.2.2] 尝试函数内联
                func_name = call.get('symbol', '')
                args_list = call.get('args', [])
                
                # 提取参数值
                arg_values = []
                for arg in args_list:
                    if isinstance(arg, dict):
                        # 优先使用 'value' 字段（已解析的值）
                        if 'value' in arg:
                            arg_values.append(arg['value'])
                        else:
                            # 回退到 'text' 字段
                            arg_text = arg.get('text', '')
                            parsed_value = self._parse_value_from_text(arg_text)
                            if parsed_value is not None:
                                arg_values.append(parsed_value)
                    else:
                        # 直接值
                        arg_values.append(arg)
                
                # 尝试内联
                if func_name and arg_values:
                    inlined_value = self.function_inliner.inline_call(func_name, arg_values)
                    if inlined_value is not None:
                        return inlined_value
                
                # 回退：返回第一个参数（旧逻辑）
                if args_list and len(args_list) > 0:
                    first_arg = args_list[0]
                    if isinstance(first_arg, dict):
                        # 优先返回 'value' 字段
                        if 'value' in first_arg:
                            return first_arg['value']
                        arg_text = first_arg.get('text', '')
                        return self._parse_value_from_text(arg_text)
        
        return None
    
    def _trace_parameter(
        self,
        candidate: Candidate,
        param_name: str,
        max_depth: int = 10,
        _depth: int = 0
    ) -> Optional[Any]:
        """
        跨函数参数追踪：从函数调用点回溯参数值（支持多层递归）
        
        场景示例：
        ```c
        // 单层追踪
        void init_rsa(int key_bits) {
            RSA_generate_key(rsa, key_bits, ...);  // <- candidate 在这里
        }
        int main() {
            init_rsa(2048);  // <- 从这里追踪到 key_bits = 2048
        }
        
        // 多层追踪
        void low_level(int bits) {
            RSA_generate_key(rsa, bits, ...);  // <- candidate
        }
        void mid_level(int size) {
            low_level(size);  // <- 第一层追踪到 size
        }
        int main() {
            mid_level(2048);  // <- 第二层追踪到 2048
        }
        ```
        
        Args:
            candidate: 当前候选点（函数调用）
            param_name: 需要追踪的参数名（如 "key_bits"）
            max_depth: 最大递归深度（防止无限递归）
            _depth: 当前递归深度（内部使用）
        
        Returns:
            追踪到的参数值，失败返回 None
        """
        # 防止无限递归
        if _depth >= max_depth:
            return None
        features = self.kb.get('features')
        if not features:
            return None
        
        functions = features.get('functions', [])
        calls = features.get('calls', [])
        
        # Step 1: 找到包含当前 candidate 的函数定义
        containing_function = None
        for func in functions:
            func_start = func.get('start_line', func.get('line', 0))
            func_end = func.get('end_line', func_start)
            
            if func_start <= candidate.location.line <= func_end:
                containing_function = func
                break
        
        if not containing_function:
            return None  # 候选点不在任何函数内（可能是全局调用）
        
        # Step 2: 从 AST 节点提取函数名和参数列表（纯 AST，无正则）
        func_node = containing_function.get('_node')
        if not func_node:
            return None
        
        # 使用 AST 工具函数提取信息
        from pqscan.abstract_syntax_tree.extractor import node_text, extract_function_params
        from pqscan.abstract_syntax_tree.navigator import _cpp_fn_name_from_definition, _is_cpp
        
        # 提取函数名（从 AST 节点）
        func_name = None
        if _is_cpp(candidate.language):
            func_name = _cpp_fn_name_from_definition(func_node, self.kb.get('code', ''))
        else:
            # 通用方法：获取 name 或 declarator 字段
            name_node = func_node.child_by_field_name('name')
            if name_node:
                func_name = node_text(self.kb.get('code', ''), name_node).strip()
            else:
                # 尝试从 declarator 获取（C/Java）
                declarator = func_node.child_by_field_name('declarator')
                if declarator:
                    if declarator.type == 'function_declarator':
                        inner_declarator = declarator.child_by_field_name('declarator')
                        if inner_declarator and inner_declarator.type == 'identifier':
                            func_name = node_text(self.kb.get('code', ''), inner_declarator).strip()
                    elif declarator.type == 'identifier':
                        func_name = node_text(self.kb.get('code', ''), declarator).strip()
        
        if not func_name:
            return None
        
        # 提取参数列表（纯 AST，使用已有的 extract_function_params）
        params = extract_function_params(func_node, self.kb.get('code', ''), candidate.language)
        
        # Step 3: 确认 param_name 是该函数的参数
        param_index = -1
        for i, p in enumerate(params):
            if p == param_name:
                param_index = i
                break
        
        if param_index == -1:
            return None  # param_name 不是该函数的参数
        
        # Step 4: 找到所有调用该函数的调用点
        for call in calls:
            call_symbol = call.get('symbol', '')
            
            # 匹配函数名
            if call_symbol != func_name:
                # 尝试匹配最后一部分（例如：crypto.init_rsa -> init_rsa）
                if '.' in call_symbol:
                    call_symbol = call_symbol.split('.')[-1]
                if call_symbol != func_name:
                    continue
            
            # Step 5: 提取调用点的第 param_index 个参数值
            args = call.get('args', [])
            if param_index >= len(args):
                continue  # 参数数量不匹配
            
            arg = args[param_index]
            
            # 处理不同的参数格式
            if isinstance(arg, dict):
                # 格式：{"text": "2048", "value": 2048, "type": "number_literal"}
                arg_value = arg.get('value')
                if arg_value is None:
                    arg_text = arg.get('text', '')
                    # 如果是标识符，需要进一步追踪
                    if arg.get('type') == 'identifier' and arg_text.isidentifier():
                        # 优先尝试从变量赋值查找
                        var_assignments = features.get('var_assignments', {})
                        call_line = call.get('line', 0)
                        traced = self._lookup_variable_in_assignments(
                            arg_text,
                            var_assignments,
                            call_line
                        )
                        if traced is not None:
                            return traced
                        
                        # 如果变量追踪失败，尝试递归参数追踪
                        # 创建一个虚拟 candidate 在调用点位置
                        recursive_candidate = Candidate(
                            location=Location(
                                file=candidate.location.file,
                                line=call_line,
                                column=0
                            ),
                            symbol=call_symbol,
                            api_type=candidate.api_type,
                            language=candidate.language,
                            ast_node=None,
                            scope=candidate.scope,
                            call_context=candidate.call_context,
                            literal_args={param_name: arg_text}
                        )
                        
                        # 递归追踪（深度+1）
                        recursive_result = self._trace_parameter(
                            recursive_candidate,
                            arg_text,
                            max_depth=max_depth,
                            _depth=_depth + 1
                        )
                        if recursive_result is not None:
                            return recursive_result
                    
                    # 尝试文本解析
                    return self._parse_value_from_text(arg_text)
                return arg_value
            else:
                # 直接值
                if isinstance(arg, (int, str)):
                    return arg
                # 尝试文本解析
                return self._parse_value_from_text(str(arg))
        
        return None
    
    def _parse_value_from_text(self, text: str) -> Optional[Any]:
        """
        从文本中解析值（最小化处理，AST 应已完成大部分工作）
        
        Args:
            text: 值的文本表示
        
        Returns:
            解析后的值
        """
        if not text:
            return None
        
        text = text.strip()
        
        # 整数字面量
        if text.isdigit():
            return int(text)
        
        # 字符串字面量（去除引号）
        if (text.startswith('"') and text.endswith('"')) or \
           (text.startswith("'") and text.endswith("'")):
            return text[1:-1]
        
        # 简单算术表达式（使用 AST 的 safe_eval，无正则）
        # 依赖 AST extractor 中的 safe_eval_int 函数
        from pqscan.abstract_syntax_tree.extractor import safe_eval_int
        try:
            result = safe_eval_int(text)
            if result is not None:
                return result
        except:
            pass
        
        # 无法解析（可能是复杂表达式或函数调用）
        return None
    
    def _parse_crypto_expression(self, expr: str) -> Optional[int]:
        """
        解析加密相关表达式，提取密钥长度
        
        支持的模式：
        - make([]byte, N) → N * 8 bits
        - b'...' → len * 8 bits
        - EVP_aes_128_* → 128 bits
        - new byte[N] → N * 8 bits (Java)
        - bytearray(N) → N * 8 bits (Python)
        - 算术表达式：16*2 → 32
        
        Args:
            expr: 表达式字符串
        
        Returns:
            密钥位数，如果无法解析则返回 None
        """
        if not expr or not isinstance(expr, str):
            return None
        
        import re
        
        # Go: make([]byte, N)
        match = re.search(r'make\s*\(\s*\[\s*\]\s*byte\s*,\s*(\d+)\s*\)', expr)
        if match:
            bytes_count = int(match.group(1))
            return bytes_count * 8
        
        # Python: b'...' or b"..."
        match = re.match(r"b['\"](.+)['\"]", expr)
        if match:
            byte_string = match.group(1)
            # 处理转义序列（简化）
            byte_string = byte_string.replace('\\x', 'X')  # \x00 → XX (2 chars per byte)
            byte_string = byte_string.replace('\\n', 'N')
            byte_string = byte_string.replace('\\r', 'R')
            byte_string = byte_string.replace('\\t', 'T')
            byte_string = byte_string.replace('\\\\', 'B')
            # 粗略估计：字符数 ≈ 字节数
            return len(byte_string) * 8
        
        # Python: bytearray(N) 或 bytearray(b'...')
        match = re.search(r'bytearray\s*\(\s*(\d+)\s*\)', expr)
        if match:
            bytes_count = int(match.group(1))
            return bytes_count * 8
        
        # Java: new byte[N]
        match = re.search(r'new\s+byte\s*\[\s*(\d+)\s*\]', expr)
        if match:
            bytes_count = int(match.group(1))
            return bytes_count * 8

        # Python / Go style slicing: key[:16] or key[0:16]
        match = re.search(r'\[[ \t]*(?:0)?[ \t]*:[ \t]*(\d+)[ \t]*\]', expr)
        if match:
            bytes_count = int(match.group(1))
            return bytes_count * 8
        
        # Java: new byte[]{0x01, 0x02, ...} - 计算元素个数
        match = re.search(r'new\s+byte\s*\[\s*\]\s*\{([^}]+)\}', expr)
        if match:
            elements = match.group(1)
            # 简单计数逗号
            comma_count = elements.count(',')
            bytes_count = comma_count + 1  # 元素数 = 逗号数 + 1
            return bytes_count * 8
        
        # C: char key[N] = {...} 或 unsigned char key[N]
        match = re.search(r'\[\s*(\d+)\s*\]', expr)
        if match:
            bytes_count = int(match.group(1))
            return bytes_count * 8
        
        # C/OpenSSL: EVP_aes_NNN_*
        match = re.search(r'EVP_aes_(\d+)_', expr)
        if match:
            return int(match.group(1))
        
        # Java/Python: AES-NNN 或 AES_NNN
        match = re.search(r'AES[_-](\d+)', expr, re.IGNORECASE)
        if match:
            return int(match.group(1))
        
        # 算术表达式：16*2, 128/8, 256+128, etc.
        # 只支持简单的整数运算
        if re.match(r'^[\d\s\+\-\*/\(\)]+$', expr):
            try:
                result = eval(expr)
                if isinstance(result, (int, float)):
                    return int(result)
            except:
                pass
        
        return None
    
    def _resolve_ast_argument(self, arg_node: Dict) -> Optional[int]:
        """
        递归解析 AST 参数节点，提取整数值
        
        支持节点类型：
        - number_literal / integer_literal：直接返回整数值
        - identifier：从赋值表中查找（暂不支持，返回 None）
        - binary_expression：计算左右子树后求值（+/-/*//）
        
        Args:
            arg_node: extract_call_arguments 返回的参数字典
        
        Returns:
            解析出的整数值，失败返回 None
        """
        if not isinstance(arg_node, dict):
            return None
        
        node_type = arg_node.get('type', '')
        
        # 已有数值字段
        if 'value' in arg_node and isinstance(arg_node['value'], (int, float)):
            return int(arg_node['value'])
        
        # 整数字面量
        if node_type in ('number_literal', 'integer_literal', 'int_literal',
                         'decimal_integer_literal', 'numeric_literal', 'integer'):
            text = arg_node.get('text', '')
            try:
                return int(text)
            except (ValueError, TypeError):
                pass
        
        # 二元表达式（仅限整数运算，不使用 eval）
        if node_type in ('binary_expression', 'binary_operator'):
            left = arg_node.get('left')
            right = arg_node.get('right')
            operator = arg_node.get('operator', '')
            if left and right:
                lv = self._resolve_ast_argument(left)
                rv = self._resolve_ast_argument(right)
                if lv is not None and rv is not None:
                    try:
                        if operator == '+':
                            return lv + rv
                        elif operator == '-':
                            return lv - rv
                        elif operator == '*':
                            return lv * rv
                        elif operator in ('/', '//'):
                            return lv // rv if rv != 0 else None
                    except Exception:
                        pass
            # 备用：扁平 text 格式（只有 text 字段，无 left/right/operator）
            # 例如 {'text': 'keySize*2', 'type': 'binary_expression'}
            text = arg_node.get('text', '')
            if text:
                # 复用 _evaluate_expression 进行变量替换后求值（不新增 regex）
                evaluated = self._evaluate_expression(text, None)
                if isinstance(evaluated, int):
                    return evaluated
        
        # 标识符：从 kb.var_assignments 查找变量值（支持 Go make([]byte, keySize) 等情形）
        if node_type == 'identifier':
            text = arg_node.get('text', '')
            if text and text.isidentifier():
                var_assignments = self.kb.get('features', {}).get('var_assignments', [])
                if var_assignments:
                    # target_line=999999 → 不限行号，取最近的赋值
                    resolved = self._lookup_variable_in_assignments(text, var_assignments, 999999)
                    if isinstance(resolved, int):
                        return resolved
                    if isinstance(resolved, str):
                        try:
                            return int(resolved)
                        except (ValueError, TypeError):
                            pass
            return None

        # 字符串形式的整数
        text = arg_node.get('text', '')
        try:
            return int(text)
        except (ValueError, TypeError):
            pass
        
        return None
    
    def _parse_call_from_ast_info(self, ast_info: Dict) -> Optional[int]:
        """
        从 AST 结构化信息中提取密钥位数 [Task 12.3 Phase 3]
        
        支持的 ast_info 类型：
        - array_creation（Java new byte[N]）→ N * 8
        - array_initializer（Java new byte[]{...}）→ len * 8
        - call（Python bytearray(N)）→ N * 8
        - function_call（已求值）→ 直接返回 value
        - binary_op（算术表达式）→ 不做正则，仅安全求值
        
        Args:
            ast_info: extractor 保存的 ast_info 字典
        
        Returns:
            密钥位数，失败返回 None
        """
        if not isinstance(ast_info, dict):
            return None
        
        info_type = ast_info.get('type', '')
        
        # Java: new byte[N]
        if info_type == 'array_creation' and ast_info.get('element_type') == 'byte':
            dimensions = ast_info.get('dimensions', [])
            if dimensions:
                n = self._resolve_ast_argument(dimensions[0])
                if n is not None:
                    return n * 8
        
        # Java: new byte[]{0x01, 0x02, ...}
        if info_type == 'array_initializer' and ast_info.get('element_type') == 'byte':
            init = ast_info.get('initializer', [])
            if isinstance(init, list) and len(init) > 0:
                return len(init) * 8
        
        # Python / Go: bytearray(N) / make([]byte, N) as a 'call'
        if info_type == 'call':
            func_name = ast_info.get('function', '')
            args = ast_info.get('args', [])
            if func_name in ('bytearray', 'make') and args:
                # For make([]byte, N), args[1] is the size; for bytearray(N) args[0]
                size_arg = args[1] if func_name == 'make' and len(args) > 1 else args[0]
                n = self._resolve_ast_argument(size_arg)
                if n is not None:
                    return n * 8
        
        # Pre-evaluated function call
        if info_type == 'function_call':
            value = ast_info.get('value')
            if isinstance(value, (int, float)):
                return int(value)
        
        # Binary arithmetic expression — safe integer evaluation only
        if info_type == 'binary_op':
            expr = ast_info.get('expression', '')
            # Only allow digits, whitespace, and arithmetic operators (no eval)
            import re
            if expr and re.match(r'^[\d\s\+\-\*/\(\)]+$', expr):
                try:
                    result = eval(compile(expr, '<string>', 'eval'))  # nosec
                    if isinstance(result, (int, float)):
                        return int(result)
                except Exception:
                    pass
        
        return None
    
    def _parse_from_ast_or_fallback(
        self, value: Any, ast_info: Optional[Dict] = None
    ) -> Optional[int]:
        """
        统一解析入口 [Task 12.3 Phase 3]：
        优先使用 AST 结构化信息提取密钥位数，失败时回退到字符串正则解析
        
        Args:
            value: 变量值（str/int）
            ast_info: extractor 保存的 AST 结构化信息（可选）
        
        Returns:
            密钥位数，失败返回 None
        """
        # Path A: AST-based parsing
        if ast_info:
            result = self._parse_call_from_ast_info(ast_info)
            if result is not None:
                return result
        
        # Path B: String-based fallback (regex)
        if isinstance(value, str):
            return self._parse_crypto_expression(value)
        
        return None
    
    def _symbolic_execution(
        self,
        candidate: Candidate,
        ssa: Any
    ) -> AnalysisResult:
        """
        符号执行：追踪变量定义
        
        示例：
          int bits = 1024;
          RSA_generate_key(rsa, bits, ...);  # 追踪 bits 的值
        """
        result = AnalysisResult(confidence=0.7)
        
        # ★ 暂时禁用不完整的符号执行引擎
        # TODO: 修复 executor.execute() 方法或使用 analyze_candidate()
        # state = self.executor.execute(
        #     target=candidate,
        #     ssa=ssa,
        #     max_depth=10
        # )
        # 
        # # 从执行状态提取参数
        # if state:
        #     result.key_bits = state.get_value('key_bits')
        #     result.algorithm = state.get_value('algorithm')
        #     result.constraints = state.constraints
        
        return result
    
    def _analyze_wrapper(
        self,
        candidate: Candidate,
        ssa: Any
    ) -> AnalysisResult:
        """
        Wrapper 函数分析

        利用 CallersIndex 对调用关系进行反向指针配置，
        以约束传播方式分析 wrapper 内部密钒参数来源。

        示例：
          void my_init_rsa(int bits) {
              RSA_generate_key(rsa, bits, ...);  # 候选点
          }

          my_init_rsa(1024);  # 需要追踪到这里
        """
        result = AnalysisResult(confidence=0.5)

        # 1. 先尝试直接字面量 / 变量追踪
        direct = self._extract_literals(candidate)
        if direct.key_bits:
            result.key_bits = direct.key_bits
            result.confidence = 0.8
        if direct.algorithm:
            result.algorithm = direct.algorithm

        if not result.key_bits:
            traced = self._trace_variables_from_candidate(candidate)
            if 'bits' in traced:
                result.key_bits = traced['bits']
                result.confidence = 0.75
            elif 'key_size' in traced:
                result.key_bits = traced['key_size']
                result.confidence = 0.75

        # 2. 构建 CallersIndex，查找 wrapper 的调用者
        features = self.kb.get('features', {})
        calls = features.get('calls', [])

        from pqscan.analysis.wrapper_summary import CallersIndex, CallSite
        callers_index = CallersIndex()
        for call in calls:
            scope = call.get('scope', {})
            caller_fn = scope.get('function_name', '') if isinstance(scope, dict) else ''
            callee = call.get('symbol', '')
            if caller_fn and callee:
                cs = CallSite(
                    caller_fqname=caller_fn,
                    callee_fqname=callee,
                    args_repr=[str(a) for a in call.get('args', [])],
                    line=call.get('line', 0),
                    file=getattr(candidate.location, 'file', '') or ''
                )
                callers_index.add_call(cs)

        # 3. 查找 wrapper 内部被封装的目标函数名称
        wrapper_fn = candidate.scope.function_name or '<unknown>'
        callers = callers_index.get_callers(wrapper_fn)

        if callers:
            # 从调用点傍评 key_bits：取第 param_index 个参数
            if not result.key_bits:
                for cs in callers[:5]:
                    for arg_repr in cs.args_repr:
                        try:
                            val = int(arg_repr)
                            from pqscan.analysis.crypto_constants import get_all_valid_key_sizes
                            if val in get_all_valid_key_sizes():
                                result.key_bits = val
                                result.confidence = 0.7
                                break
                        except (ValueError, TypeError):
                            pass
                    if result.key_bits:
                        break

            # 构建进入路径
            result.paths = [
                f"{cs.caller_fqname}() -> {wrapper_fn}() -> {candidate.symbol}()"
                for cs in callers[:5]
            ]

        if not result.algorithm:
            result.algorithm = self._infer_algorithm_from_name(candidate.symbol)

        return result
    
    def _explore_paths(
        self,
        candidate: Candidate,
        ssa: Any
    ) -> List[str]:
        """
        路径探索：反向遍历调用图，构建完整调用链 [Task 12.3 Phase 3]
        
        利用 self.kb['features']['calls'] 构建反向调用索引，
        从候选点向上追踪直到入口函数，最多 3 层。
        
        返回：
          ["main() -> init_crypto() -> RSA_generate_key()",
           "setup() -> configure_rsa() -> RSA_generate_key()"]
        """
        if os.environ.get('PQSCAN_SKIP_PATH_EXPLORATION', '').strip().lower() in {'1', 'true', 'yes', 'on'}:
            direct_func = candidate.scope.function_name or '<unknown>'
            symbol = candidate.symbol
            return [f"{direct_func}() -> {symbol}()"]

        paths: List[str] = []
        direct_func = candidate.scope.function_name or '<unknown>'
        symbol = candidate.symbol
        
        # 1. 直接路径
        paths.append(f"{direct_func}() -> {symbol}()")
        
        # 2. 从 features 构建反向调用索引 callee → {caller, ...}
        features = self.kb.get('features', {})
        calls = features.get('calls', [])
        
        callee_to_callers: Dict[str, set] = {}
        for call in calls:
            callee = call.get('symbol', '')
            scope = call.get('scope', {})
            caller_fn = scope.get('function_name', '') if isinstance(scope, dict) else ''
            if callee and caller_fn:
                callee_to_callers.setdefault(callee, set()).add(caller_fn)
        
        # 3. 向上追踪两层（BFS，限制宽度避免路径爆炸）
        MAX_CALLERS_PER_LEVEL = 5
        MAX_DEPTH = 2
        
        def _expand(func_name: str, chain: List[str], depth: int) -> None:
            """递归追踪调用者"""
            if depth >= MAX_DEPTH:
                return
            callers = list(callee_to_callers.get(func_name, set()))[:MAX_CALLERS_PER_LEVEL]
            for caller in callers:
                full_chain = [f"{caller}()"] + chain
                paths.append(" -> ".join(full_chain))
                _expand(caller, full_chain, depth + 1)
        
        base_chain = [f"{direct_func}()", f"{symbol}()"]
        _expand(direct_func, base_chain, 0)
        
        # 去重，保持插入顺序
        seen: set = set()
        unique_paths: List[str] = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)
        
        return unique_paths
    
    def _to_finding(
        self,
        candidate: Candidate,
        result: AnalysisResult
    ) -> Finding:
        """将分析结果转换为 Finding 对象"""
        from pqscan.reporting.severity import assess_severity
        
        candidate_profile_id = getattr(candidate, 'profile_id', None)
        literal_args = getattr(candidate, 'literal_args', {}) or {}

        def _profile_family(profile_id: Any) -> str:
            text = str(profile_id or '').upper().strip()
            if text.startswith('ALG.'):
                parts = text.split('.')
                if len(parts) >= 2:
                    return parts[1]
            return text

        def _resolve_profile_from_algorithm(algorithm: Any) -> tuple[Optional[str], Optional[dict]]:
            if not algorithm:
                return None, None
            try:
                _common_profiles = self.kb.get('common_profiles', {})
                _aliases = _common_profiles.get('id_aliases', {})
                _rules = {r['id']: r for r in _common_profiles.get('rules', [])}
                _algo_upper = str(algorithm).upper()
                _tokens = []
                for _token in re.split(r'[/:_\-\s]+', _algo_upper):
                    _token = _token.strip()
                    if _token and _token not in _tokens:
                        _tokens.append(_token)
                if _algo_upper not in _tokens:
                    _tokens.insert(0, _algo_upper)
                for _token in _tokens:
                    for _pid in list(_aliases.keys()) + list(_rules.keys()):
                        _pid_upper = _pid.upper()
                        if _pid_upper.endswith('.' + _token) or _pid_upper == _token or _pid_upper == ('ALG.' + _token):
                            resolved_id = _aliases.get(_pid, _pid)
                            return resolved_id, _rules.get(resolved_id) or _rules.get(_pid)
                for _pid in list(_aliases.keys()) + list(_rules.keys()):
                    if _algo_upper in _pid.upper():
                        resolved_id = _aliases.get(_pid, _pid)
                        return resolved_id, _rules.get(resolved_id) or _rules.get(_pid)
                algo_mapper = self.kb.get('algorithm_mapper')
                if algo_mapper is not None:
                    for _token in _tokens:
                        algo_info = algo_mapper.get_algorithm_by_name(_token)
                        if algo_info and getattr(algo_info, 'profile_id', None):
                            return algo_info.profile_id, {'id': algo_info.profile_id, 'recommendation': ''}
            except Exception:
                return None, None
            return None, None

        inferred_profile_id, inferred_profile = _resolve_profile_from_algorithm(result.algorithm)
        literal_profile_id = None
        literal_profile = None
        for _arg_name in ('algorithm', 'transformation', 'mode', 'arg0', 'arg1'):
            _arg_value = literal_args.get(_arg_name)
            if not isinstance(_arg_value, str) or not _arg_value.strip():
                continue
            literal_profile_id, literal_profile = _resolve_profile_from_algorithm(_arg_value)
            if literal_profile_id:
                break

        ctx_key_bits = None
        if isinstance(literal_args, dict):
            _ctx_key_bits_raw = literal_args.get('_ctx_key_bits')
            if isinstance(_ctx_key_bits_raw, int):
                ctx_key_bits = _ctx_key_bits_raw

        # A direct KB API match is the primary semantic identity of the call.  Argument
        # algorithms such as rsa.EncryptOAEP(sha256.New(), ...) describe parameters,
        # not the enclosing sink API.
        has_primary_profile = isinstance(candidate_profile_id, str) and candidate_profile_id.startswith('ALG.')
        if has_primary_profile:
            profile_id = candidate_profile_id
            profile = None
            if inferred_profile_id and _profile_family(inferred_profile_id) != _profile_family(candidate_profile_id):
                effective_algorithm = candidate_profile_id
                effective_key_bits = ctx_key_bits
            else:
                effective_algorithm = result.algorithm or candidate_profile_id
                effective_key_bits = result.key_bits if result.key_bits is not None else ctx_key_bits
        else:
            profile_id = None
            profile = None
            effective_algorithm = literal_profile_id or result.algorithm or candidate_profile_id
            effective_key_bits = result.key_bits if result.key_bits is not None else ctx_key_bits

        # 评估严重性
        severity = assess_severity(
            algorithm=effective_algorithm,
            key_bits=effective_key_bits,
            kb=self.kb
        )
        
        # 从 KB 查找 profile_id（基于 result.algorithm）
        if not has_primary_profile and literal_profile_id:
            profile_id = literal_profile_id
            profile = literal_profile
        elif not has_primary_profile and inferred_profile_id:
            profile_id = inferred_profile_id
            profile = inferred_profile

        if profile_id is None and isinstance(candidate_profile_id, str) and candidate_profile_id:
            profile_id = candidate_profile_id

        if profile_id and profile is None:
            try:
                _common_profiles = self.kb.get('common_profiles', {})
                _rules = {r['id']: r for r in _common_profiles.get('rules', [])}
                profile = _rules.get(profile_id)
            except Exception:
                profile = None

        # 5. 兜底：如果当前位置没有推导出 key_bits，且已经拿到算法/profile，
        # 尝试直接从算法知识库恢复固定密钥长度。
        if effective_key_bits is None:
            try:
                from pqscan.analysis.crypto_constants import get_cipher_key_bits, get_algorithm_key_bits

                VARIABLE_KEY_ALG_TOKENS = {
                    'BLOWFISH', 'ALG.BLOWFISH', 'RC2', 'ALG.RC2',
                }

                def _resolve_bits(name: Any) -> Optional[int]:
                    if not name:
                        return None
                    algo_name = str(name).strip()
                    if not algo_name:
                        return None
                    algo_upper = algo_name.upper()
                    if any(token == algo_upper or token in algo_upper for token in VARIABLE_KEY_ALG_TOKENS):
                        return None
                    if algo_name.upper().startswith('ALG.'):
                        algo_name = algo_name.split('.', 1)[1]
                    bits = get_cipher_key_bits(algo_name)
                    if bits is None:
                        bits = get_algorithm_key_bits(algo_name)
                    return bits

                for _hint in (effective_algorithm, literal_profile_id, profile_id):
                    _bits = _resolve_bits(_hint)
                    if _bits is not None:
                        effective_key_bits = _bits
                        break
            except Exception:
                pass
        
        # [Task 15/37] 读取 wrapper 传播链路。优先使用当前文件本地链，
        # 再使用项目级跨文件链；直接 API finding 也尝试用所在函数名
        # 找到完整的 wrapper chain。
        def _norm_func_name(value: Any) -> str:
            text = str(value or '').strip()
            if '::' in text:
                text = text.split('::')[-1]
            if '.' in text:
                text = text.split('.')[-1]
            return text

        def _lookup_chain(symbol: Any, allow_tail_match: bool = False) -> list:
            text = str(symbol or '').strip()
            if not text:
                return []
            tail = _norm_func_name(text)
            keys = [text, text.lower()]
            if allow_tail_match and tail and tail != text:
                keys.extend([tail, tail.lower()])
            for map_name in ('wrapper_chains', '_local_wrapper_chains', '_cross_file_wrapper_chains'):
                chain_map = self.kb.get(map_name, {})
                if not isinstance(chain_map, dict):
                    continue
                for key in keys:
                    chain = chain_map.get(key)
                    if chain:
                        return list(chain)
            return []

        def _looks_like_direct_crypto_api(symbol: Any) -> bool:
            text = str(symbol or '').strip()
            if '.' not in text:
                return False
            prefix = text.split('.', 1)[0].lower()
            return prefix in {
                'aes', 'cipher', 'des', 'dsa', 'ecdh', 'ecdsa', 'ed25519',
                'hmac', 'hkdf', 'md5', 'rand', 'rsa', 'scrypt', 'sha1',
                'sha3', 'sha224', 'sha256', 'sha384', 'sha512', 'subtle',
                'tls', 'x509', 'chacha20', 'chacha20poly1305',
                'curve25519', 'bcrypt', 'argon2', 'nacl', 'box',
                'secretbox',
            }

        # Direct crypto APIs are the sink/root evidence and should keep a
        # single-item chain. Wrapper findings are emitted separately at their
        # definition/call sites, so the sink itself must not inherit enclosing
        # wrapper chains.
        if _looks_like_direct_crypto_api(candidate.symbol):
            _chain = [candidate.symbol] if candidate.symbol else []
        else:
            _chain = _lookup_chain(candidate.symbol, allow_tail_match=False)
            if not _chain:
                scope_func = getattr(getattr(candidate, 'scope', None), 'function_name', None)
                _chain = _lookup_chain(scope_func, allow_tail_match=True)
            if not _chain and candidate.symbol:
                _chain = [candidate.symbol]

        possible_profiles = [
            str(item)
            for item in literal_args.get('_possible_profiles', []) or []
            if isinstance(item, str) and item.startswith('ALG.')
        ]
        possible_key_bits = [
            int(item)
            for item in literal_args.get('_possible_key_bits', []) or []
            if isinstance(item, int)
        ]

        def _condition_reason() -> Optional[str]:
            parts = []
            if len(possible_profiles) > 1:
                selected = profile_id or effective_algorithm or 'unknown'
                parts.append(
                    "条件分支候选算法："
                    + ", ".join(possible_profiles[:6])
                    + f"；当前采用：{selected}"
                )
            if len(possible_key_bits) > 1:
                selected_bits = effective_key_bits if isinstance(effective_key_bits, int) else 'unknown'
                parts.append(
                    "条件分支候选 key_bits："
                    + ", ".join(str(v) for v in possible_key_bits[:6])
                    + f"；当前采用：{selected_bits}"
                )
            return "；".join(parts) if parts else None

        def _key_bits_reason() -> Optional[str]:
            if effective_key_bits is not None:
                if isinstance(literal_args, dict) and literal_args.get('_ctx_key_bits') == effective_key_bits:
                    return "key_bits 由对象状态或上下文参数传播得到。"
                arg_sources = literal_args.get('_arg_sources', {}) if isinstance(literal_args, dict) else {}
                if isinstance(arg_sources, dict):
                    for name, source in arg_sources.items():
                        if source == 'go_signature_fixed_array_param':
                            value = literal_args.get(name)
                            if isinstance(value, int):
                                return (
                                    "key_bits 由当前函数参数的静态类型推导得到；"
                                    f"参数来源：{name} 来自固定长度字节数组签名（{value} bytes）。"
                                )
                source_parts = []
                if isinstance(literal_args, dict):
                    for name, value in literal_args.items():
                        if str(name).startswith('_'):
                            continue
                        if isinstance(value, (str, int)) and str(value).strip():
                            source_parts.append(f"{name}={str(value).strip()}")
                if source_parts:
                    return "key_bits 由当前调用参数推导得到；参数来源：" + ", ".join(source_parts[:4]) + "。"
                if _chain and len(_chain) > 1:
                    return "key_bits 由封装链传播得到：" + " -> ".join(str(item) for item in _chain if item) + "。"
                return None
            source_parts = []
            for name, value in literal_args.items():
                if str(name).startswith('_'):
                    continue
                if isinstance(value, str) and value.strip():
                    source_parts.append(f"{name}={value.strip()}")
                elif isinstance(value, int):
                    source_parts.append(f"{name}={value}")
            symbol_text = str(getattr(candidate, 'symbol', '') or '')
            if source_parts and any(
                token in symbol_text
                for token in (
                    'ParsePKCS1PrivateKey',
                    'ParsePKCS8PrivateKey',
                    'MarshalPKCS1PrivateKey',
                    'MarshalPKCS8PrivateKey',
                )
            ):
                return (
                    "无法通过静态分析得到 key_bits；参数来源："
                    + ", ".join(source_parts[:4])
                    + "。该调用处理的是 RSA 密钥对象或 DER/PEM 字节，当前位置无法直接恢复模数位数；"
                    + "需要继续追踪其来源，例如 rsa.GenerateKey(bits)、key.N.BitLen() 或固定测试密钥常量。"
                )
            if source_parts:
                return (
                    "无法通过静态分析得到 key_bits；参数来源："
                    + ", ".join(source_parts[:4])
                    + "。若该参数来自函数入参、运行时配置或外部输入，需要在调用点继续解析其实际字节长度。"
                )
            return "无法通过静态分析得到 key_bits；当前调用未暴露可解析的密钥长度参数。"

        # ★ 适配Finding类的实际签名
        finding = Finding(
            file=candidate.location.file,
            line=candidate.location.line,
            symbol=candidate.symbol,
            rule_id="quantum_deprecated",
            layer="symbolic",
            category="crypto",
            quantum_secure=False if (effective_key_bits and effective_key_bits < 2048) else None,
            severity=severity,
            reason=f"检测到{effective_algorithm or '加密'}操作，密钥长度：{effective_key_bits or 'unknown'}",
            recommendation=self._generate_recommendation(result, profile=profile),
            profile_id=profile_id,
            profile_reason=infer_profile_reason(
                {
                    'source': 'symbolic_execution',
                    'algorithm': effective_algorithm,
                    'key_bits': effective_key_bits,
                    'confidence': result.confidence,
                },
                profile_id,
            ),
            key_bits=effective_key_bits,
            key_bits_reason=_key_bits_reason(),
            evidence={
                'source': 'symbolic_execution',
                'algorithm': effective_algorithm,
                'key_bits': effective_key_bits,
                'confidence': result.confidence
            },
            wrapper_chain=_chain,
        )

        _condition_text = _condition_reason()
        if _condition_text:
            finding.reason = f"{finding.reason}; {_condition_text}"
            if finding.key_bits_reason:
                finding.key_bits_reason = f"{finding.key_bits_reason}；{_condition_text}"
            else:
                finding.key_bits_reason = _condition_text
            if isinstance(finding.evidence, dict):
                finding.evidence['conditions'] = _condition_text
                finding.evidence['possible_profiles'] = possible_profiles
                finding.evidence['possible_key_bits'] = possible_key_bits
        
        return finding
    
    def _generate_recommendation(self, result: AnalysisResult, profile: Optional[Dict[str, Any]] = None) -> str:
        """生成修复建议"""
        if isinstance(profile, dict):
            recommendation = str(profile.get('recommendation', '') or '').strip()
            if recommendation:
                return recommendation

        if result.algorithm == 'RSA' and result.key_bits and result.key_bits < 2048:
            return "升级 RSA 密钥长度至 2048 位以上，推荐使用后量子算法如 Kyber"
        elif result.algorithm == 'AES' and result.key_bits and result.key_bits < 256:
            return "升级 AES 密钥长度至 256 位"
        else:
            return "评估并升级至后量子安全算法"


def analyze_candidates(
    candidates: List[Candidate],
    code: str,
    lang: str,
    kb: Dict[str, Any]
) -> List[Finding]:
    """
    统一入口：符号执行分析
    
    这是 Phase 2 的主入口函数
    """
    analyzer = SymbolicAnalyzer(kb)
    return analyzer.analyze_candidates(candidates, code, lang)
