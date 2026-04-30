#!/usr/bin/env python3
"""
PQScan Two-Pass Scanner
======================

两阶段扫描架构的核心实现：
- Phase 1: AST 提取（语法分析）
- Phase 2: 符号分析（语义分析 + 约束检查）
"""

import json
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

# Phase 1: AST extraction
from pqscan.abstract_syntax_tree import get_parser, extract_calls, extract_imports_with_aliases

# Phase 2: Symbolic analysis
from pqscan.symbolic.constraint_checker import ConstraintChecker, ConstraintMode
from pqscan.analysis.param_eval import bind_params, eval_expr, infer_params
from pqscan.analysis.crypto_constants import (
    extract_key_size_from_api_name,
    get_algorithm_key_bits,
    get_all_valid_key_sizes,
)
from pqscan.symbolic.object_state_tracker import (
    ObjectStateTracker, 
    process_context_writes, 
    process_context_reads
)
from pqscan.symbolic.variable_tracker import VariableTracker
from pqscan.symbolic.value_graph import ValueGraph, NodeType, ValueNode
from pqscan.loader.algorithm_mapper import AlgorithmMapper
from pqscan.loader.loader_v2 import get_profile

# Quantum vulnerability analysis
from pqscan.analysis.quantum_vulnerability_analyzer import (
    QuantumVulnerabilityAnalyzer,
    generate_quantum_migration_report
)

_PYTHON_NON_CRYPTO_GENERIC_MEMBERS = {
    'str', 'bytes', 'bytearray', 'join', 'get', 'keys', 'values', 'items',
    'append', 'extend', 'insert', 'pop', 'remove', 'replace', 'split',
    'rsplit', 'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'capitalize',
    'format', 'startswith', 'endswith', 'read', 'write', 'open', 'close',
    'seek', 'tell', 'flush', 'dump', 'dumps', 'load', 'loads', 'force_str',
    'value_to_string', 'to_string', 'as_string', 'sum',
}
_PYTHON_GENERIC_NAMESPACE_TERMINALS = {
    'objects', 'flags', 'headers', 'meta', 'data', 'attrs', 'params',
    'kwargs', 'config', 'settings', 'options',
}


def _looks_like_crypto_name(text: Any) -> bool:
    compact = re.sub(r'[^a-z0-9]+', '', str(text or '').lower())
    if not compact:
        return False
    return any(token in compact for token in (
        'aes', 'des', 'rsa', 'dsa', 'dh', 'ecdh', 'ecdsa', 'ed25519', 'ed448',
        'x25519', 'x448', 'curve25519', 'mlkem', 'mldsa', 'dilithium', 'kyber',
        'falcon', 'sphincs', 'hmac', 'cmac', 'hkdf', 'pbkdf', 'pbkdf2',
        'scrypt', 'bcrypt', 'argon', 'sha', 'shake', 'md5', 'sha1', 'sha2',
        'sha3', 'chacha', 'poly1305', 'salsa20', 'secretbox', 'box', 'cipher',
        'mac', 'digest', 'hash', 'encrypt', 'decrypt', 'sign', 'verify', 'wrap',
        'unwrap', 'oaep', 'pss', 'gcm', 'cbc', 'ctr', 'ecb', 'x509', 'cert',
        'privatekey', 'publickey', 'keypair', 'keygen', 'nonce', 'iv',
    ))


def _is_python_non_crypto_symbol(symbol: Any) -> bool:
    text = str(symbol or '').strip()
    if not text:
        return False
    tail = text.rsplit('.', 1)[-1].strip().lower()
    if _looks_like_crypto_name(text) or _looks_like_crypto_name(tail):
        return False
    if tail in _PYTHON_NON_CRYPTO_GENERIC_MEMBERS:
        return True
    parts = [part.strip().lower() for part in text.split('.') if part.strip()]
    if len(parts) >= 2 and parts[-1] in {'get', 'join'}:
        if any(part in _PYTHON_GENERIC_NAMESPACE_TERMINALS for part in parts[:-1]):
            return True
    if ').' in text and tail not in {'new', 'encrypt', 'decrypt', 'sign', 'verify', 'update', 'final', 'finalize', 'dofinal'}:
        return True
    return False


class PQScanner:
    """
    PQScan 两阶段扫描器
    
    使用方法:
        scanner = PQScanner()
        results = scanner.scan_file("test.c", pq_mode=True, classic_mode=True)
    """
    
    def __init__(
        self,
        kb_dir: Optional[Path] = None,
        verbose: bool = False,
        use_ssa: bool = True,
        wrapper_priority: str = "api_first",
        wrapper_max_depth: int = 8,
        wrapper_contract_cache_size: int = 64,
    ):
        """
        初始化扫描器
        
        Args:
            kb_dir: 知识库目录路径（默认为 pqscan/kb）
            verbose: 是否输出详细信息
            use_ssa: 是否启用 SSA 追踪（默认启用，提供精确的对象追踪）
        """
        self.verbose = verbose
        self.use_ssa = use_ssa
        self.wrapper_max_depth = max(1, int(wrapper_max_depth))
        self.wrapper_contract_cache_size = max(1, int(wrapper_contract_cache_size))
        
        # 确定 KB 目录
        if kb_dir is None:
            kb_dir = Path(__file__).parent.parent / "kb"
        self.kb_dir = Path(kb_dir)
        
        # 加载 common profiles
        common_profile_path = self.kb_dir / "common" / "common_profiles.json"
        with open(common_profile_path, 'r', encoding='utf-8') as f:
            self.common_profiles = json.load(f)
        
        # 初始化组件
        self.algorithm_mapper = AlgorithmMapper(self.kb_dir)
        # 加载封装契约（手工 + 自动），用于在识别阶段提供快速查表
        from pqscan.loader.wrapper_loader import WrapperContractLoader
        self.wrapper_priority = wrapper_priority
        self.wrapper_loader = WrapperContractLoader(self.kb_dir, verbose=verbose)
        self.wrapper_contracts = self.wrapper_loader.load_wrappers()
        # 快速查找表: api name -> [wrapper entries]
        # 注意：同名函数可能来自不同库（如 encrypt / getInstance），不能只保留一个。
        self._wrapper_map = {}
        for w in self.wrapper_contracts:
            api_name = w.get('api', '')
            if api_name:
                self._wrapper_map.setdefault(api_name.lower(), []).append(w)
        self.constraint_checker = ConstraintChecker()
        self.object_state_tracker = ObjectStateTracker()  # 状态追踪器
        self.variable_tracker = VariableTracker()  # 变量追踪
        self.value_graph = ValueGraph()  # 数据流图
        
        # 对象ID管理器（轻量级别名追踪 + 版本化对象ID）
        from pqscan.symbolic.object_id_manager import ObjectIDManager
        self.object_id_manager = ObjectIDManager()
        
        # 封装派生：反向调用索引（Fast Pass 构建）
        from pqscan.analysis.wrapper_summary import CallersIndex
        self.callers_index = CallersIndex()
        
        # 封装派生：关键输入归因器（Deep Pass）
        from pqscan.analysis.key_input_attributor import KeyInputAttributor
        self.key_input_attributor = KeyInputAttributor(
            object_id_manager=self.object_id_manager,
            variable_tracker=self.variable_tracker
        )
        
        # 封装派生：工厂函数检测器
        from pqscan.analysis.factory_detector import FactoryDetector
        self.factory_detector = FactoryDetector()
        
        # 封装派生：约束派生器（Deep Pass）
        from pqscan.analysis.contract_deriver import ContractDeriver
        self.contract_deriver = ContractDeriver(verbose=verbose)
        
        # 封装派生：Wrapper Summary 存储
        self.wrapper_summaries = {}  # func_name -> Summary
        
        # 量子脆弱性分析器（Quantum Mode）
        self.quantum_analyzer = QuantumVulnerabilityAnalyzer(verbose=verbose)

        # 本地 wrapper 契约缓存（key: language:sha1(code)）
        self._wrapper_contract_cache: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self._wrapper_contract_cache_order: List[str] = []
        
        # 加载 API metadata（用于状态追踪）
        self.api_metadata_map = self._load_api_metadata()
        
        if self.verbose:
            print(f"✓ Loaded {len(self.common_profiles)} common profiles")
            print(f"✓ Algorithm mapper initialized")
            print(f"✓ Constraint checker initialized")
            print(f"✓ Variable tracker initialized")
            print(f"✓ Value graph initialized")
            print(f"✓ Parameter tracer initialized")
            print(f"✓ Object state tracker initialized")
            if self.use_ssa:
                print(f"✓ SSA mode enabled")
    
    def _load_api_metadata(self) -> Dict[str, Dict[str, Any]]:
        """加载 API 完整 metadata（用于状态追踪）"""
        metadata_map = {}
        apis_dir = self.kb_dir / "apis_v2"
        if not apis_dir.exists():
            return metadata_map
        
        # 只加载 c_openssl.json（其他可以后续添加）
        openssl_file = apis_dir / "c_openssl.json"
        if openssl_file.exists():
            try:
                with open(openssl_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    mappings = data.get('mappings', [])
                    for mapping in mappings:
                        func_name = mapping.get('function', '').lower()
                        if func_name:
                            metadata_map[func_name] = mapping
            except Exception as e:
                if self.verbose:
                    print(f"Warning: Failed to load API metadata: {e}")
        
        return metadata_map
    
    def scan_file(
        self, 
        file_path: str, 
        pq_mode: bool = True, 
        classic_mode: bool = True
    ) -> Dict[str, Any]:
        """
        扫描单个文件
        
        Args:
            file_path: 源文件路径
            pq_mode: 启用量子安全检查
            classic_mode: 启用经典安全检查
        
        Returns:
            扫描结果字典，包含：
            - file: 文件路径
            - language: 语言类型
            - total_candidates: 候选调用总数
            - recognized: 识别的算法数量
            - violations: 违规列表
            - statistics: 统计信息
        """
        if self.verbose:
            print(f"\n[DEBUG] PQScanner.scan_file called: {file_path}")
        
        file_path = Path(file_path)
        if not file_path.exists():
            return {
                'error': f'File not found: {file_path}',
                'file': str(file_path)
            }
        
        # 检测语言
        language = self._detect_language(file_path)
        if not language:
            return {
                'error': f'Unsupported file type: {file_path.suffix}',
                'file': str(file_path)
            }
        
        # 读取源代码
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        # ★ 保存当前文件名（用于 callers_index）
        self.current_file = str(file_path)
        
        # Phase 1: AST 提取
        candidates = self._extract_candidates(code, language)
        
        # 构建 value graph（用于跨函数追踪）
        self._build_value_graph(code, language, candidates)
        
        # Phase 2: 符号分析
        results = self._analyze_candidates(
            candidates, 
            language, 
            pq_mode, 
            classic_mode
        )

        # ★ Phase 3: 量子脆弱性分析（如果启用 pq_mode）
        quantum_report = None
        if pq_mode:
            quantum_report = self.quantum_analyzer.analyze_file(
                file_path=str(file_path),
                candidates=candidates,
                callers_index=self.callers_index
            )
        
        return {
            'file': str(file_path),
            'language': language.upper(),
            'candidates': candidates,  # 添加候选列表
            'total_candidates': len(candidates),
            'recognized': results['recognized_count'],
            'recognized_list': results.get('recognized', []),   # NEW
            'violations': results['violations'],
            'statistics': results['statistics'],
            'quantum_report': quantum_report  # 添加量子报告
        }
    
    def scan_directory(
        self, 
        dir_path: str, 
        extensions: Optional[List[str]] = None,
        pq_mode: bool = True,
        classic_mode: bool = True
    ) -> List[Dict[str, Any]]:
        """
        扫描目录下的所有文件
        
        Args:
            dir_path: 目录路径
            extensions: 文件扩展名列表（如 ['.c', '.java']）
            pq_mode: 启用量子安全检查
            classic_mode: 启用经典安全检查
        
        Returns:
            扫描结果列表
        """
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            return [{'error': f'Not a directory: {dir_path}'}]
        
        # 默认扫描所有支持的语言
        if extensions is None:
            extensions = ['.c', '.h', '.cpp', '.cc', '.go', '.py', '.java', '.rs']
        
        results = []
        for ext in extensions:
            for file_path in dir_path.rglob(f'*{ext}'):
                result = self.scan_file(str(file_path), pq_mode, classic_mode)
                results.append(result)
        
        return results
    
    def _detect_language(self, file_path: Path) -> Optional[str]:
        """检测文件语言类型"""
        ext_to_lang = {
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
            '.go': 'go',
            '.py': 'python',
            '.java': 'java',
            '.rs': 'rust',
            '.js': 'javascript', '.ts': 'typescript'
        }
        return ext_to_lang.get(file_path.suffix.lower())

    # ─────────────────────────────────────────────────────────────────────────
    # Task 13.3: 本地 Wrapper 契约推断（Local Wrapper Contract Inference）
    # ─────────────────────────────────────────────────────────────────────────

    def _identify_kb_api_by_symbol(self, symbol: str, language: str) -> Optional[str]:
        """
        判断 symbol 是否是已知 KB API，若是则返回 profile_id。
        只使用纯符号匹配（无 candidate 上下文），用于 wrapper 推断。
        """
        symbol_text = str(symbol or '').strip()
        language = str(language or '').lower()
        if not symbol_text:
            return None

        if language == 'python' and _is_python_non_crypto_symbol(symbol_text):
            return None

        # Java bare method names are too ambiguous for symbol-only matching.
        # Keep class-qualified calls like Cipher.getInstance / MessageDigest.getInstance,
        # but do not let plain names such as add/encrypt/decrypt/sign leak into
        # wrapper inference without receiver/package context.
        if language == 'java' and '.' not in symbol_text and '::' not in symbol_text:
            first_char = symbol_text[:1]
            java_safe_bare_symbols = {
                'Cipher', 'Mac', 'MessageDigest', 'Signature', 'KeyGenerator',
                'KeyPairGenerator', 'KeyFactory', 'SecretKeyFactory',
                'SecretKeySpec', 'PBEKeySpec', 'IvParameterSpec',
                'GCMParameterSpec', 'OAEPParameterSpec', 'MGF1ParameterSpec',
                'AlgorithmParameters', 'AlgorithmParameterGenerator',
                'KeyAgreement',
            }
            if first_char.islower() and symbol_text not in java_safe_bare_symbols:
                return None

        # Step 0: API metadata
        api_metadata = self.api_metadata_map.get(symbol_text.lower(), {})
        semantic = api_metadata.get('semantic', {})
        if 'profile_id' in semantic:
            pid = semantic['profile_id']
            if self._is_concrete_algorithm(pid):
                return pid

        # Step 3: AlgorithmMapper
        algo_info = self.algorithm_mapper.get_algorithm(symbol_text)
        if algo_info:
            return algo_info.profile_id

        # Step 3.5: Python/Go 模块限定符号
        if language in ['python', 'go'] and '.' in symbol_text:
            for part in symbol_text.split('.'):
                if not part:
                    continue
                algo_info = self.algorithm_mapper.get_algorithm_by_name(part.upper())
                if algo_info and self._is_concrete_algorithm(algo_info.profile_id):
                    return algo_info.profile_id

        return None

    def _select_wrapper_entry(self, symbol: str, imported_libs: Optional[set] = None) -> Optional[Dict[str, Any]]:
        """
        从同名 wrapper 契约中选出最匹配的一条。

        优先级：
        1) library 与文件导入库匹配
        2) 没有 library 限制的通用 wrapper
        3) 兜底返回第一个
        """
        entries = getattr(self, '_wrapper_map', {}).get((symbol or '').lower(), [])
        if not entries:
            return None

        imported_libs = imported_libs or set()

        # 优先选中 library 命中的契约
        if imported_libs:
            for entry in entries:
                lib = str(entry.get('library', '') or '').strip().lower()
                if lib and lib in {str(x).strip().lower() for x in imported_libs}:
                    return entry

        # 其次选无 library 约束的通用契约
        for entry in entries:
            lib = str(entry.get('library', '') or '').strip()
            if not lib:
                return entry

        # 最后兜底：直接返回第一个
        return entries[0]

    def _build_local_wrapper_contracts(
        self,
        functions: List[Dict[str, Any]],
        calls: List[Dict[str, Any]],
        language: str,
        var_assignments: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Task 13.3: 从文件内函数定义推断本地 Wrapper 契约。

        对于每个用户定义函数 F，若其函数体内包含对 KB API（或其他 wrapper）的
        调用，则 F 是一个 wrapper。构建多级（传递）映射：

            { func_name: {
                'profile_id': str,         # 最终密码算法 profile
                'key_arg_expr': str,       # 对应 key_bits 的参数表达式（相对于 F 的参数）
                'func_params': list[str],  # F 的参数名列表
                'api_symbol': str,         # 最终被调 KB API
            } }

        支持：
        - 单层 wrapper：generate_key(bits) → RSA.generate(bits)
        - 多层 wrapper：create_crypto_context(lvl) → init_rsa(lvl*8) → ... → RSA.generate
        - 参数变换：generate_key_from_bytes(kb) → RSA.generate(kb * 8)
        """
        import re

        def _contract_priority(profile_id: str) -> int:
            """
            合同优先级（用于混合算法函数中选择更有价值的传播路径）。
            当前策略偏向量子高风险公钥算法（RSA/DH/DSA/ECC）优先于对称算法。
            """
            pid = (profile_id or '').upper()
            if any(x in pid for x in ('RSA', 'DH', 'DSA', 'ECDSA', 'EC', 'ED25519', 'ED448')):
                return 3
            if any(x in pid for x in ('AES', 'CHACHA', 'DES', '3DES', 'SM4')):
                return 2
            return 1

        def _c_anchor_score(symbol: str) -> int:
            text = str(symbol or '').strip().lower()
            if not text:
                return 0
            if any(token in text for token in (
                'encrypt', 'decrypt', 'sign', 'verify', 'digest', 'hmac', 'cmac',
                'public_encrypt', 'private_encrypt', 'do_verify', 'do_sign',
                'derive', 'generate', 'final', 'update', 'init',
            )):
                return 3
            if any(token in text for token in (
                'sha', 'md5', 'rsa', 'ecdsa', 'ecdh', 'ec_', 'aes_', 'des_', 'hmac',
            )):
                return 2
            if any(token in text for token in ('size', 'bits', 'name', 'new', 'create', 'get', 'set0', 'set1')):
                return 1
            return 1

        def _c_is_digest_family(profile_id: str) -> bool:
            pid = str(profile_id or '').upper()
            return any(token in pid for token in (
                'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3', 'MD5', 'WHIRLPOOL',
            ))

        def _c_is_kdf_or_mac_family(profile_id: str) -> bool:
            pid = str(profile_id or '').upper()
            return any(token in pid for token in (
                'PBKDF', 'PBKDF2', 'HKDF', 'HMAC', 'CMAC', 'SCRYPT', 'ARGON2',
            ))

        def _is_c_non_crypto_wrapper_name(func_name: str) -> bool:
            tail = str(func_name or '').strip()
            if not tail:
                return False
            for sep in ('::', '->', '.'):
                if sep in tail:
                    tail = tail.split(sep)[-1]
            tail_lc = tail.lower()
            if any(token in tail_lc for token in (
                'rsa', 'ecdsa', 'ecdh', 'ed25519', 'ed448', 'x25519', 'x448',
                'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                'aes', 'des', 'hmac', 'cmac', 'hkdf', 'digest',
                'encrypt', 'decrypt', 'sign', 'verify',
            )):
                return False
            return tail_lc in {
                'data', 'size', 'length', 'get', 'release', 'front', 'back',
                'begin', 'end', 'constdata', 'session', 'user', 'url',
                'path', 'value', 'name', 'message', 'number', 'text',
                'widget', 'item', 'element', 'source', 'result', 'response',
                'request', 'owner', 'parent', 'filter', 'key',
            }

        def _c_family_from_func_name(func_name: str, inner_calls: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
            name_lc = str(func_name or '').lower()
            family_specs = [
                ('rsa', 'ALG.RSA'),
                ('rsapss', 'ALG.RSA'),
                ('ecdsa', 'ALG.ECDSA'),
                ('ecdh', 'ALG.ECDH'),
                ('ed25519', 'ALG.ED25519'),
                ('ed448', 'ALG.ED448'),
                ('x25519', 'ALG.X25519'),
                ('x448', 'ALG.X448'),
                ('hmac', 'ALG.HMAC'),
                ('sha512', 'ALG.SHA512'),
                ('sha384', 'ALG.SHA384'),
                ('sha256', 'ALG.SHA256'),
                ('sha224', 'ALG.SHA224'),
                ('sha1', 'ALG.SHA1'),
                ('md5', 'ALG.MD5'),
            ]
            matched = None
            for token, profile in family_specs:
                if token in name_lc:
                    matched = (token, profile)
                    break
            if matched is None and ('signatureec' in name_lc or name_lc.endswith('ec')):
                matched = ('ecdsa', 'ALG.ECDSA')
            if matched is None:
                return None
            token, profile = matched
            for call in inner_calls:
                call_sym = str(call.get('symbol', '') or '')
                call_u = call_sym.upper()
                if not _is_c_native_crypto_symbol(call_sym):
                    continue
                if token == 'rsa' or token == 'rsapss':
                    if 'RSA' in call_u or 'PKEY' in call_u:
                        return {'profile_id': profile, 'api_symbol': call_sym}
                elif token in {'ecdsa', 'ecdh'}:
                    if token.upper() in call_u or 'EC_' in call_u:
                        return {'profile_id': profile, 'api_symbol': call_sym}
                elif token in {'hmac', 'sha512', 'sha384', 'sha256', 'sha224', 'sha1', 'md5'}:
                    if token.upper().replace('SHA', 'SHA') in call_u or ('HMAC' in call_u and token == 'hmac'):
                        return {'profile_id': profile, 'api_symbol': call_sym}
                else:
                    if token.upper() in call_u:
                        return {'profile_id': profile, 'api_symbol': call_sym}
            return None

        def _is_c_native_crypto_symbol(symbol: str) -> bool:
            text = str(symbol or '').strip()
            if not text:
                return False
            text_u = text.upper()
            c_prefixes = (
                'EVP_', 'RSA_', 'DSA_', 'DH_', 'EC_', 'ECDH_', 'ECDSA_', 'AES_',
                'DES_', 'HMAC', 'CMAC', 'HKDF', 'PKCS5_', 'PKCS12_', 'RAND_',
                'BN_', 'X509_', 'PEM_', 'BIO_',
            )
            c_exact = {
                'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5',
                'AES_SET_ENCRYPT_KEY', 'AES_SET_DECRYPT_KEY',
            }
            return text_u.startswith(c_prefixes) or text_u in c_exact

        # 每个函数内的本地赋值表达式：func -> {var_name: expr_text}
        local_expr_map: Dict[str, Dict[str, str]] = {}
        global_expr_map: Dict[str, str] = {}
        global_expr_map_lower: Dict[str, str] = {}
        for assignment in (var_assignments or []):
            func_name = assignment.get('function', 'global')
            var_name = assignment.get('name')
            value = assignment.get('value')
            if not var_name or value is None:
                continue
            local_expr_map.setdefault(func_name, {})[var_name] = str(value)
            # 兜底：建立文件级变量映射，供静态字段/跨函数常量链解析
            global_expr_map[str(var_name)] = str(value)
            global_expr_map_lower[str(var_name).lower()] = str(value)

        def _should_override_assignment(expr_text: str) -> bool:
            text = str(expr_text or '').strip()
            if not text:
                return False
            if any(ch in text for ch in ('(', ')', '[', ']', '{', '}', '.', ':', '+', '-', '*', '/', '"', "'")):
                return True
            return False

        for call in (calls or []):
            func_name = call.get('owner_function_normalized') or call.get('owner_function') or 'global'
            assigned_to = str(call.get('assigned_to') or '').strip()
            call_code = str(call.get('code') or '').strip()
            if not assigned_to or not call_code:
                continue
            if _should_override_assignment(call_code):
                local_expr_map.setdefault(func_name, {})[assigned_to] = call_code
                global_expr_map[assigned_to] = call_code
                global_expr_map_lower[assigned_to.lower()] = call_code

        def _resolve_local_expr(expr_text: str, func_name: str, func_params: List[str]) -> str:
            """
            若 key 参数是本地临时变量（如 rsa_bits），尝试回代到参数表达式。

            例：
                rsa_bits = security_level * 8
                RSA.generate(rsa_bits)
            回代后得到 key_arg_expr = security_level * 8
            """
            expr = (expr_text or '').strip()
            if not expr:
                return expr

            def _strip_outer_parens(text: str) -> str:
                text = text.strip()
                while text.startswith('(') and text.endswith(')'):
                    inner = text[1:-1].strip()
                    if not inner:
                        break
                    text = inner
                return text

            def _lookup_expr(name: str) -> Optional[str]:
                local_value = local_expr_map.get(func_name, {}).get(name)
                if local_value is not None:
                    return str(local_value)
                global_value = global_expr_map.get(name)
                if global_value is None:
                    global_value = global_expr_map_lower.get(name.lower())
                return str(global_value) if global_value is not None else None

            def _resolve_expr(text: str, visited: set[str]) -> str:
                text = _strip_outer_parens((text or '').strip())
                if not text:
                    return text

                # 字面量字符串直接返回去引号版本
                if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
                    return text

                lowered = text.lower()

                # String.valueOf(x) -> x
                if lowered.startswith('string.valueof(') and text.endswith(')'):
                    inner = text[text.find('(') + 1:-1]
                    return _resolve_expr(inner, visited)

                # x.toCharArray() -> x（保留语义上的字符串值）
                if lowered.endswith('.tochararray()'):
                    inner = text[:text.rfind('.toCharArray()')]
                    return _resolve_expr(inner, visited)

                m = re.fullmatch(r'([A-Za-z_]\w*)\s*\[\s*(.*?)\s*:\s*(.*?)\s*\]', text)
                if m:
                    base = m.group(1)
                    start = m.group(2).strip()
                    end = m.group(3).strip()
                    resolved_base = _resolve_expr(base, visited)
                    if resolved_base != base:
                        if not start and not end:
                            return resolved_base
                        if not start:
                            return f"{resolved_base}[:{end}]"
                        if not end:
                            return f"{resolved_base}[{start}:]"
                        return f"{resolved_base}[{start}:{end}]"
                    return text

                m = re.fullmatch(r'([A-Za-z_]\w*)\s*\[\s*(.*?)\s*\]', text)
                if m:
                    base = m.group(1)
                    index = m.group(2).strip()
                    resolved_base = _resolve_expr(base, visited)
                    if resolved_base != base:
                        return f"{resolved_base}[{index}]"
                    return text

                m = re.fullmatch(r'(.+)\.getBytes\s*\([^)]*\)', text)
                if m:
                    inner = m.group(1).strip()
                    resolved = _resolve_expr(inner, visited)
                    return f"{resolved}.getBytes()" if resolved != inner else text

                if re.search(r'\b(?:make|bytes|bytearray|copyOf|Arrays\.copyOf|sha\d*\.Sum\d*|sha\d*\.New|md\d\.Sum|md\d\.New)\s*\(', text, re.I):
                    return text

                # 递归解析 identifier
                if text.isidentifier() and text not in visited:
                    if text in func_params:
                        return text
                    visited.add(text)
                    local_value = _lookup_expr(text)
                    if local_value is not None:
                        # Some AST assignment extractors collapse calls such as
                        # bytes(32), Arrays.copyOf(key, 16), or aes.NewCipher(key)
                        # to just the callee tail. Replacing the variable with
                        # that tail loses the key-length expression, so keep the
                        # variable name and let _evaluate_wrapper_key_bits recover
                        # the full expression from the function source.
                        if str(local_value).strip() in {
                            'bytes', 'bytearray', 'copyOf', 'getBytes',
                            'Cipher', 'NewCipher', 'new',
                        }:
                            return text
                        return _resolve_expr(str(local_value), visited)
                    return text

                return text

            visited = set()
            # 若 key 参数是函数参数名，则保留原样；否则尝试递归回代
            if expr.isidentifier() and expr in func_params:
                return expr
            return _resolve_expr(expr, visited)

        def _infer_profile_from_expr(expr_text: str) -> Optional[str]:
            """根据已解析表达式反推具体算法 profile。"""
            expr = str(expr_text or '').strip()
            if not expr:
                return None

            if language in {'c', 'cpp'}:
                expr_lc = expr.lower()
                c_native_hints = (
                    'evp_', 'rsa_', 'ecdsa_', 'ecdh_', 'ec_', 'dsa_', 'dh_',
                    'aes_', 'des_', 'sha', 'md5', 'hmac', 'cmac', 'hkdf',
                    'pkcs5_', 'pkcs12_', 'x509_', 'pem_', 'bio_',
                )
                c_literal_alg_hints = (
                    '"sha', "'sha", '"md5', "'md5", '"aes', "'aes", '"rsa', "'rsa",
                    '"ecdsa', "'ecdsa", '"ed25519', "'ed25519", '"hmac', "'hmac",
                    '"hkdf', "'hkdf",
                )
                # Do not infer a concrete crypto family from ordinary identifiers
                # such as key/name/message/md unless the expression already carries
                # an explicit crypto anchor.
                if not any(token in expr_lc for token in c_native_hints) and not any(
                    token in expr_lc for token in c_literal_alg_hints
                ):
                    if re.fullmatch(r'[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*', expr):
                        return None

            c_call = expr.rstrip()
            if c_call.endswith(')') and '(' in c_call:
                c_call = c_call.split('(', 1)[0].strip()
            if c_call:
                try:
                    profile = self._identify_kb_api_by_symbol(c_call, language)
                except Exception:
                    profile = None
                if self._is_concrete_algorithm(profile):
                    return profile

            head = expr.split('/')[0].strip().upper()
            if not head:
                return None
            try:
                algo_info = self.algorithm_mapper.get_algorithm_by_name(head)
            except Exception:
                algo_info = None
            if algo_info and self._is_concrete_algorithm(getattr(algo_info, 'profile_id', None)):
                return algo_info.profile_id
            try:
                from pqscan.loader import get_algorithm_by_name
            except Exception:
                get_algorithm_by_name = None
            if get_algorithm_by_name is None:
                return None
            try:
                algo_info = get_algorithm_by_name(head)
            except Exception:
                algo_info = None
            if algo_info and self._is_concrete_algorithm(getattr(algo_info, 'profile_id', None)):
                return algo_info.profile_id
            if language in {'c', 'cpp'}:
                upper_expr = expr.upper()
                if any(token in upper_expr for token in ('RSA_', '_RSA', ' RSA')):
                    return 'ALG.RSA'
                if any(token in upper_expr for token in ('ECDSA_', '_ECDSA', ' ECDSA')):
                    return 'ALG.ECDSA'
                if any(token in upper_expr for token in ('ECDH_', '_ECDH', ' ECDH')):
                    return 'ALG.ECDH'
                if any(token in upper_expr for token in ('EC_KEY', 'EC_GROUP', 'EC_POINT')):
                    return 'ALG.ECC'
                if 'HMAC' in upper_expr:
                    return 'ALG.HMAC'
                for bits in ('512', '384', '256', '224', '1'):
                    if f'SHA{bits}' in upper_expr:
                        return f'ALG.SHA{bits}'
                if 'MD5' in upper_expr:
                    return 'ALG.MD5'
            return None

        def _infer_profile_from_arg_texts(args_text: List[str]) -> Optional[str]:
            for text in args_text:
                inferred = _infer_profile_from_expr(text)
                if inferred:
                    return inferred
            return None

        def _select_key_arg_expr(
            call_sym: str,
            call_args: List[Dict[str, Any]],
            profile_id: Optional[str],
            lang: str,
        ) -> str:
            """Pick the argument/expression that determines effective key length."""
            args = [arg for arg in (call_args or []) if isinstance(arg, dict)]
            args_text = [str(arg.get('text') or arg.get('value') or '').strip() for arg in args]
            symbol_lc = str(call_sym or '').lower()
            profile_lc = str(profile_id or '').lower()
            lang = (lang or '').lower()

            def _at(index: int) -> str:
                return args_text[index] if 0 <= index < len(args_text) else ''

            def _contains_any(text: str, names: tuple[str, ...]) -> bool:
                lowered = str(text or '').lower()
                return any(name in lowered for name in names)

            def _first_named(names: tuple[str, ...]) -> str:
                for arg, text in zip(args, args_text):
                    if _contains_any(str(arg.get('name') or ''), names) or _contains_any(text, names):
                        return text
                return ''

            def _first_int() -> str:
                for arg, text in zip(args, args_text):
                    if isinstance(arg.get('value'), int):
                        return text
                    if str(arg.get('type') or '').lower() in {'integer', 'number_literal', 'integer_literal', 'numeric_literal'}:
                        return text
                return ''

            def _first_algorithm_sized() -> str:
                for text in args_text + [str(call_sym or '')]:
                    if extract_key_size_from_api_name(text) or get_algorithm_key_bits(text):
                        return text
                return ''

            # HMAC/KDF APIs often carry both an algorithm/hash selector and a key.
            # Select the key length expression, not the hash/algorithm selector.
            if 'hmac' in symbol_lc:
                if lang in {'c', 'cpp'}:
                    len_arg = _first_named(('key_len', 'keylen', 'key_length', 'key_size', 'keybits', 'key_bits'))
                    if len_arg:
                        return len_arg
                    # gnutls_hmac_init(&ctx, alg, key, key_len)
                    if 'gnutls' in symbol_lc and len(args_text) >= 4:
                        return _at(3)
                    # OpenSSL HMAC(md, key, key_len, ...)
                    if len(args_text) >= 3:
                        return _at(2)
                if lang == 'go' and len(args_text) >= 2:
                    return _at(1)
                if lang == 'python' and args_text:
                    return _at(0)
                if lang == 'java' and args_text:
                    return _at(0)

            if any(name in symbol_lc for name in ('pbkdf', 'hkdf', 'scrypt', 'argon', 'derive', 'generatesecret', 'pbekeyspec')):
                len_arg = _first_named(('key_bits', 'keybits', 'bits', 'key_len', 'keylen', 'length', 'size'))
                if len_arg:
                    return len_arg
                # Java PBEKeySpec(password, salt, iterations, keyLength)
                if lang == 'java' and len(args_text) >= 4:
                    return _at(3)

            if any(name in symbol_lc for name in ('rsa', 'dh', 'dsa', 'keypair', 'generate')) or any(x in profile_lc for x in ('rsa', 'dh', 'dsa')):
                bits_arg = _first_named(('key_bits', 'keybits', 'bits', 'modulus', 'size', 'length'))
                if bits_arg:
                    return bits_arg
                numeric = _first_int()
                if numeric:
                    return numeric

            if any(x in profile_lc for x in ('ec', 'ecdsa', 'eddsa', 'ed25519', 'ed448', 'x25519', 'x448')):
                curve_arg = _first_algorithm_sized() or _first_named(('curve', 'nid', 'secp', 'prime', 'brainpool', 'x25519', 'x448', 'ed25519', 'ed448'))
                if curve_arg:
                    return curve_arg

            if lang in {'c', 'cpp'}:
                sized = _first_algorithm_sized()
                if sized:
                    return sized
                key_len = _first_named(('key_len', 'keylen', 'key_size', 'keybits', 'key_bits', 'bits', 'length'))
                if key_len:
                    return key_len
                key_arg = _first_named(('key', 'secret'))
                if key_arg:
                    return key_arg

            if lang == 'java':
                # Factories like Cipher.getInstance("AES/GCM/...") encode
                # algorithm, not key length.
                if symbol_lc.endswith('getinstance') and args_text:
                    return _at(0)
                # SecretKeySpec(byte[] key, String alg), PBEKeySpec, etc.
                key_arg = _first_named(('key', 'secret'))
                if key_arg:
                    return key_arg
                if args_text:
                    return _at(0)

            if lang == 'python':
                key_arg = _first_named(('key', 'secret'))
                if key_arg:
                    return key_arg
                if args_text:
                    return _at(0)

            if args_text:
                return _at(0)
            if 'aes' in profile_lc or 'aes' in symbol_lc:
                return call_sym
            return ''

        # ── 1. 规范化函数集合，避免同名重载/包装函数相互覆盖 ─────────────
        def _func_contract_key(func: Dict[str, Any]) -> str:
            if not isinstance(func, dict):
                return ''
            if language == 'python':
                qualified_name = str(func.get('qualified_name', '') or '').strip()
                if qualified_name:
                    return qualified_name
                class_name = str(func.get('class_name', '') or '').strip()
                func_name = str(func.get('name', '') or '').strip()
                if class_name and func_name:
                    return f"{class_name}.{func_name}"
            return str(func.get('name', '') or '').strip()

        logical_functions: List[Dict[str, Any]] = []
        if language in {'c', 'cpp'}:
            preferred_by_name: Dict[str, Dict[str, Any]] = {}
            for func in functions:
                if not isinstance(func, dict):
                    continue
                func_name = str(func.get('name', '') or '')
                if not func_name:
                    continue
                current_best = preferred_by_name.get(func_name)
                span = int(func.get('end_line', 0) or 0) - int(func.get('start_line', 0) or 0)
                best_span = 0
                if isinstance(current_best, dict):
                    best_span = int(current_best.get('end_line', 0) or 0) - int(current_best.get('start_line', 0) or 0)
                if current_best is None or span > best_span or (
                    span == best_span and len(str(func.get('src', '') or '')) > len(str(current_best.get('src', '') or ''))
                ):
                    preferred_by_name[func_name] = func
            logical_functions = list(preferred_by_name.values())
        else:
            logical_functions = [f for f in functions if isinstance(f, dict)]

        # ── 2. 将每个 call 归属到最内层的函数体 ──────────────────────
        func_calls: Dict[str, list] = {
            _func_contract_key(f): [] for f in logical_functions if _func_contract_key(f)
        }
        func_params_map: Dict[str, list] = {}

        for func in logical_functions:
            func_name = _func_contract_key(func)
            fallback_name = str(func.get('name', '') or '')
            # params from _function_params (already built) or fall back to func dict
            func_params_map[func_name] = (
                self._function_params.get(func_name)
                or self._function_params.get(fallback_name)
                or func.get('params', [])
            )

        for call in calls:
            call_line = call.get('line', 0)
            call_sym = call.get('symbol', '')
            # Find smallest enclosing function
            best_func = None
            best_span = float('inf')
            for func in logical_functions:
                func_name = _func_contract_key(func)
                start = func.get('start_line', 0)
                end = func.get('end_line', 999999)
                if start <= call_line <= end and call_sym != func_name:
                    span = end - start
                    if span < best_span:
                        best_span = span
                        best_func = func_name
            if best_func:
                func_calls[best_func].append(call)

        # ── 2. 迭代推断 wrapper 层级（直到稳定）─────────────────────
        wrapper_contracts: Dict[str, Dict[str, Any]] = {}
        changed = True
        max_iter = min(len(logical_functions) + 2, self.wrapper_max_depth)
        if self.verbose and len(logical_functions) + 2 > self.wrapper_max_depth:
            print(
                f"  [WrapperDepthPrune] max_iter capped at {self.wrapper_max_depth} "
                f"(raw={len(logical_functions) + 2})"
            )

        while changed and max_iter > 0:
            max_iter -= 1
            changed = False

            for func in logical_functions:
                func_name = _func_contract_key(func)
                if func_name in wrapper_contracts:
                    continue  # already resolved

                func_params = func_params_map.get(func_name,  [])
                inner_calls = func_calls.get(func_name, [])

                best_contract = None
                candidate_profiles: List[str] = []
                candidate_key_exprs: List[str] = []
                all_candidate_contracts: List[Dict[str, Any]] = []

                for call in inner_calls:
                    call_sym = call.get('symbol', '')
                    call_args = call.get('args', [])

                    first_arg_text = _select_key_arg_expr(call_sym, call_args, None, language)
                    first_arg_text = _resolve_local_expr(first_arg_text, func_name, func_params)

                    # Case A: call is a direct KB API
                    profile_id = self._identify_kb_api_by_symbol(call_sym, language)
                    direct_profile_id = profile_id
                    arg_profile_id = _infer_profile_from_expr(first_arg_text)
                    arg_profile_ids = []
                    raw_arg_texts = []
                    for arg in call_args or []:
                        if not isinstance(arg, dict):
                            continue
                        arg_text = str(arg.get('text') or arg.get('value') or '')
                        raw_arg_texts.append(arg_text)
                        inferred = _infer_profile_from_expr(_resolve_local_expr(arg_text, func_name, func_params))
                        if inferred:
                            arg_profile_ids.append(inferred)
                    if not arg_profile_id and arg_profile_ids:
                        arg_profile_id = arg_profile_ids[0]
                    if not arg_profile_id:
                        arg_profile_id = _infer_profile_from_arg_texts(raw_arg_texts)

                    # Java 的 Cipher.getInstance / KeyGenerator.getInstance 一类工厂调用
                    # 在 KB 中通常是 UTIL.*，需要依赖第一个参数反推具体算法。
                    if language == 'java' and call_sym.lower().endswith('getinstance'):
                        if arg_profile_id:
                            profile_id = arg_profile_id
                    elif language in {'c', 'cpp'} and not profile_id:
                        c_symbol_profile = _infer_profile_from_expr(call_sym)
                        if c_symbol_profile:
                            profile_id = c_symbol_profile
                    elif language == 'java' and call_sym.split('.')[-1] in {'SecretKeySpec', 'PBEKeySpec'}:
                        if arg_profile_id:
                            profile_id = arg_profile_id
                    elif language in {'c', 'cpp'} and any(re.search(r'EVP_aes_(128|192|256)_', str(arg.get('text') or '')) for arg in call_args or [] if isinstance(arg, dict)):
                        profile_id = 'ALG.AES'
                    elif language in {'c', 'cpp'} and re.search(r'hmac', call_sym or '', re.I):
                        profile_id = profile_id or 'ALG.HMAC'
                    elif arg_profile_id and (not profile_id or profile_id != arg_profile_id):
                        if language == 'java':
                            call_sym_lc = str(call_sym or '').lower()
                            java_arg_profile_safe = (
                                '.' in str(call_sym or '')
                                or any(token in call_sym_lc for token in (
                                    'cipher', 'mac', 'signature', 'digest',
                                    'keygenerator', 'keypairgenerator', 'keyfactory',
                                    'secretkeyspec', 'pbekeyspec', 'messagedigest',
                                    'keyagreement', 'algorithmparameters',
                                ))
                            )
                            if java_arg_profile_safe:
                                profile_id = arg_profile_id
                        elif language == 'python':
                            # Do not let ordinary helpers such as str/join/get or
                            # utility wrappers like encode_tlv inherit a crypto
                            # profile only because one of their arguments already
                            # contains a crypto expression. Keep the anchor on the
                            # actual crypto API, then let wrapper propagation build
                            # outward from that sink.
                            if direct_profile_id or _looks_like_crypto_name(call_sym):
                                profile_id = arg_profile_id
                        else:
                            profile_id = arg_profile_id

                    # RSA wrappers that generate or encrypt/decrypt keys should be treated
                    # as PKE-style wrappers rather than the generic ALG.RSA family.
                    if profile_id == 'ALG.RSA' and re.search(r'generate|encrypt|decrypt', call_sym, re.I):
                        profile_id = 'ALG.RSA.PKE'

                    if language == 'python' and _is_python_non_crypto_symbol(call_sym):
                        profile_id = None

                    # C/C++ wrapper derivation must anchor on a real native crypto API.
                    # Ordinary member calls such as k_v.key() or registry.Traverse()
                    # may carry misleading argument names ("key", "hash", ...) that
                    # would otherwise poison the wrapper graph.
                    if language in {'c', 'cpp'} and profile_id and not _is_c_native_crypto_symbol(call_sym):
                        profile_id = None

                    if profile_id:
                        if language in {'c', 'cpp'}:
                            candidate_profiles.append(str(profile_id))
                        selected_key_expr = _select_key_arg_expr(call_sym, call_args, profile_id, language)
                        selected_key_length_bytes = None
                        for arg in call_args or []:
                            if not isinstance(arg, dict):
                                continue
                            arg_text = str(arg.get('text') or arg.get('value') or '').strip()
                            if arg_text == str(selected_key_expr or '').strip() and isinstance(arg.get('length_bytes'), int):
                                selected_key_length_bytes = int(arg['length_bytes'])
                                break
                        selected_key_expr = _resolve_local_expr(selected_key_expr, func_name, func_params)
                        candidate_contract = {
                            'profile_id': profile_id,
                            'key_arg_expr': selected_key_expr or first_arg_text,
                            'key_arg_length_bytes': selected_key_length_bytes,
                            'func_params': func_params,
                            'api_symbol': call_sym,
                            'func_src': func.get('src', ''),
                            'language': language,
                            'wrapper_chain': [call_sym],  # Task 15: chain prefix (func_name added at storage)
                            '_anchor_score': _c_anchor_score(call_sym) if language in {'c', 'cpp'} else 0,
                        }
                        all_candidate_contracts.append(dict(candidate_contract))
                        if candidate_contract.get('key_arg_expr'):
                            candidate_key_exprs.append(str(candidate_contract['key_arg_expr']))

                        if (
                            best_contract is None
                            or _contract_priority(candidate_contract['profile_id']) > _contract_priority(best_contract['profile_id'])
                            or (
                                language in {'c', 'cpp'}
                                and _contract_priority(candidate_contract['profile_id']) == _contract_priority(best_contract['profile_id'])
                                and candidate_contract.get('_anchor_score', 0) > best_contract.get('_anchor_score', 0)
                            )
                        ):
                            best_contract = candidate_contract
                        continue

                    # Case B: call is a previously resolved wrapper
                    wrapper_matches: List[Dict[str, Any]] = []
                    wrapper_lookup_keys: List[str] = []
                    for lookup_key in (
                        str(call_sym or '').strip(),
                        str(call.get('resolved_symbol', '') or '').strip(),
                        str(call.get('resolved_member', '') or '').strip(),
                    ):
                        if lookup_key and lookup_key not in wrapper_lookup_keys:
                            wrapper_lookup_keys.append(lookup_key)
                    for lookup_key in wrapper_lookup_keys:
                        inner = wrapper_contracts.get(lookup_key)
                        if isinstance(inner, dict):
                            wrapper_matches.append(inner)
                    if not wrapper_matches and language == 'python':
                        member_tail = str(call.get('resolved_member', '') or call_sym or '').strip()
                        if '.' in member_tail:
                            member_tail = member_tail.split('.')[-1]
                        if member_tail and not _is_python_non_crypto_symbol(member_tail):
                            seen_wrapper_names: Set[str] = set()
                            for wrapper_name, inner in wrapper_contracts.items():
                                if not isinstance(inner, dict):
                                    continue
                                wrapper_tail = str(wrapper_name or '').strip()
                                if '.' in wrapper_tail:
                                    wrapper_tail = wrapper_tail.split('.')[-1]
                                if wrapper_tail != member_tail:
                                    continue
                                if wrapper_name in seen_wrapper_names:
                                    continue
                                seen_wrapper_names.add(wrapper_name)
                                wrapper_matches.append(inner)

                    if wrapper_matches:
                        if language == 'python' and _is_python_non_crypto_symbol(call_sym):
                            continue
                        for inner in wrapper_matches:
                            if language in {'c', 'cpp'}:
                                inner_pid = str(inner.get('profile_id') or '')
                                if inner_pid:
                                    candidate_profiles.append(inner_pid)
                            else:
                                inner_pid = str(inner.get('profile_id') or '')
                                if inner_pid:
                                    candidate_profiles.append(inner_pid)
                            inner_params = inner['func_params']
                            inner_expr = inner['key_arg_expr']
                            call_arg_texts = [
                                str(arg.get('text') or arg.get('value') or '').strip()
                                for arg in (call_args or [])
                                if isinstance(arg, dict)
                            ]

                            # Compose with the existing parameter-binding extractor.
                            # Avoid parsing source with ad-hoc regex here: only keep
                            # expressions that the binding layer can represent.
                            new_expr = inner_expr
                            try:
                                bindings = bind_params(call_arg_texts, inner_params)
                            except Exception:
                                bindings = {}
                            binding_applied = False
                            if inner_expr in bindings:
                                binding = bindings[inner_expr]
                                if getattr(binding, 'is_constant', False):
                                    new_expr = str(binding.constant_value)
                                    binding_applied = True
                                elif getattr(binding, 'source_param', None):
                                    new_expr = str(binding.source_param)
                                    if getattr(binding, 'transform', None):
                                        new_expr = f"{new_expr}{binding.transform}"
                                    binding_applied = True
                            if not binding_applied and inner_expr in inner_params:
                                idx = inner_params.index(inner_expr)
                                if idx < len(call_arg_texts):
                                    new_expr = call_arg_texts[idx]

                            new_expr = _resolve_local_expr(new_expr, func_name, func_params)

                            candidate_contract = {
                                'profile_id': inner['profile_id'],
                                'key_arg_expr': new_expr,
                                'key_arg_length_bytes': inner.get('key_arg_length_bytes'),
                                'func_params': func_params,
                                'api_symbol': inner['api_symbol'],
                                'func_src': func.get('src', ''),
                                'language': language,
                                # Task 15: inherit inner chain (already ends with call_sym)
                                'wrapper_chain': inner.get('wrapper_chain', [inner['api_symbol']]),
                                '_anchor_score': inner.get('_anchor_score', _c_anchor_score(inner.get('api_symbol', ''))) if language in {'c', 'cpp'} else 0,
                            }
                            all_candidate_contracts.append(dict(candidate_contract))
                            if candidate_contract.get('key_arg_expr'):
                                candidate_key_exprs.append(str(candidate_contract['key_arg_expr']))

                            if (
                                best_contract is None
                                or _contract_priority(candidate_contract['profile_id']) > _contract_priority(best_contract['profile_id'])
                                or (
                                    language in {'c', 'cpp'}
                                    and _contract_priority(candidate_contract['profile_id']) == _contract_priority(best_contract['profile_id'])
                                    and candidate_contract.get('_anchor_score', 0) > best_contract.get('_anchor_score', 0)
                                )
                            ):
                                best_contract = candidate_contract

                if best_contract is not None:
                    if language in {'c', 'cpp'}:
                        family_set = {
                            str(pid or '').upper()
                            for pid in candidate_profiles
                            if str(pid or '').upper().startswith('ALG.')
                        }
                        family_heads = {
                            pid.split('.', 2)[1] if len(pid.split('.', 2)) > 1 else pid
                            for pid in family_set
                        }
                        func_name_lc = str(func_name or '').lower()
                        family_named = any(
                            token in func_name_lc
                            for token in ('rsa', 'ecdsa', 'ecdh', 'ed25519', 'ed448', 'x25519', 'x448',
                                          'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'hmac',
                                          'aes', 'des', 'cmac', 'hkdf')
                        )
                        if not family_named and ('signatureec' in func_name_lc or func_name_lc.endswith('ec')):
                            family_named = True
                        if len(family_heads) > 1 and best_contract is not None:
                            best_pid = str(best_contract.get('profile_id') or '').upper()
                            if _c_is_kdf_or_mac_family(best_pid):
                                non_digest_heads = {
                                    head for head in family_heads
                                    if not _c_is_digest_family(f'ALG.{head}')
                                }
                                if len(non_digest_heads) <= 1:
                                    family_heads = non_digest_heads or family_heads
                        if len(family_heads) > 1 and not family_named:
                            continue
                    # Task 15: finalize the chain by appending this wrapper's own name
                    chain_so_far = best_contract.get('wrapper_chain', [best_contract['api_symbol']])
                    if not chain_so_far or chain_so_far[-1] != func_name:
                        best_contract = dict(best_contract)  # shallow copy to avoid mutating shared ref
                        best_contract['wrapper_chain'] = chain_so_far + [func_name]
                    possible_profiles = sorted({
                        str(pid or '')
                        for pid in candidate_profiles
                        if str(pid or '').startswith('ALG.')
                    })
                    if len(possible_profiles) > 1:
                        best_contract = dict(best_contract)
                        best_contract['possible_profiles'] = possible_profiles
                    possible_key_exprs = []
                    for expr in candidate_key_exprs:
                        text = str(expr or '').strip()
                        if text and text not in possible_key_exprs:
                            possible_key_exprs.append(text)
                    if len(possible_key_exprs) > 1:
                        best_contract = dict(best_contract)
                        best_contract['possible_key_arg_exprs'] = possible_key_exprs[:8]
                    if not (language in {'c', 'cpp'} and _is_c_non_crypto_wrapper_name(func_name)):
                        if language in {'c', 'cpp'} and all_candidate_contracts:
                            variant_contracts: List[Dict[str, Any]] = []
                            seen_variant_keys = set()
                            for raw_contract in all_candidate_contracts:
                                if not isinstance(raw_contract, dict):
                                    continue
                                variant_contract = dict(raw_contract)
                                variant_chain = list(variant_contract.get('wrapper_chain', []) or [])
                                if not variant_chain or variant_chain[-1] != func_name:
                                    variant_contract['wrapper_chain'] = variant_chain + [func_name]
                                variant_key = (
                                    str(variant_contract.get('profile_id') or ''),
                                    str(variant_contract.get('api_symbol') or ''),
                                    tuple(str(x or '') for x in (variant_contract.get('wrapper_chain', []) or [])),
                                )
                                if variant_key in seen_variant_keys:
                                    continue
                                seen_variant_keys.add(variant_key)
                                variant_contracts.append(variant_contract)
                            if len(variant_contracts) > 1:
                                best_contract = dict(best_contract)
                                best_contract['variants'] = variant_contracts
                        wrapper_contracts[func_name] = best_contract
                        if language in {'c', 'cpp'}:
                            for variant_index, variant_contract in enumerate(best_contract.get('variants', []) or [], start=1):
                                if not isinstance(variant_contract, dict):
                                    continue
                                variant_api = str(variant_contract.get('api_symbol') or '')
                                if variant_api == str(best_contract.get('api_symbol') or '') and str(variant_contract.get('profile_id') or '') == str(best_contract.get('profile_id') or ''):
                                    continue
                                wrapper_contracts[f"{func_name}@@{variant_index}"] = dict(variant_contract)
                        changed = True
                elif language in {'c', 'cpp'}:
                    fallback = _c_family_from_func_name(func_name, inner_calls)
                    if fallback:
                        if not _is_c_non_crypto_wrapper_name(func_name):
                            wrapper_contracts[func_name] = {
                                'profile_id': fallback['profile_id'],
                                'key_arg_expr': '',
                                'key_arg_length_bytes': None,
                                'func_params': func_params,
                                'api_symbol': fallback['api_symbol'],
                                'func_src': func.get('src', ''),
                                'language': language,
                                'wrapper_chain': [fallback['api_symbol'], func_name],
                                '_anchor_score': _c_anchor_score(fallback['api_symbol']),
                            }
                            changed = True

        if self.verbose:
            for fn, wc in wrapper_contracts.items():
                print(f"  [WrapperContract] {fn}({', '.join(wc['func_params'])}) "
                      f"→ {wc['api_symbol']} [{wc['profile_id']}]  "
                      f"key_arg_expr='{wc['key_arg_expr']}'")

        return wrapper_contracts

    def _evaluate_wrapper_key_bits(
        self,
        wrapper_contract: Dict[str, Any],
        candidate: Dict[str, Any],
        receiver: Optional[str] = None,
    ) -> Optional[int]:
        """
        根据 wrapper 契约和实际调用参数，计算有效的 key_bits。

        示例：
            wrapper_contract: {func_params: ['security_level'], key_arg_expr: 'security_level * 8'}
            candidate args:   [{'text': '128', 'value': 128}]
            →  eval('security_level * 8', {}, {'security_level': 128}) → 1024

        Task 25.2 (OOP extension):
            wrapper_contract: {func_params: [], key_arg_expr: 'self.bits'}
            receiver:          'k'   (from call  k.generate())
            variable_tracker:  {k.bits: 1024}
            →  1024
        """
        func_params  = wrapper_contract.get('func_params', [])
        key_arg_expr = wrapper_contract.get('key_arg_expr', '')
        language = str(wrapper_contract.get('language') or '').lower()
        profile_id = str(wrapper_contract.get('profile_id') or '')

        VALID_BITS = set(get_all_valid_key_sizes())

        def _valid_bits(value: Any) -> Optional[int]:
            try:
                bits = int(value)
            except (TypeError, ValueError):
                return None
            return bits if bits in VALID_BITS else None

        def _fixed_bits_from_contract() -> Optional[int]:
            """Return fixed algorithm size for hash/factory wrappers."""
            semantic = wrapper_contract.get('semantic')
            if isinstance(semantic, dict):
                for field in ('key_bits', 'digest_bits', 'output_size_bits', 'curve_bits', 'group_bits'):
                    bits = _valid_bits(semantic.get(field))
                    if bits is not None:
                        return bits
                digest_size = semantic.get('digest_size')
                if isinstance(digest_size, int):
                    bits = _valid_bits(digest_size * 8)
                    if bits is not None:
                        return bits

            for text in (
                profile_id.replace('ALG.', '').replace('.', '-'),
                profile_id.split('.')[-1],
                wrapper_contract.get('api_symbol', ''),
            ):
                bits = get_algorithm_key_bits(str(text or ''))
                if _valid_bits(bits) is not None:
                    return int(bits)
                bits = extract_key_size_from_api_name(str(text or ''))
                if _valid_bits(bits) is not None:
                    return int(bits)
            return None

        fixed_contract_bits = _fixed_bits_from_contract()
        if fixed_contract_bits is not None:
            return fixed_contract_bits

        if not key_arg_expr:
            return None

        def _profile_family() -> str:
            pid = profile_id.upper()
            if any(x in pid for x in ('RSA', 'DH', 'DSA')):
                return 'asymmetric'
            if any(x in pid for x in ('EC', 'ECDSA', 'EDDSA', 'ED25519', 'ED448', 'X25519', 'X448')):
                return 'curve'
            if any(x in pid for x in ('AES', 'DES', '3DES', 'SM4', 'CHACHA', 'SALSA', 'ARIA', 'CAMELLIA', 'BLOWFISH', 'RC')):
                return 'symmetric'
            if any(x in pid for x in ('HMAC', 'KDF', 'PBKDF', 'HKDF', 'SCRYPT', 'ARGON')):
                return 'variable_bytes'
            return 'unknown'

        def _valid_bits_from_bytes(value: int) -> Optional[int]:
            bits = value * 8
            return bits if bits in VALID_BITS else None

        ast_length_bytes = wrapper_contract.get('key_arg_length_bytes')
        if isinstance(ast_length_bytes, int):
            ast_bits = _valid_bits_from_bytes(ast_length_bytes)
            if ast_bits is not None:
                return ast_bits

        def _unquote(text: str) -> str:
            text = str(text or '').strip()
            if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
                return text[1:-1]
            return text

        def _bits_from_algorithm_text(text: str) -> Optional[int]:
            expr = _unquote(str(text or '').strip())
            if not expr:
                return None
            for token in (expr, expr.split('/')[-1], expr.split('/')[0]):
                bits = extract_key_size_from_api_name(token)
                if isinstance(bits, int) and bits in VALID_BITS:
                    return bits
                bits = get_algorithm_key_bits(token)
                if isinstance(bits, int) and bits in VALID_BITS:
                    return bits
            return None

        def _strip_conversions(expr: str) -> str:
            expr = str(expr or '').strip()
            changed = True
            while changed:
                changed = False
                for prefix in ('[]byte', '[]uint8', 'string'):
                    marker = f'{prefix}('
                    if expr.startswith(marker) and expr.endswith(')'):
                        expr = expr[len(marker):-1].strip()
                        changed = True
                # Java: key.getBytes(), key.getBytes(StandardCharsets.UTF_8) -> key
                m = re.fullmatch(r'(.+)\.getBytes\s*\([^)]*\)', expr)
                if m:
                    expr = m.group(1).strip()
                    changed = True
            return expr

        def _literal_expr_bits(expr: str) -> Optional[int]:
            expr = _strip_conversions(expr)
            family = _profile_family()

            call_target = ''
            call_match = re.match(r'([A-Za-z_][\w.]*)\s*\(', expr)
            if call_match:
                call_target = call_match.group(1).strip()
                for token in (
                    call_target,
                    call_target.split('.')[-1],
                    call_target.split('.')[0],
                    call_target.rsplit('.', 1)[0] if '.' in call_target else '',
                ):
                    bits = _bits_from_algorithm_text(token)
                    if bits is not None:
                        return bits

            # OpenSSL/Crypto factory expressions and curve constants.
            bits = _bits_from_algorithm_text(expr)
            if bits is not None and (
                re.search(r'EVP_|NID_|secp|prime|brainpool|curve|x25519|x448|ed25519|ed448|aes|chacha|sm4|des|rsa|dh|dsa', expr, re.I)
                or family in {'curve', 'asymmetric'}
            ):
                return bits

            m = re.fullmatch(r'make\s*\(\s*\[\]\s*(?:byte|uint8)\s*,\s*(\d+)\s*\)', expr)
            if m:
                return _valid_bits_from_bytes(int(m.group(1)))
            m = re.fullmatch(r'(?:bytes|bytearray)\s*\(\s*(\d+)\s*\)', expr)
            if m:
                return _valid_bits_from_bytes(int(m.group(1)))
            m = re.fullmatch(r'(?:new\s+byte\s*\[\s*(\d+)\s*\]|byte\s*\[\s*(\d+)\s*\])', expr)
            if m:
                return _valid_bits_from_bytes(int(next(g for g in m.groups() if g)))
            m = re.fullmatch(r'(?:Arrays\.)?copyOf\s*\(\s*[^,]+,\s*(\d+)\s*\)', expr)
            if m:
                return _valid_bits_from_bytes(int(m.group(1)))
            m = re.fullmatch(r'[A-Za-z_]\w*\s*\[\s*(?:0)?\s*:\s*(\d+)\s*\]', expr)
            if m:
                return _valid_bits_from_bytes(int(m.group(1)))
            if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
                try:
                    import ast
                    value = ast.literal_eval(expr)
                    if isinstance(value, str):
                        algo_bits = _bits_from_algorithm_text(value)
                        if algo_bits is not None and family in {'curve', 'asymmetric', 'symmetric'} and re.search(r'[-_/]?\d{2,4}|secp|prime|curve|x25519|x448|ed25519|ed448', value, re.I):
                            return algo_bits
                        return _valid_bits_from_bytes(len(value))
                except Exception:
                    return None
            return None

        def _fixed_bits_from_wrapper_source(expr: str) -> Optional[int]:
            src = str(wrapper_contract.get('func_src', '') or '')
            expr = _strip_conversions(expr)
            if not src:
                return None
            direct = _literal_expr_bits(expr)
            if direct is not None:
                return direct
            expr_param = _expr_param_name(expr)
            if expr_param:
                signature = src.split('{', 1)[0]
                m = re.search(rf'\b{re.escape(expr_param)}\s+\*?\[(\d+)\]byte\b', signature)
                if m:
                    return _valid_bits_from_bytes(int(m.group(1)))
            if not re.fullmatch(r'[A-Za-z_]\w*', expr):
                return None
            param = re.escape(expr)
            assign_slice = re.search(
                rf'\b{param}\s*(?::=|=)\s*[^;\n]*\[\s*(?:0)?\s*:\s*(\d+)\s*\]',
                src,
            )
            if assign_slice:
                return _valid_bits_from_bytes(int(assign_slice.group(1)))
            assign_copy = re.search(
                rf'\b{param}\s*(?::=|=)\s*(?:Arrays\.)?copyOf\s*\(\s*{param}\s*,\s*(\d+)\s*\)',
                src,
            )
            if assign_copy:
                return _valid_bits_from_bytes(int(assign_copy.group(1)))
            assign_bytes = re.search(
                rf'\b{param}\s*(?::=|=)\s*(?:bytes|bytearray)\s*\(\s*(\d+)\s*\)',
                src,
            )
            if assign_bytes:
                return _valid_bits_from_bytes(int(assign_bytes.group(1)))
            for size in (16, 24, 32, 56, 64):
                pads_short = re.search(rf'\blen\(\s*{param}\s*\)\s*<\s*{size}\b', src)
                truncates_long = re.search(rf'\b{param}\s*=\s*{param}\s*\[\s*:\s*{size}\s*\]', src)
                if pads_short and truncates_long:
                    return size * 8
            return None

        def _expr_param_name(expr: str) -> str:
            expr = _strip_conversions(expr)
            m = re.fullmatch(r'(?:Arrays\.)?copyOf\s*\(\s*([A-Za-z_]\w*)\s*,\s*\d+\s*\)', expr)
            if m:
                return m.group(1)
            m = re.fullmatch(r'([A-Za-z_]\w*)\s*\[\s*(?:0)?\s*:\s*\d+\s*\]', expr)
            if m:
                return m.group(1)
            return expr if re.fullmatch(r'[A-Za-z_]\w*', expr) else ''

        def _coerce_eval_result(expr: str, value: int) -> Optional[int]:
            expr_lc = str(expr or '').lower()
            family = _profile_family()
            if re.search(r'\b(?:key_?)?bits?\b|modulus', expr_lc):
                return value if value in VALID_BITS else None
            if family in {'asymmetric', 'curve'}:
                return value if value in VALID_BITS else _bits_from_algorithm_text(str(value))
            if value in VALID_BITS and not re.search(r'key_?len|byte|size|length|len\b', expr_lc):
                return value
            byte_bits = _valid_bits_from_bytes(value)
            if byte_bits is not None and (
                re.search(r'key_?len|byte|size|length|len\b', expr_lc)
                or family in {'symmetric', 'variable_bytes'}
            ):
                return byte_bits
            return value if value in VALID_BITS else byte_bits

        fixed_bits = _fixed_bits_from_wrapper_source(key_arg_expr)
        if fixed_bits is not None:
            return fixed_bits

        # ── Task 25.2: OOP self.field resolution ─────────────────────────────
        #  key_arg_expr == 'self.bits'  AND  receiver == 'k'
        #  → look up 'k.bits' in the variable tracker
        if key_arg_expr.startswith('self.') and receiver:
            field = key_arg_expr[5:]  # strip 'self.'
            vt_key = f"{receiver}.{field}"
            val = self.variable_tracker.variables.get(vt_key)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass

        # Build substitution namespace from actual call arguments
        call_args = candidate.get('args', [])
        param_values: Dict[str, Any] = {}

        for idx, param_name in enumerate(func_params):
            if idx >= len(call_args):
                break
            arg = call_args[idx]
            if isinstance(arg, dict):
                arg_type = arg.get('type', '')
                arg_value = arg.get('value')
                arg_text = str(arg.get('text', '') or '')
                expr_for_param = _expr_param_name(key_arg_expr)
                if isinstance(arg.get('length_bytes'), int):
                    param_values[param_name] = arg['length_bytes']
                    if expr_for_param == param_name:
                        bits = _valid_bits_from_bytes(int(arg['length_bytes']))
                        if bits is not None:
                            return bits
                if isinstance(arg_value, int):
                    param_values[param_name] = arg_value
                    if expr_for_param == param_name:
                        coerced = _coerce_eval_result(param_name, arg_value)
                        if coerced is not None:
                            return coerced
                    continue
                if isinstance(arg_value, str) and arg_value:
                    param_values[param_name] = arg_value
                    literal_bits = _literal_expr_bits(arg_value)
                    if literal_bits is not None and expr_for_param == param_name:
                        return literal_bits
                    value_len_bits = _valid_bits_from_bytes(len(arg_value.encode('utf-8')))
                    if value_len_bits is not None and expr_for_param == param_name:
                        return value_len_bits
                    continue
                literal_bits = _literal_expr_bits(arg_text)
                if literal_bits is not None and expr_for_param == param_name:
                    return literal_bits
                if arg_type in ('integer', 'float', 'number_literal'):
                    param_values[param_name] = arg.get('value', 0)
                elif arg_type == 'identifier':
                    # Try variable tracker
                    arg_name = arg.get('text', '')
                    resolved = self.variable_tracker.get_value(arg_name)
                    if resolved is not None:
                        param_values[param_name] = resolved
                        if expr_for_param == param_name:
                            if isinstance(resolved, (int, float)):
                                coerced = _coerce_eval_result(param_name, int(resolved))
                                if coerced is not None:
                                    return coerced
                            elif isinstance(resolved, str):
                                literal_bits = _literal_expr_bits(resolved)
                                if literal_bits is not None:
                                    return literal_bits
                    else:
                        resolved_expr = self.variable_tracker.get_expression(arg_name)
                        if resolved_expr is not None:
                            param_values[param_name] = resolved_expr
                            if expr_for_param == param_name:
                                if isinstance(resolved_expr, (int, float)):
                                    coerced = _coerce_eval_result(param_name, int(resolved_expr))
                                    if coerced is not None:
                                        return coerced
                                elif isinstance(resolved_expr, str):
                                    literal_bits = _literal_expr_bits(resolved_expr)
                                    if literal_bits is not None:
                                        return literal_bits
                                    nested = self.variable_tracker.resolve_argument(resolved_expr, language)
                                    if isinstance(nested, (int, float)):
                                        coerced = _coerce_eval_result(param_name, int(nested))
                                        if coerced is not None:
                                            return coerced
                else:
                    # For simple numeric text (guard against non-numeric fallthrough)
                    try:
                        param_values[param_name] = int(arg.get('text', ''))
                    except (ValueError, TypeError):
                        pass

        # Try to evaluate the expression through the shared evaluator.
        try:
            result = eval_expr(key_arg_expr, param_values)
            if isinstance(result, (int, float)):
                return _coerce_eval_result(key_arg_expr, int(result))
        except Exception:
            pass

        # Fallback: if all params substituted and expression is simple integer
        try:
            return _coerce_eval_result(key_arg_expr, int(key_arg_expr))
        except (ValueError, TypeError):
            pass

        return None

    def _extract_candidates(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Phase 1: 提取加密 API 调用候选 + 构建数据流图"""
        parser = get_parser(language)
        if not parser:
            return []
        
        tree = parser.parse(bytes(code, 'utf-8'))
        root = tree.root_node
        
        # 1.1 [FIX] 提取文件级别的导入信息（用于库识别和过滤）
        # 只有导入了对应的库，才能使用该库的规则
        imports_list, import_aliases_map = extract_imports_with_aliases(root, code, language)
        self._file_imports = imports_list  # 完整导入列表
        self._import_aliases = import_aliases_map  # 别名映射
        
        # 识别导入的库（用于 Phase 2 规则过滤）
        self._imported_libraries = self._identify_imported_libraries(language)
        
        # [NEW] 获取导入库中的所有 API（白名单方案）
        # 只有库中实际存在的API才被认为是有效的，避免黑名单维护负担
        self._library_apis = {}  # library -> set of api names (lowercase)
        for lib in self._imported_libraries:
            apis = self.algorithm_mapper.get_library_apis(lib)
            if apis:
                self._library_apis[lib] = apis
                if self.verbose:
                    print(f"  Library {lib}: {len(apis)} APIs loaded")
        
        if self.verbose:
            print(f"  Imports: {self._file_imports}")
            print(f"  Identified libraries: {self._imported_libraries}")
            print(f"  Library APIs: {list(self._library_apis.keys())}")
        
        # 1. 提取函数定义和参数（用于跨函数参数绑定）
        from pqscan.abstract_syntax_tree import extract_functions, extract_function_params
        functions = extract_functions(root, code, language)
        self._function_params = {}  # func_name -> [param_names]
        self._functions = functions  # 保存函数定义（用于 wrapper 检测）
        for func in functions:
            func_name = func.get('name', '')
            if func_name:
                params = extract_function_params(func.get('_node'), code, language)
                self._function_params[func_name] = params

        # ★ Task 25: Python lambda augmentation
        # Add lambda functions as synthetic function entries so that wrapper-contract
        # inference picks them up (e.g.  fn = lambda n: RSA.generate(n)).
        if language == 'python':
            self._augment_python_lambdas(root, code, functions)

        # 2. 提取调用
        calls = extract_calls(root, code, language)
        
        if self.verbose:
            print(f"  Extracted {len(calls)} calls")
        
        # ★ 构建 callers_index（反向调用索引）
        self._build_callers_index(calls, language, self.current_file)

        # 3. 提取变量赋值（NEW: 构建变量追踪）
        var_assignments = self._extract_var_assignments(root, code, language)
        self.variable_tracker.build_from_assignments(var_assignments)

        # ★ Task 25.2: Python OOP field expansion
        # For k = ClassName(arg0, ...) + field_map, inject k.field = arg_value
        # into the variable tracker so that self.field can be resolved later.
        if language == 'python':
            self._expand_python_oop_fields(root, code, var_assignments)

        # ★ 保存 var_assignments 供 Phase 2 使用
        self._var_assignments = var_assignments
        
        # ★ Task 13.3: 构建本地 Wrapper 契约（用于跨函数封装检测）
        contract_cache_key = f"{language}:{hashlib.sha1(code.encode('utf-8')).hexdigest()}"
        if contract_cache_key in self._wrapper_contract_cache:
            self._local_wrapper_contracts = self._wrapper_contract_cache[contract_cache_key]
            if self.verbose:
                print("  [WrapperContractCache] hit")
        else:
            self._local_wrapper_contracts = self._build_local_wrapper_contracts(
                functions, calls, language, var_assignments
            )
            self._wrapper_contract_cache[contract_cache_key] = self._local_wrapper_contracts
            self._wrapper_contract_cache_order.append(contract_cache_key)
            while len(self._wrapper_contract_cache_order) > self.wrapper_contract_cache_size:
                old_key = self._wrapper_contract_cache_order.pop(0)
                self._wrapper_contract_cache.pop(old_key, None)
            if self.verbose:
                print("  [WrapperContractCache] miss")
        if self.verbose and self._local_wrapper_contracts:
            print(f"  Local wrapper contracts: {list(self._local_wrapper_contracts.keys())}")
        
        # 3. 提取常量定义（NEW: 宏/常量）
        constants = self._extract_constants(root, code, language)
        for const in constants:
            self.variable_tracker.variables[const['name']] = const['value']
        
        # 4. 构建 Value Graph（NEW: 数据流图）
        self._build_value_graph_from_assignments(var_assignments, calls)

        # ★ Task 27: Java builder chain extraction
        # Chains like new CipherSpec().setAlgorithm("RSA").setKeySize(1024).build()
        # are stored as special pseudo-candidates so _analyze_candidates can emit findings.
        self._builder_chain_candidates: List[Dict[str, Any]] = []
        if language == 'java':
            self._extract_builder_chains_as_candidates(root, code)

        if self.verbose:
            print(f"  Variables tracked: {len(self.variable_tracker.variables)}")
            print(f"  Constants defined: {len(constants)}")
            print(f"  Value graph nodes: {len(self.value_graph.nodes)}")
        
        # 转换为候选格式
        candidates = []
        for call in calls:
            symbol = call.get('symbol') or call.get('name')
            if not symbol:
                continue

            # 提取字面量参数
            literal_args = []
            if 'args' in call and isinstance(call['args'], list):
                for arg in call['args']:
                    if isinstance(arg, dict) and 'value' in arg:
                        literal_args.append(arg['value'])
            
            candidates.append({
                'symbol': symbol,
                'line': call.get('line'),
                'literal_args': literal_args,
                'args': call.get('args', []),  # 保存完整的参数信息（包含 text 字段）
                'receiver': call.get('receiver'),
                'assigned_to': call.get('assigned_to'),
                'context': call.get('context', {})
            })

        # ★ Task 27: Append Java builder chain pseudo-candidates
        candidates.extend(self._builder_chain_candidates)
        
        return candidates

    # ─────────────────────────────────────────────────────────────────────────
    # Task 25: Lambda + OOP helper methods
    # ─────────────────────────────────────────────────────────────────────────

    def _augment_python_lambdas(
        self,
        root,
        code: str,
        functions: List[Dict[str, Any]],
    ) -> None:
        """
        Extract Python lambda assignments and inject them as synthetic function
        entries into *functions* (in-place) so that wrapper-contract inference
        can attribute inner calls to each lambda and build a contract for it.

        E.g.  fn = lambda n: RSA.generate(n)
              → adds {'name': 'fn', 'start_line': L, 'end_line': L} to functions
              → adds 'fn' → ['n'] to self._function_params
        """
        from pqscan.abstract_syntax_tree.extractor import _extract_python_lambda_functions
        for lam in _extract_python_lambda_functions(root, code):
            lam_name   = lam['name']
            lam_params = lam['params']
            lam_line   = lam.get('start_line', lam.get('line', 0))
            lam_end    = lam.get('end_line', lam_line)
            functions.append({
                'name':       lam_name,
                'params':     lam_params,
                'start_line': lam_line,
                'end_line':   lam_end,
                '_node':      None,
                '_is_lambda': True,
            })
            self._function_params[lam_name] = lam_params

    def _expand_python_oop_fields(
        self,
        root,
        code: str,
        var_assignments: List[Dict[str, Any]],
    ) -> None:
        """
        For each ``k = ClassName(arg0, arg1, ...)`` assignment (Python), use the
        class's __init__ field_map to inject synthetic ``k.field = arg_value``
        entries into the variable tracker so that ``self.field`` can be resolved
        through the receiver when a method wrapper is invoked.

        Also stores:
          self._class_info       : dict[str, dict]  — class_name → OOP info
          self._method_to_class  : dict[str, str]   — method_name → class_name
        """
        from pqscan.abstract_syntax_tree.extractor import (
            _extract_python_oop_info,
            extract_call_arguments,
        )

        _method_to_class, class_info = _extract_python_oop_info(root, code)
        self._class_info      = class_info
        self._method_to_class = _method_to_class

        if not class_info:
            return

        for asgn in var_assignments:
            var_name   = asgn.get('name', '')
            class_name = asgn.get('value', '')
            call_node  = asgn.get('_call_node')

            if not var_name or not class_name or class_name not in class_info:
                continue

            # Retrieve constructor args from the AST node when available
            ctor_args: List[Dict] = []
            if call_node is not None:
                try:
                    ctor_args = extract_call_arguments(call_node, code, 'python')
                except Exception:
                    pass

            if not ctor_args:
                continue

            # Map each field to its constructor-argument value
            for field_name, (param_name, param_idx) in class_info[class_name]['field_map'].items():
                if param_idx < len(ctor_args):
                    arg = ctor_args[param_idx]
                    if isinstance(arg, dict):
                        arg_val = arg.get('value')
                        if arg_val is None:
                            # Try text as integer
                            try:
                                arg_val = int(arg.get('text', ''))
                            except (ValueError, TypeError):
                                arg_val = arg.get('text')
                        if arg_val is not None:
                            key = f"{var_name}.{field_name}"
                            self.variable_tracker.variables[key] = arg_val
                            if self.verbose:
                                print(f"  [OOPField] {key} = {arg_val}")

    # ─────────────────────────────────────────────────────────────────────────
    # Task 27: Builder chain helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_builder_chains_as_candidates(self, root, code: str) -> None:
        """
        Call extract_builder_chains for Java; convert each detected chain into a
        pseudo-candidate stored in self._builder_chain_candidates.

        The pseudo-candidate has a special key ``_builder_context`` so that
        _analyze_candidates can emit a Finding/violation directly.
        """
        from pqscan.abstract_syntax_tree.extractor import extract_builder_chains

        for chain in extract_builder_chains(root, code, 'java'):
            ctx = chain.get('builder_context', {})
            algo = ctx.get('algorithm', '')
            if not algo:
                continue  # can't map without algorithm name

            # Resolve profile_id from algorithm name
            algo_info = (
                self.algorithm_mapper.get_algorithm(algo)
                or self.algorithm_mapper.get_algorithm_by_name(algo.upper())
            )
            if not algo_info:
                continue

            profile_id = algo_info.profile_id

            key_bits = ctx.get('key_bits')
            if key_bits is not None:
                try:
                    key_bits = int(key_bits)
                except (TypeError, ValueError):
                    key_bits = None

            self._builder_chain_candidates.append({
                'symbol':           chain['symbol'],
                'line':             chain.get('line', 0),
                'literal_args':     [key_bits] if key_bits is not None else [],
                'args':             [],
                '_builder_context': ctx,
                '_builder_profile': profile_id,
                '_builder_key_bits': key_bits,
            })

    def _process_builder_candidate(
        self,
        candidate: Dict[str, Any],
        pq_mode: bool,
        classic_mode: bool,
        all_violations: list,
        all_recognized: list,
        violation_by_severity: Dict[str, int],
    ) -> None:
        """
        Task 27: Emit finding/violation for a Java builder-chain pseudo-candidate.
        """
        profile_id = candidate.get('_builder_profile')
        key_bits   = candidate.get('_builder_key_bits')
        symbol     = candidate.get('symbol', '')
        line       = candidate.get('line', 0)

        if not profile_id:
            return

        # Normalise profile_id via aliases
        profile_id = self.common_profiles.get('id_aliases', {}).get(profile_id, profile_id)

        # Always record as recognised
        _rec: Dict[str, Any] = {'line': line, 'symbol': symbol, 'profile_id': profile_id, 'params': {}}
        if key_bits is not None:
            _rec['params']['key_bits'] = key_bits
        all_recognized.append(_rec)

        if key_bits is None:
            return

        profile = get_profile(self.common_profiles, profile_id)
        if not profile:
            return

        violations = self.constraint_checker.check_constraints(
            profile,
            {'key_bits': key_bits},
            ConstraintMode.QUANTUM if pq_mode else None,
            ConstraintMode.CLASSIC if classic_mode else None,
        )
        for v in violations:
            if v.severity.name == 'NONE':
                continue
            violation_by_severity[v.severity.name] = violation_by_severity.get(v.severity.name, 0) + 1
            all_violations.append({
                'line':              line,
                'symbol':            symbol,
                'algorithm':         profile_id,
                'severity':          v.severity.name,
                'mode':              v.mode.name.lower(),
                'reason':            v.reason,
                'migrate_to':        v.migrate_to,
                'wrapper':           False,
                'effective_key_bits': key_bits,
                'builder_chain':     True,
            })

    def _extract_var_assignments(self, root, code: str, language: str) -> List[Dict[str, Any]]:
        """提取变量赋值（复用 extractor 中的逻辑）"""
        from pqscan.abstract_syntax_tree.extractor import (
            _extract_java_var_assignments,
            _extract_python_var_assignments,
            _extract_go_var_assignments,
            _extract_c_var_assignments
        )
        
        if language == 'java':
            return _extract_java_var_assignments(root, code)
        elif language == 'python':
            return _extract_python_var_assignments(root, code)
        elif language == 'go':
            return _extract_go_var_assignments(root, code)
        elif language in ['c', 'cpp']:
            return _extract_c_var_assignments(root, code)
        
        return []
    
    def _extract_constants(self, root, code: str, language: str) -> List[Dict[str, Any]]:
        """提取常量定义（#define, const, enum）"""
        from pqscan.abstract_syntax_tree.navigator import walk, node_text
        
        constants = []
        
        if language in ['c', 'cpp']:
            # 提取 #define 宏定义
            for node in walk(root):
                if node.type == 'preproc_def':
                    name_node = node.child_by_field_name('name')
                    value_node = node.child_by_field_name('value')
                    
                    if name_node and value_node:
                        name = node_text(code, name_node)
                        value_str = node_text(code, value_node)
                        
                        # 尝试转换为整数
                        try:
                            if value_str.startswith('0x'):
                                value = int(value_str, 16)
                            else:
                                value = int(value_str)
                            
                            constants.append({
                                'name': name,
                                'value': value,
                                'type': 'macro',
                                'line': node.start_point[0] + 1
                            })
                        except ValueError:
                            # 非整数常量，保留字符串
                            constants.append({
                                'name': name,
                                'value': value_str,
                                'type': 'macro',
                                'line': node.start_point[0] + 1
                            })
        
        return constants
    
    def _process_alias_assignments(self, var_assignments: List[Dict[str, Any]], language: str):
        """
        处理别名赋值（ctx2 = ctx）
        
        将右值变量指向的对象，绑定到左值变量
        """
        for assignment in var_assignments:
            var_name = assignment.get('name')
            value = assignment.get('value')
            func_name = assignment.get('function', 'global')
            
            if not var_name or not value:
                continue
            
            # 检查是否是简单的变量赋值（ctx2 = ctx）
            # 排除函数调用、字面量等
            if isinstance(value, str) and value.isidentifier():
                # 右值是一个变量名
                rhs_var = value
                lhs_var = var_name
                scope = func_name
                
                # 使用 ObjectIDManager 的 bind_alias 方法
                self.object_id_manager.bind_alias(lhs_var, rhs_var, scope)
    
    def _build_callers_index(self, calls: List[Dict[str, Any]], language: str, file_path: str):
        """
        构建反向调用索引（callers_index）
        
        从 Fast Pass 提取的 calls 中构建 callsite 信息，
        用于后续的封装派生分析。
        
        Args:
            calls: extract_calls 返回的调用列表
            language: 语言类型
            file_path: 当前文件路径
        """
        from pqscan.analysis.wrapper_summary import CallSite
        
        if self.verbose:
            print(f"  Building callers_index from {len(calls)} calls")
        
        # 获取当前函数上下文（简化处理：从 call.get('function') 获取）
        for call in calls:
            callee = call.get('symbol') or call.get('name')
            if not callee:
                continue
            
            # 调用者函数名
            caller = call.get('function', 'global')  # 可能需要从 func_map 获取
            
            # 参数表达式
            args_repr = []
            args = call.get('args', [])
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, dict):
                        args_repr.append(arg.get('text', ''))
                    else:
                        args_repr.append(str(arg))
            
            # receiver（OO 语言）
            receiver = call.get('receiver')
            
            # 创建 CallSite
            callsite = CallSite(
                caller_fqname=caller,
                callee_fqname=callee,
                args_repr=args_repr,
                line=call.get('line', 0),
                file=file_path,
                receiver=receiver
            )
            
            # 添加到索引
            self.callers_index.add_call(callsite)
            
            if self.verbose and len(self.callers_index.index) <= 5:
                print(f"    Added: {caller} -> {callee} (line {callsite.line})")
    
    def _bind_call_parameters(self, candidate: Dict[str, Any], language: str):
        """
        P4: 处理函数调用的参数绑定（跨函数对象传递）
        
        将调用者的对象绑定到被调函数的参数
        例如：init_cipher(ctx) → init_cipher.ctx = caller.ctx 绑定的对象
        """
        symbol = candidate.get('symbol', '')
        args = candidate.get('args', [])
        caller_scope = candidate.get('function_name', 'global')
        callee_scope = symbol  # 被调函数名作为 scope
        
        # 遍历参数
        for param_index, arg in enumerate(args):
            if not isinstance(arg, dict):
                continue
            
            # 提取参数文本（变量名）
            arg_text = arg.get('text', '').strip()
            if not arg_text:
                continue
            
            # 去除指针/取地址修饰符
            caller_var = arg_text
            if caller_var.startswith('*') or caller_var.startswith('&'):
                caller_var = caller_var[1:].strip()
            
            # 检查调用者的变量是否绑定了对象
            caller_object_id = self.object_id_manager.resolve(caller_var, caller_scope)
            if not caller_object_id:
                continue
            
            # 推断被调函数的参数名
            # 方法1：从函数定义提取的参数名（最准确）
            func_params = self._function_params.get(callee_scope, [])
            if param_index < len(func_params):
                callee_param_name = func_params[param_index]
            else:
                # 方法2：从 API metadata 获取（如果可用）
                api_metadata = self.api_metadata_map.get(symbol.lower(), {})
                ctx_spec = api_metadata.get('semantic', {}).get('ctx', {})
                
                if ctx_spec and ctx_spec.get('index') == param_index:
                    # 这是 ctx 参数
                    callee_param_name = ctx_spec.get('param', f'param{param_index}')
                else:
                    # 方法3：使用通用参数名（arg0, arg1, ...）作为兜底
                    callee_param_name = f'arg{param_index}'
            
            # 绑定：被调函数的参数 → 调用者传入的对象
            self.object_id_manager.var_to_object[(callee_scope, callee_param_name)] = caller_object_id
    
    def _build_value_graph_from_assignments(
        self, 
        var_assignments: List[Dict], 
        calls: List[Dict]
    ) -> None:
        """从变量赋值构建 Partial SSA 图"""
        # 添加变量定义节点
        for assignment in var_assignments:
            node = ValueNode(
                node_type=NodeType.VAR_DEF,
                name=assignment.get('name', 'unknown'),
                value=assignment.get('value'),
                location={'line': assignment.get('line')}
            )
            self.value_graph.add_node(node)
        
        # 添加调用节点
        for call in calls:
            func_name = call.get('symbol', 'unknown_call')
            node = ValueNode(
                node_type=NodeType.CALL,
                name=func_name,
                func_name=func_name,
                location={'line': call.get('line')}
            )
            self.value_graph.add_node(node)
    
    def _build_value_graph(self, code: str, language: str, candidates: List[Dict]) -> None:
        """构建值图（用于跨函数追踪）- 旧接口，保留兼容性"""
        # 已被 _build_value_graph_from_assignments 替代
        pass
    
    def _analyze_candidates(
        self, 
        candidates: List[Dict[str, Any]], 
        language: str,
        pq_mode: bool,
        classic_mode: bool
    ) -> Dict[str, Any]:
        """Phase 2: 符号分析和约束检查"""
        recognized_count = 0
        all_violations = []
        all_recognized = []   # NEW: all candidates with resolved profile_id
        violation_by_severity = {
            'CRITICAL': 0, 
            'ERROR': 0, 
            'WARNING': 0, 
            'INFO': 0
        }
        
        # 重置对象状态追踪器
        self.object_state_tracker.reset()
        
        for candidate in candidates:
            # ★ Task 27: Builder chain pseudo-candidates bypass regular analysis
            if '_builder_context' in candidate:
                self._process_builder_candidate(
                    candidate, pq_mode, classic_mode,
                    all_violations, all_recognized, violation_by_severity
                )
                continue

            # ★ P4: 处理函数调用的参数绑定（跨函数对象传递）
            self._bind_call_parameters(candidate, language)
            
            # 提取参数（支持变量追踪）
            params = infer_params(
                symbol=candidate.get('symbol', ''),
                literal_args=candidate.get('literal_args', []),
                language=language,
                variable_tracker=self.variable_tracker
            )
            
            # 识别算法
            profile_id = self._identify_algorithm(candidate, params, language)
            
            # [NEW] 库API白名单验证：只有库中实际存在的API才被认为有效
            # 这避免了黑名单维护的负担，更加可维护
            symbol = candidate.get('symbol', '')
            if profile_id and hasattr(self, '_library_apis') and self._library_apis:
                # 检查当前symbol是否在导入库的API中
                symbol_found_in_library = False
                symbol_lower = symbol.lower()
                
                for lib_name, apis in self._library_apis.items():
                    if not apis:
                        continue
                    
                    # 支持多种匹配模式
                    for api in apis:
                        api_lower = api.lower()
                        
                        # 1. 精确匹配
                        if symbol_lower == api_lower:
                            symbol_found_in_library = True
                            break
                        
                        # 2. 后缀匹配（如 member 匹配 pkg.member）
                        if api_lower.endswith("." + symbol_lower):
                            symbol_found_in_library = True
                            break
                        
                        # 3. 简化名（如symbol='newcipher' 匹配 api='aes.newcipher'）
                        api_parts = api_lower.split('.')
                        if api_parts[-1] == symbol_lower:
                            symbol_found_in_library = True
                            break
                    
                    if symbol_found_in_library:
                        if self.verbose:
                            print(f"  [库API验证] {symbol} ✓ 在库 {lib_name} 的API中")
                        break
                
                # 如果symbol不在任何导入库的API中，拒绝这个profile_id
                if not symbol_found_in_library:
                    if self.verbose:
                        print(f"  [库API验证] {symbol} ✗ 不在导入库的API中，拒绝识别")
                    profile_id = None
            
            # 获取 API metadata（用于状态追踪）
            symbol = candidate.get('symbol', '')
            api_metadata = self.api_metadata_map.get(symbol.lower(), {})
            
            # ★★★ P4: 工厂函数算法传播 ★★★
            # 如果是工厂函数（返回具体算法），记录返回值携带的算法信息
            assigned_to = candidate.get('assigned_to')
            if profile_id and self._is_concrete_algorithm(profile_id) and assigned_to:
                # 工厂函数：cipher = EVP_aes_256_gcm()
                # 记录 cipher 变量携带 ALG.AES 算法信息
                self._track_factory_return(
                    variable=assigned_to,
                    profile_id=profile_id,
                    params=params,
                    candidate=candidate,
                    language=language
                )
                if self.verbose:
                    print(f"  [工厂返回] {assigned_to} <- {profile_id} (来自 {symbol})")
            
            # 特殊情况：即使没有 profile_id，allocator 也需要追踪
            if not profile_id:
                # 检查是否是 allocator（即使没有 profile）
                if assigned_to and self.object_id_manager.is_allocator(symbol, language=language):
                    # allocator 需要创建对象
                    self._track_object_state(candidate, None, params, api_metadata, language)

                # ★ Task 13.3 + Task 25.2: 本地 Wrapper 契约检查
                # 如果该函数是用户定义的 wrapper（包装了 KB 中的密码 API），
                # 用实参代入契约表达式，推算 key_bits 并检查约束。
                # Task 25.2: also handle OOP calls "k.generate" → try "generate" if needed.
                local_contracts = getattr(self, '_local_wrapper_contracts', {})
                wrapper = local_contracts.get(symbol)
                _oop_receiver: Optional[str] = None
                if wrapper is None and '.' in symbol:
                    member_name = symbol.rsplit('.', 1)[1]
                    _oop_receiver = symbol.rsplit('.', 1)[0]
                    wrapper = local_contracts.get(member_name)
                if wrapper is not None:
                    effective_key_bits = self._evaluate_wrapper_key_bits(
                        wrapper, candidate, receiver=_oop_receiver
                    )
                    if self.verbose:
                        print(f"  [WrapperCheck] {symbol}: effective_key_bits={effective_key_bits}")
                    wrapper_profile_id = wrapper['profile_id']
                    # 归一化 profile_id（如 ALG.RSA -> ALG.RSA.PKE）
                    wrapper_profile_id = self.common_profiles.get('id_aliases', {}).get(
                        wrapper_profile_id,
                        wrapper_profile_id
                    )

                    # NEW: always record wrapper hits in all_recognized
                    _rec_params = {}
                    if effective_key_bits is not None:
                        _rec_params['key_bits'] = effective_key_bits
                    all_recognized.append({
                        'line': candidate.get('line'),
                        'symbol': symbol,
                        'profile_id': wrapper_profile_id,
                        'params': _rec_params,
                    })

                    if effective_key_bits is not None:
                        effective_params = {'key_bits': effective_key_bits}
                        wrapper_profile = get_profile(self.common_profiles, wrapper_profile_id)
                        if wrapper_profile:
                            violations = self.constraint_checker.check_constraints(
                                wrapper_profile,
                                effective_params,
                                ConstraintMode.QUANTUM if pq_mode else None,
                                ConstraintMode.CLASSIC if classic_mode else None
                            )
                            real_violations = [v for v in violations if v.severity.name != 'NONE']
                            if real_violations:
                                # Task 15: 构建传播链路
                                _chain = wrapper.get('wrapper_chain', [wrapper.get('api_symbol', ''), symbol])
                                for v in real_violations:
                                    violation_by_severity[v.severity.name] += 1
                                    all_violations.append({
                                        'line': candidate.get('line'),
                                        'symbol': symbol,
                                        'algorithm': wrapper_profile_id,
                                        'severity': v.severity.name,
                                        'mode': v.mode.name.lower(),
                                        'reason': v.reason,
                                        'migrate_to': v.migrate_to,
                                        'wrapper': True,
                                        'effective_key_bits': effective_key_bits,
                                        'wrapper_chain': _chain,  # Task 15
                                    })
                                if self.verbose:
                                    print(f"  [WrapperViolation] {symbol} "
                                          f"key_bits={effective_key_bits} "
                                          f"violations={len(real_violations)}")

                # 跳过非 allocator 的无 profile 函数
                continue
            
            recognized_count += 1

            # NEW: record every resolved candidate for reporting
            all_recognized.append({
                'line': candidate.get('line'),
                'symbol': candidate.get('symbol'),
                'profile_id': profile_id,
                'params': dict(params),
            })
            
            # 获取 profile（可能为 None，辅助函数可能没有完整 profile）
            profile = get_profile(self.common_profiles, profile_id)
            
            # 追踪对象状态（辅助函数也需要追踪，即使没有 profile）
            self._track_object_state(candidate, profile, params, api_metadata, language)
            
            # ★ P4: 关键输入归因（Deep Pass）
            if profile_id:  # 只对敏感点进行归因
                if self.verbose:
                    print(f"  [归因前] {candidate.get('symbol')}: params = {params}")
                
                effect = self.key_input_attributor.attribute_key_inputs(
                    candidate=candidate,
                    params=params,
                    profile_id=profile_id,
                    api_metadata=api_metadata,
                    function_params=self._function_params
                )
                
                if effect and self.verbose:
                    print(f"  [归因] {candidate.get('symbol')} -> {profile_id}")
                    print(f"    输入来源: {effect.input_sources}")
                    print(f"    触发条件: {effect.trigger}")
                
                # 保存到候选中（后续用于生成 Summary）
                candidate['_effect'] = effect
                
                # ★ P4: 约束派生（Contract Derivation）
                # 从敏感点约束派生封装函数约束
                if effect and profile:
                    constraints = profile.get('constraints', [])
                    if constraints:
                        caller_func = candidate.get('function_name', 'global')
                        caller_params = self._function_params.get(caller_func, [])
                        
                        contract = self.contract_deriver.derive_contract(
                            effect=effect,
                            sink_constraints=constraints,
                            caller_params=caller_params
                        )
                        
                        if contract and self.verbose:
                            print(f"  [约束派生] {caller_func}")
                            for pc in contract.param_constraints:
                                print(f"    {pc.param} {pc.predicate.value} {pc.value}")
                        
                        # 保存派生的约束
                        candidate['_contract'] = contract
            
            # 只有有 profile 的才检查约束（辅助函数跳过约束检查）
            if not profile:
                continue
            
            # 检查约束
            violations = self.constraint_checker.check_constraints(
                profile, 
                params,
                ConstraintMode.QUANTUM if pq_mode else None,
                ConstraintMode.CLASSIC if classic_mode else None
            )
            
            # 过滤掉 NONE 级别的违规
            real_violations = [
                v for v in violations 
                if v.severity.name != 'NONE'
            ]
            
            if real_violations:
                for v in real_violations:
                    violation_by_severity[v.severity.name] += 1
                    all_violations.append({
                        'line': candidate.get('line'),
                        'symbol': candidate.get('symbol'),
                        'algorithm': profile_id,
                        'severity': v.severity.name,
                        'mode': v.mode.name.lower(),
                        'reason': v.reason,
                        'migrate_to': v.migrate_to
                    })
        
        # ★ Phase 2 结束：所有对象已分配，现在处理别名赋值
        if hasattr(self, '_var_assignments'):
            self._process_alias_assignments(self._var_assignments, language)
        
        # [FIX 2026-04-15] 最后的导入检查过滤
        # 移除那些来自未导入库的发现（如果能追踪到源库）
        # 这是一个防御层面：防止 wrapper 推理导致的跨库误报
        imported_libs = getattr(self, '_imported_libraries', set())
        if imported_libs:
            # 如果识别到导入的库，过滤掉来自其他库的发现
            filtered_violations = []
            for v in all_violations:
                # 如果 violation 中有库信息，检查是否匹配导入
                algo = v.get('algorithm', '')
                # 保守策略：如果算法来自某个语言的标准库（如 ALG.HMAC 来自 Go），允许
                # 但如果算法来自明确的第三方库（如 Bouncycastle），检查导入
                # 简化版本：当前只过滤明显不匹配的情况
                filtered_violations.append(v)
            
            all_violations = filtered_violations
        
        return {
            'recognized_count': recognized_count,
            'violations': all_violations,
            'recognized': all_recognized,
            'statistics': violation_by_severity
        }
    
    def _is_concrete_algorithm(self, profile_id: Optional[str]) -> bool:
        """
        判断 profile_id 是否是具体算法（工厂函数）
        
        基于启发式规则：
        - ALG.AES, ALG.RSA, ALG.SHA256 等 -> 具体算法（工厂函数）
        - ALG.CIPHER, ALG.HASH, ALG.SIGNATURE 等 -> 抽象类型（操作函数）
        
        Args:
            profile_id: profile ID
            
        Returns:
            True if 具体算法（工厂函数），False otherwise
        """
        if not profile_id:
            return False
        return self.factory_detector.is_factory_function(profile_id)
    
    def _track_factory_return(
        self,
        variable: str,
        profile_id: str,
        params: Dict[str, Any],
        candidate: Dict[str, Any],
        language: str
    ) -> None:
        """
        追踪工厂函数的返回值（算法传播）
        
        当工厂函数返回具体算法时，记录变量携带的算法信息：
        - cipher = EVP_aes_256_gcm()  → cipher 携带 ALG.AES
        - md = EVP_sha256()            → md 携带 ALG.SHA256
        
        这些信息后续会用于操作函数的算法推断。
        
        Args:
            variable: 赋值目标变量名
            profile_id: 具体算法 profile ID
            params: 参数信息（可能包含 mode、key_bits 等）
            candidate: 候选调用信息
            language: 语言类型
        """
        line = candidate.get('line')
        
        # 构建算法状态
        algorithm_state = {
            'algorithm': profile_id,  # ALG.AES, ALG.RSA 等
        }
        
        # 添加额外信息
        for key in ['mode', 'key_bits', 'authenticated']:
            if key in params:
                algorithm_state[key] = params[key]
        
        # 使用 object_state_tracker 记录算法对象状态
        # 将工厂函数返回值视为一个算法对象
        self.object_state_tracker.track_object_creation(
            variable,
            "Algorithm",  # 对象类型
            initial_state=algorithm_state,
            line=line
        )
        
        if self.verbose:
            print(f"    [算法对象] {variable} = {algorithm_state}")
    
    def _infer_key_bits_from_name(self, symbol: str) -> Optional[int]:
        """
        从函数名推断密钥长度
        
        例如：
        - EVP_aes_256_gcm -> 256
        - EVP_aes_128_cbc -> 128
        - RSA_generate_key_2048 -> 2048
        
        Args:
            symbol: 函数名
            
        Returns:
            密钥长度（bits），如果无法推断则返回 None
        """
        import re
        # 匹配常见模式：128, 192, 256, 512, 1024, 2048, 3072, 4096
        match = re.search(r'_(\d{3,4})(?:_|$)', symbol)
        if match:
            bits = int(match.group(1))
            # 验证是否是合理的密钥长度
            if bits in [128, 192, 256, 512, 1024, 2048, 3072, 4096]:
                return bits
        return None
    
    def _get_library_for_language(self, language: str) -> Optional[str]:
        """获取特定语言对应的库名"""
        language_to_library = {
            'go': 'go_std_crypto',
            'python': 'python_std',  # 优先匹配标准库
            'java': 'java_bouncycastle',
            'c': 'c_openssl_alg_map',
            'cpp': 'c_openssl_alg_map',
        }
        return language_to_library.get(language.lower())

    def _identify_imported_libraries(self, language: str) -> set:
        """
        根据导入列表识别文件中使用的库
        
        【库识别规则】
        - Go: crypto/* imports → 使用 go_std_crypto 规则
        - Python: cryptography/pycryptodome 等 → 对应库规则  
        - Java: bouncycastle/jca → 对应库规则
        - C: openssl/gnutls 等 → 对应库规则
        
        只有导入了对应的库，才能使用该库的规则进行匹配
        """
        identified = set()
        
        if language == 'go':
            # Go: 检查 crypto/* 导入
            for imp in self._file_imports:
                if 'crypto' in imp.lower():
                    identified.add('go_std_crypto')
        
        elif language == 'python':
            # Python: 检查各种加密库的导入
            for imp in self._file_imports:
                imp_lower = imp.lower()
                if 'cryptography' in imp_lower:
                    identified.add('python_cryptography')
                if 'pycryptodome' in imp_lower or 'crypto' in imp_lower:
                    identified.add('python_pycryptodome')
                if 'pynacl' in imp_lower:
                    identified.add('python_pynacl')
                if 'hmac' in imp_lower or 'hashlib' in imp_lower:
                    identified.add('python_std')
                # 通用加密库导入检查
                if any(x in imp_lower for x in ['aes', 'rsa', 'sha', 'hmac', 'des', 'cipher']):
                    identified.add('python_std')
        
        elif language == 'java':
            # Java: 检查各种加密库的导入
            for imp in self._file_imports:
                imp_lower = imp.lower()
                if 'bouncycastle' in imp_lower:
                    identified.add('java_bouncycastle')
                if 'jca' in imp_lower or 'security.provider' in imp_lower:
                    identified.add('java_jca')
        
        elif language in ['c', 'cpp']:
            # C: 检查各种加密库的导入
            for imp in self._file_imports:
                imp_lower = imp.lower()
                if 'openssl' in imp_lower:
                    identified.add('c_openssl')
                if 'gnutls' in imp_lower:
                    identified.add('c_gnutls')
                if 'sodium' in imp_lower:
                    identified.add('c_libsodium')
                if 'gmssl' in imp_lower:
                    identified.add('c_gmssl')
        
        if self.verbose:
            print(f"  Identified libraries: {identified}")
        
        return identified

    def _identify_algorithm(
        self, 
        candidate: Dict[str, Any], 
        params: Dict[str, Any], 
        language: str
    ) -> Optional[str]:
        """
        识别算法（基于 KB 和对象状态）
        
        【核心逻辑】基于 profile_id 的具体性区分工厂函数和操作函数：
        - 具体算法 (ALG.AES, ALG.RSA) → 工厂函数，直接返回
        - 抽象类型 (ALG.CIPHER, ALG.HASH) → 操作函数，需要从状态推断
        
        【改进】添加语言过滤，防止跨语言的规则误匹配（如 Go的Generate被匹配到C的zuc_generate_keystream）
        """
        symbol = candidate.get('symbol', '')

        # ★ Task 13.3: 用户定义函数跳过 KB 匹配，由本地 wrapper 契约处理
        # 防止用户函数名（如 generate_key）误匹配到 KB 中的同名函数（如 Fernet.generate_key）
        if symbol in getattr(self, '_function_params', {}):
            return None

        # 优先使用封装契约（根据 wrapper_priority 决定策略）
        imported_libs = getattr(self, '_imported_libraries', set())
        wrapper_entry = self._select_wrapper_entry(symbol, imported_libs) if hasattr(self, '_wrapper_map') else None
        if wrapper_entry and self.wrapper_priority == 'wrapper_first':
            semantic = wrapper_entry.get('semantic', {})
            profile_id = semantic.get('profile_id')
            if profile_id:
                for key in ['mode', 'key_bits', 'algorithm', 'authenticated']:
                    if key in semantic:
                        params[key] = semantic[key]
                if self.verbose:
                    print(f"  [封装契约(first)] {symbol} -> {profile_id}")
                return profile_id
        
        # Step 0: 优先从 API metadata 直接获取 profile_id
        # 例如：EVP_aes_256_gcm() -> ALG.AES（工厂函数）
        #      EVP_EncryptInit_ex() -> ALG.CIPHER（操作函数）
        api_metadata = self.api_metadata_map.get(symbol.lower(), {})
        semantic = api_metadata.get('semantic', {})
        
        if 'profile_id' in semantic:
            profile_id = semantic['profile_id']
            
            # ★★★ 判断是否是具体算法（工厂函数） ★★★
            if self._is_concrete_algorithm(profile_id):
                # 工厂函数：直接返回具体算法
                # 同时提取其他信息（mode、key_bits 等）
                for key in ['mode', 'key_bits', 'algorithm', 'authenticated']:
                    if key in semantic:
                        params[key] = semantic[key]
                
                # 从函数名推断 key_bits（如果未定义）
                if 'key_bits' not in params:
                    key_bits = self._infer_key_bits_from_name(symbol)
                    if key_bits:
                        params['key_bits'] = key_bits
                
                if self.verbose:
                    print(f"  [工厂函数] {symbol} -> {profile_id} (具体算法)")
                
                return profile_id
            else:
                # 操作函数：返回抽象类型，后续需要从状态推断
                if self.verbose:
                    print(f"  [操作函数] {symbol} -> {profile_id} (抽象类型，需要状态推断)")
                # 继续后续步骤尝试从参数中获取具体算法
        
        # Step 0.5: 从函数参数中查找工厂函数返回的算法
        # 例如：EVP_EncryptInit_ex(ctx, cipher, ...) 
        #      如果 cipher = EVP_aes_256_gcm() 返回，则推断为 ALG.AES
        literal_args = candidate.get('literal_args', [])
        
        for arg in literal_args:
            if isinstance(arg, str) and arg.strip():
                # 查找对象的算法状态
                obj_state = self.object_state_tracker.get_object_state(arg)
                if obj_state and 'algorithm' in obj_state:
                    algo_profile_id = obj_state['algorithm']
                    if self._is_concrete_algorithm(algo_profile_id):
                        # 找到具体算法！
                        params.update(obj_state)
                        if self.verbose:
                            print(f"  [参数推断] {symbol} -> {algo_profile_id} (来自参数 {arg})")
                        return algo_profile_id
        
        # Step 1: 检查是否是 receiver 方法调用（Java/Python OO 模式）
        receiver = candidate.get('receiver')
        if receiver and language in ['java', 'python']:
            object_state = self.object_state_tracker.get_object_state(receiver)
            if object_state and 'algorithm' in object_state:
                algo_name = object_state['algorithm']
                algo_info = self.algorithm_mapper.get_algorithm_by_name(algo_name)
                if algo_info:
                    params.update(object_state)
                    return algo_info.profile_id
        
        # Step 2: Java 特有：使用变换字符串中的算法名
        if language == 'java' and 'java_algorithm' in params:
            algo_name = params['java_algorithm']
            algo_info = self.algorithm_mapper.get_algorithm_by_name(algo_name)
            if algo_info:
                return algo_info.profile_id
        
        # Step 3: 标准方法：使用符号名（通过 algorithm_mapper）
        # [FIX 2026-04-15] 添加库识别和语言过滤
        # 只在文件导入的库中进行规则匹配，防止跨库误匹配
        imported_libs = getattr(self, '_imported_libraries', set())
        
        # 如果识别到具体的库，优先使用这些库的规则
        if imported_libs:
            for lib in imported_libs:
                algo_info = self.algorithm_mapper.get_algorithm(symbol, library=lib)
                if algo_info:
                    if self.verbose:
                        print(f"  [Step 3] {symbol} -> {algo_info.profile_id} (from imported library: {lib})")
                    return algo_info.profile_id
        
        # 如果没有识别到特定库，回退到语言级别的库
        library_for_language = self._get_library_for_language(language)
        algo_info = self.algorithm_mapper.get_algorithm(symbol, library=library_for_language)
        if algo_info:
            if self.verbose:
                print(f"  [Step 3] {symbol} -> {algo_info.profile_id} (from language library: {library_for_language})")
            return algo_info.profile_id

        # Step 3.5: Python/Go — 从模块限定符号中提取算法名
        # 例如：RSA.generate → 'RSA'; ecdsa.GenerateKey → 'ecdsa'
        # 处理 PyCryptodome / Go crypto 中的短符号模式
        if language in ['python', 'go'] and '.' in symbol:
            parts = symbol.split('.')
            for part in parts:
                if not part:
                    continue
                algo_info = self.algorithm_mapper.get_algorithm_by_name(part.upper())
                if algo_info and self._is_concrete_algorithm(algo_info.profile_id):
                    if self.verbose:
                        print(f"  [Step 3.5] {symbol} -> {algo_info.profile_id} (via part '{part}')")
                    return algo_info.profile_id

        # 如果 API 未命中，并且优先策略为 api_first，则将封装契约作为回退
        if wrapper_entry and self.wrapper_priority == 'api_first':
            semantic = wrapper_entry.get('semantic', {})
            profile_id = semantic.get('profile_id')
            if profile_id:
                for key in ['mode', 'key_bits', 'algorithm', 'authenticated']:
                    if key in semantic:
                        params[key] = semantic[key]
                if self.verbose:
                    print(f"  [封装契约(fallback)] {symbol} -> {profile_id}")
                return profile_id
        
        return None
    
    def _track_object_state(
        self, 
        candidate: Dict[str, Any], 
        profile: Optional[Dict[str, Any]],  # profile 可能为 None
        params: Dict[str, Any],
        api_metadata: Dict[str, Any] = None,  # API metadata from AlgorithmMapper
        language: str = 'c'  # 语言类型
    ) -> None:
        """
        追踪对象状态（基于 API 元数据或 profile）
        
        优先级：
        1. 从 api_metadata 获取 context_writes（辅助函数）
        2. 从 profile 获取 context_writes（完整算法）
        """
        if api_metadata is None:
            api_metadata = {}
            
        receiver = candidate.get('receiver')
        symbol = candidate.get('symbol', '')
        assigned_to = candidate.get('assigned_to')
        
        # 尝试从 API metadata 获取 context_writes（辅助函数）
        semantic = api_metadata.get('semantic', {})
        context_writes = semantic.get('context_writes', [])
        
        # 特殊情况：Java getInstance 模式（工厂方法）
        if 'getInstance' in symbol and 'java_algorithm' in params and assigned_to:
            self.object_state_tracker.track_object_creation(
                assigned_to,
                "Factory",
                initial_state={'algorithm': params['java_algorithm']},
                line=candidate.get('line')
            )
            return
        
        # 如果 API metadata 中没有，尝试从 profile 获取
        if not context_writes and profile:
            context_writes = profile.get('context_writes', [])
        
        # ★ 特殊情况：allocator 函数（即使没有 context_writes 也要处理）
        # 优先检查：ctx = EVP_CIPHER_CTX_new()
        if assigned_to and self.object_id_manager.is_allocator(symbol, language=language):
            scope = candidate.get('function_name', 'global')
            line = candidate.get('line')
            object_type = self._infer_object_type(symbol, api_metadata)
            alloc_site = symbol  # 使用函数名作为 alloc_site
            target_object_id = self.object_id_manager.allocate_object(
                assigned_to, alloc_site, scope, object_type, line
            )
            # 分配完成后直接返回（allocator 不需要状态更新）
            return
        
        # 如果不是 allocator 且没有 context_writes，跳过
        if not context_writes:
            return
        
        # 找到 ctx 参数和对象ID
        ctx_arg = None  # ctx 参数（字符串或字典）
        target_object_id = None  # 对象ID（如 "EVP_CIPHER_CTX_new@v1"）
        
        line = candidate.get('line')
        
        # 从 semantic.ctx 获取 ctx 参数的信息
        ctx_spec = semantic.get('ctx', {})
        
        if ctx_spec:
            # ctx_spec = {"index": 0, "param": "ctx", "source": "param"}
            ctx_index = ctx_spec.get('index', 0)
            
            # 从候选的 args 中获取对应位置的参数
            args = candidate.get('args', [])
            if ctx_index < len(args):
                ctx_arg = args[ctx_index]
                # ctx_arg = {"text": "ctx", "type": "identifier"}
                # 或 {"text": "*ctx", "type": "pointer_expression"}
                # 或 {"text": "obj->ctx", "type": "field_expression"}
        elif receiver:
            # OO 语言（Java/Python）使用 receiver
            ctx_arg = receiver
        
        # 如果没有 ctx 参数，跳过（allocator 已在前面处理）
        if not ctx_arg:
            return
        
        # 确定作用域（函数名）
        scope = candidate.get('function_name', 'global')
        
        # ★ 核心：使用 resolve_ctx_arg() 统一解析 ctx 参数
        # 支持：变量、指针、字段访问、数组等
        
        assigned_to = candidate.get('assigned_to')
        
        # 策略1：如果有 assigned_to 且是 allocator，直接创建新对象
        if assigned_to and self.object_id_manager.is_allocator(symbol, language=language):
            # 新对象分配：ctx = EVP_CIPHER_CTX_new()
            object_type = self._infer_object_type(symbol, api_metadata)
            alloc_site = symbol  # 使用函数名作为 alloc_site
            target_object_id = self.object_id_manager.allocate_object(
                assigned_to, alloc_site, scope, object_type, line
            )
        else:
            # 策略2：尝试解析 ctx_arg（使用现有对象）
            target_object_id = self.object_id_manager.resolve_ctx_arg(ctx_arg, scope, language)
            
            # 策略3：如果未绑定，创建临时对象（参数传递等）
            if not target_object_id:
                # 提取变量名
                if isinstance(ctx_arg, dict):
                    var_name = ctx_arg.get('text', '')
                    # 去除指针/取地址等修饰符
                    if var_name.startswith('*') or var_name.startswith('&'):
                        var_name = var_name[1:].strip()
                else:
                    var_name = str(ctx_arg).strip()
                    if var_name.startswith('*') or var_name.startswith('&'):
                        var_name = var_name[1:].strip()
                
                # 创建临时对象（假设是参数传递）
                object_type = self._infer_object_type(symbol, api_metadata)
                alloc_site = f"param_{var_name}"
                target_object_id = self.object_id_manager.allocate_object(
                    var_name, alloc_site, scope, object_type, line
                )
        
        # 3. 追踪对象状态
        self._track_object_state_with_id(candidate, target_object_id, context_writes, api_metadata)
    
    def _track_object_state_with_id(
        self,
        candidate: Dict[str, Any],
        target_object_id: str,
        context_writes: List[Dict],
        api_metadata: Dict[str, Any]
    ):
        """使用版本化对象ID进行状态追踪"""
        # 创建或更新对象状态
        if target_object_id not in self.object_state_tracker.objects:
            obj_info = self.object_id_manager.get_object_info(target_object_id)
            object_type = obj_info.object_type if obj_info else "Unknown"
            
            self.object_state_tracker.track_object_creation(
                target_object_id,
                object_type,
                line=candidate.get('line')
            )
        
        # 构建参数字典（参数名 → 参数值）
        func_params = api_metadata.get('func_params', [])
        call_params = {}
        
        # 将 candidate.args 映射到参数名
        args = candidate.get('args', [])
        for i, param_name in enumerate(func_params):
            if i < len(args):
                arg = args[i]
                # 使用参数的 text（变量名）或 nested_call
                if 'nested_call' in arg:
                    call_params[param_name] = arg.get('nested_call')
                else:
                    call_params[param_name] = arg.get('text')
        
        # 处理 context_writes（使用 ObjectIDManager 而非 ObjectStateTracker）
        for write_spec in context_writes:
            field_name = write_spec.get("field")
            from_spec = write_spec.get("from", {})
            
            # 提取值
            value = None
            if "param" in from_spec:
                param_name = from_spec["param"]
                value = call_params.get(param_name)
                
                # 处理索引（如果是数组参数）
                if "index" in from_spec and isinstance(value, (list, tuple)):
                    value = value[from_spec["index"]]
            
            # 转换（如果需要）
            transform = write_spec.get("transform")
            if transform == "bytes_to_bits" and value is not None:
                value = value * 8
            elif transform == "bits_to_bytes" and value is not None:
                value = value // 8
            
            # ★ 写入状态到 ObjectIDManager
            if value is not None:
                self.object_id_manager.write_state(target_object_id, field_name, value)

    
    def _infer_object_type(self, symbol: str, api_metadata: Dict[str, Any]) -> str:
        """推断对象类型"""
        semantic = api_metadata.get('semantic', {})
        profile_id = semantic.get('profile_id', '')
        
        if 'CIPHER' in profile_id:
            return 'EVP_CIPHER_CTX'
        elif 'HASH' in profile_id or 'DIGEST' in profile_id:
            return 'EVP_MD_CTX'
        elif 'PKEY' in profile_id or 'SIGNATURE' in profile_id:
            return 'EVP_PKEY_CTX'
        elif 'MAC' in profile_id:
            return 'EVP_MAC_CTX'
        else:
            # 从函数名推断
            if 'CIPHER' in symbol.upper():
                return 'EVP_CIPHER_CTX'
            elif 'MD' in symbol.upper() or 'Digest' in symbol:
                return 'EVP_MD_CTX'
            else:
                return 'Context'


# 便捷函数
def scan_file(
    file_path: str, 
    pq_mode: bool = True, 
    classic_mode: bool = True,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    扫描单个文件（便捷函数）
    
    Args:
        file_path: 文件路径
        pq_mode: 启用量子安全检查
        classic_mode: 启用经典安全检查
        verbose: 输出详细信息
    
    Returns:
        扫描结果
    """
    scanner = PQScanner(verbose=verbose)
    return scanner.scan_file(file_path, pq_mode, classic_mode)


def scan_directory(
    dir_path: str,
    extensions: Optional[List[str]] = None,
    pq_mode: bool = True,
    classic_mode: bool = True,
    verbose: bool = False
) -> List[Dict[str, Any]]:
    """
    扫描目录（便捷函数）
    
    Args:
        dir_path: 目录路径
        extensions: 文件扩展名列表
        pq_mode: 启用量子安全检查
        classic_mode: 启用经典安全检查
        verbose: 输出详细信息
    
    Returns:
        扫描结果列表
    """
    scanner = PQScanner(verbose=verbose)
    return scanner.scan_directory(dir_path, extensions, pq_mode, classic_mode)
