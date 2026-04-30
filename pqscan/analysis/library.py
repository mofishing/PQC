#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Library Call Analyzer - 加密库API调用检测与分析

设计原则：
1. **AST优先**: 优先使用AST解析和语义规则，正则仅作为快速兜底
2. **KB驱动**: 算法映射、安全策略等从KB规则动态加载，避免硬编码
3. **语义分析**: 通过semantic字段驱动推断，支持参数追踪和类型传播

核心流程：
1. **规则匹配**: 通过符号、导入、参数类型匹配KB规则
2. **算法解析**: 从semantic.algorithm_name配置提取算法（支持字符串参数、枚举常量等）
3. **密钥推断**: 调用keysize模块进行深度推断（变量追踪、数据流、曲线查找）
4. **安全评估**: 根据KB policy和profile评估安全等级

工具方法设计：
- _extract_string_param: AST优先提取参数，正则作为兜底
- _build_algorithm_mapper: 从KB动态构建映射表，避免硬编码
- _infer_keysize: 统一的密钥推断入口，条件判断基于semantic配置

多语言支持：Java, Python, Go, C/C++

@File    :   library.py
@Contact :   mypandamail@163.com  
@Author  :   mooo
@Version :   3.0
@Date    :   2026/1/9
"""

from typing import List, Dict, Any, Optional
import re
from .base import AnalyzerBase
from ..reporting.model import Finding
# from .keysize import infer_keysize_bits  # LEGACY: keysize module removed
# from .dataflow import create_dataflow_analyzer  # LEGACY: dataflow module removed
from ..knowledge import find_rules_for_call_precise_dispatch

# 正则：提取1-6位数字（用于识别密钥大小、迭代次数等常量）
# 示例: "AES-256-GCM" -> [256], "PBKDF2(10000)" -> [10000]
_NUM_RE = re.compile(r'\b(\d{1,6})\b')

class LibraryAnalyzer(AnalyzerBase):
    """
    加密库调用分析器
    
    分析流程：
    1. 规则匹配：find_rules_for_call_precise_dispatch
    2. 算法解析：从semantic配置提取算法信息
    3. 密钥推断：调用keysize模块深度分析
    4. 安全评估：根据profile和policy评估
    """
    
    def __init__(self, kb_bundle: Dict[str, Any]):
        """
        初始化分析器
        
        Args:
            kb_bundle: 知识库bundle（包含rules、profiles、algid_tables等）
        """
        super().__init__(kb_bundle)
        # 从KB动态构建算法映射表（避免硬编码）
        self._algorithm_mapper = self._build_algorithm_mapper()
    
    def _build_algorithm_mapper(self) -> Dict[str, str]:
        """
        从KB规则动态构建算法名称到profile_id的映射表
        
        设计思路：
        - 从common_profiles提取所有算法名称变体
        - 从api_mappings提取algorithm_name配置
        - 生成标准化映射（大写、去连字符/下划线）
        
        Returns:
            {标准化算法名: profile_id} 映射字典
        """
        mapper = {}
        
        if not self.kb:
            return mapper
        
        # 从common_profiles提取profile ID和别名
        common_profiles = self.kb.get("common_profiles", {})
        for profile in common_profiles.get("rules", []):
            profile_id = profile.get("id")
            if not profile_id:
                continue
            
            # 添加profile ID本身的映射
            # 例如: ALG.SHA256 -> ALG.SHA256
            algo_part = profile_id.replace("ALG.", "").replace(".", "")
            if algo_part:
                mapper[algo_part.upper()] = profile_id
            
            # 添加算法族名称
            # 例如: algorithm_family="SHA-256" -> ALG.SHA256
            algo_family = profile.get("algorithm_family", "")
            if algo_family:
                normalized = algo_family.upper().replace("-", "").replace("_", "").replace(" ", "")
                mapper[normalized] = profile_id
        
        # 从id_aliases提取别名映射
        id_aliases = common_profiles.get("id_aliases", {})
        for alias, target in id_aliases.items():
            alias_normalized = alias.replace("ALG.", "").replace(".", "").upper()
            if alias_normalized:
                mapper[alias_normalized] = target
        
        return mapper
    
    def analyze(self, code_path: str, code: str, features: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """
        分析代码中的加密库调用
        
        Args:
            code_path: 源文件路径
            code: 源代码内容
            features: 代码特征（calls, attributes, literals等）
            context: 额外上下文（语言、配置等）
            
        Returns:
            检测到的安全问题列表（Finding对象）
        """
        findings: List[Finding] = []
        calls = features.get("calls", [])
        attrs = features.get("attributes", []) or []
        global_int_hints = self._ints_from_literals(features.get("literals", []))
        lang = (features.get("lang") or (context or {}).get("lang") or "go").lower()
        
        # 将源代码存入features，供密钥大小推断时使用
        features['code'] = code
        
        # 保存features供参数评估使用
        self._current_features = features

        # 将属性访问转换为伪调用，统一处理流程
        # 例如：Go的crypto.SHA1 -> 转为调用形式
        sites = list(calls)
        for a in attrs:
            sites.append({
                "symbol": a.get("symbol"),
                "pkg": a.get("pkg"),
                "member": a.get("member"),
                "line": a.get("line"),
                "code": a.get("symbol") or "",
            })

        # 规则查询缓存（避免重复查询相同符号）
        _rules_cache = {}

        for call in calls:
            # 查找这个调用对应的 attribute 记录（如果有）
            fq_symbol = None
            for attr in attrs:
                if (attr.get("line") == call.get("line") and 
                    attr.get("symbol") == call.get("symbol") and
                    attr.get("member") == call.get("member")):
                    fq_symbol = attr.get("fq_symbol")
                    break

            key = (lang, call.get("symbol", ""), call.get("pkg"), call.get("member"))
            rules = _rules_cache.get(key)
            if rules is None:
                # 构造带 fq_symbol 的 call dict
                enhanced_call = dict(call)
                if fq_symbol:
                    enhanced_call["fq_symbol"] = fq_symbol
                rules = find_rules_for_call_precise_dispatch(lang, enhanced_call, features, self.kb)
                _rules_cache[key] = rules
            if not rules:
                continue

            symbol = call.get("symbol","")
            line = call.get("line",0)
            code_snippet = call.get("code","")
            
            # 过滤链式调用中的结果获取方法（如 .hexdigest(), .digest()）
            # 这些是获取加密结果的辅助方法，不是独立的加密API
            # 例如：hmac.new(...).hexdigest() 应该只报告 hmac.new，不报告 hexdigest
            # 注意：update/verify等是加密操作的一部分，应该保留
            result_getter_methods = {
                'hexdigest', 'digest', 'finalize', 'getvalue', 
                'tobytes', 'hex', 'bytes'
            }
            member = call.get("member", "")
            if member and member.lower() in result_getter_methods:
                # 检查pkg是否包含括号（说明是链式调用）
                pkg = call.get("pkg", "")
                if pkg and ("(" in pkg):
                    # 这是链式调用的末尾方法，跳过
                    # 例如：pkg="hmac.new(...)", member="hexdigest"
                    continue
            
            # 提取 literals
            literals = []
            if code_snippet:
                import re
                literals = re.findall(r'["\']([^"\']*)["\']', code_snippet)

            # 按规则 ID 分组以去重：同一行同一 rule_id 只保留一个（优先完全匹配的 literals）
            rule_by_id = {}
            for rule in rules:
                rule_id = rule.get("rule_id", "")
                if rule_id not in rule_by_id:
                    rule_by_id[rule_id] = rule
                else:
                    # 已有该 rule_id，比较 literals 匹配度
                    # 优先保留完全匹配的规则；如果都完全匹配或都不完全匹配，保留第一个
                    existing_literals = rule_by_id[rule_id].get("api", {}).get("literals", [])
                    current_literals = rule.get("api", {}).get("literals", [])
                    
                    # 检查是否完全匹配
                    existing_exact_match = any(lit in literals for lit in (existing_literals or []))
                    current_exact_match = any(lit in literals for lit in (current_literals or []))
                    
                    if current_exact_match and not existing_exact_match:
                        rule_by_id[rule_id] = rule
            
            for rule in rule_by_id.values():
                # 过滤辅助函数：跳过RNG/随机数生成器
                profile_id = rule.get("semantic", {}).get("profile_id", "")
                # 确保profile_id是字符串再调用startswith
                if isinstance(profile_id, str) and (
                    profile_id.startswith("RNG.") or 
                    profile_id.startswith("PRIM.CSPRNG") or
                    profile_id.startswith("UTIL.RNG")  # 包括UTIL.RNGFactory等
                ):
                    continue  # 跳过 os.urandom, secrets.token_bytes, SecureRandom.getInstance 等
                
                # 过滤单独的mode构造函数：modes.GCM, modes.CBC等
                # 它们的参数是IV/nonce而非密钥，不应独立报告keysize
                if symbol and ("modes." in symbol or ".modes." in symbol):
                    continue
                
                # 过滤仅构造对象不涉及密钥决策的操作
                # 重要：sign/verify/encrypt/decrypt应该报告（它们使用密钥）
                operation = rule.get("semantic", {}).get("operation", "")
                if operation in ("public_key_extract", "pub_from_priv", 
                                "public_from_numbers", "private_from_numbers"):
                    # public_key_extract: 从证书/文件提取公钥
                    # pub_from_priv: private_key.public_key()
                    # *_from_numbers: 从已知参数构造密钥对象
                    continue
                
                # 过滤签名算法配置对象（不是实际的签名操作）
                if symbol and any(x in symbol for x in ["ECDSA", "PSS", "PKCS1v15", "OAEP", "MGF1"]):
                    continue
                
                # 过滤Cipher构造函数（密钥在algorithm参数中）
                if symbol and symbol.endswith("Cipher") and "algorithm" not in symbol:
                    continue
                
                # 过滤流式数据处理操作（使用已有上下文）
                if operation in ("update", "finalize", "compare"):
                    continue
                
                # 过滤方法调用（encryptor.update等）
                if symbol and any(x in symbol for x in [".update", ".finalize", ".compare_digest"]):
                    continue
                
                evidence = self._evaluate_parameters(lang, call, code, rule, global_int_hints)
                f = self.make_finding(
                    file=code_path,
                    line=line,
                    symbol=symbol,
                    rule=rule,
                    layer="library",
                    category=rule.get("category", "unknown"),
                    evidence=evidence,
                    literals=literals
                )
                findings.append(f)
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 后处理：修复动态初始化API的UNKNOWN问题
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 问题：EVP_DigestInit_ex(ctx, NULL, ...) 这类API在调用时算法未知
        # 解决：从后续调用（如EVP_sha256()）反向传播算法信息
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        findings = self._propagate_context_info(findings, code)
        
        return findings

    def _evaluate_parameters(self, lang: str, call: Dict[str, Any], code: str, rule: Dict[str, Any], hints: List[int]) -> Dict[str, Any]:
        """
        评估加密API调用的参数和安全性
        
        核心流程：
        1. 算法识别：从semantic.algorithm_name配置提取算法（字符串参数/枚举常量）
        2. 密钥推断：调用keysize模块进行深度推断（AST+数据流分析）
        3. 安全评估：根据KB policy验证key_bits/mode/padding
        
        Args:
            lang: 编程语言（java/python/go/c）
            call: 函数调用信息（symbol、args、code等）
            code: 完整源代码
            rule: 匹配到的KB规则
            hints: 全局整数常量提示（兜底策略使用）
            
        Returns:
            evidence字典，包含：
            - semantic: 语义信息（profile_id、algorithm_name等）
            - details: 详细信息（key_bits、mode、padding等）
            - violation: 是否违反安全策略
        """
        params: Dict[str, Any] = rule.get("params", {}) or {}
        evidence: Dict[str, Any] = {"violation": False, "details": {}}
        call_code = call.get("code","")
        symbol = call.get("symbol", "")  # 添加symbol提取
        line = call.get("line", 0)        # 添加line提取
        
        # 复制semantic以避免修改原始rule
        semantic = rule.get("semantic", {})
        if semantic:
            api_id = rule.get("api_id") or rule.get("id")
            if api_id:
                semantic = dict(semantic)
                semantic["api_id"] = api_id
            evidence["semantic"] = semantic
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 0. OpenHiTLS CRYPT_EAL_PkeyNewCtx 算法识别
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        
        if symbol == "CRYPT_EAL_PkeyNewCtx":
            call_args = call.get("args", [])
            if call_args and len(call_args) > 0:
                # 获取第一个参数（算法类型常量）
                algo_param = call_args[0]
                algo_param_text = ""
                if isinstance(algo_param, dict):
                    algo_param_text = algo_param.get("text", "")
                elif isinstance(algo_param, str):
                    algo_param_text = algo_param
                
                # 从知识库的 CRYPT_PKEY_AlgId 表查找算法信息
                if algo_param_text and self.kb:
                    algid_tables = self.kb.get("algid_tables", {})
                    crypt_pkey_algid = algid_tables.get("CRYPT_PKEY_AlgId", {})
                    
                    if algo_param_text in crypt_pkey_algid:
                        algo_info = crypt_pkey_algid[algo_param_text]
                        profile_id = algo_info.get("profile_id")
                        
                        if profile_id:
                            # 设置 profile_id
                            if "semantic" not in evidence:
                                evidence["semantic"] = {}
                            evidence["semantic"]["profile_id"] = profile_id
                            evidence["details"]["algorithm"] = profile_id
                            evidence["details"]["algorithm_constant"] = algo_param_text
                            
                            # 尝试从 algid_table 获取 key_bits
                            key_bits_from_table = algo_info.get("key_bits")
                            
                            if key_bits_from_table:
                                # 固定大小算法：从表中直接获取 keysize
                                evidence["details"]["key_bits"] = key_bits_from_table
                                evidence["details"]["derived_from"] = f"{algo_param_text} (algid_table)"
                                evidence["details"]["source"] = "openhitls_algid_table"
                            else:
                                # 可变大小算法（RSA, ECDSA, DH等）
                                # 标记为需要从后续调用推断 keysize
                                evidence["details"]["derived_from"] = f"{algo_param_text} (requires parameter setup)"
                                evidence["details"]["source"] = "openhitls_algid_table"
                                # 不设置 key_bits，让后续的数据流分析或参数追踪来处理
        
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 1. 算法识别：从参数中提取算法名称
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        
        # 方式1: 字符串参数 (algorithm_name.from_param)
        # 适用：Java JCA的MessageDigest.getInstance("MD5")
        algorithm_name_info = semantic.get("algorithm_name", {}) if semantic else {}
        if isinstance(algorithm_name_info, dict) and "from_param" in algorithm_name_info:
            param_name = algorithm_name_info["from_param"]
            algo_string = self._extract_string_param(call, rule, param_name)
            
            if algo_string:
                # 特殊处理：签名/MAC算法字符串（如"SHA256withRSA"）
                # 这些API的keysize应该从密钥追溯，而不是从算法名推断
                operation = semantic.get("operation", "") if semantic else ""
                is_dynamic_key_operation = operation in (
                    "sign_init_dynamic", "verify_init_dynamic",
                    "mac_init_dynamic", "hmac_init_dynamic"
                )
                
                # 对于动态密钥操作，只保存算法字符串，不覆盖profile_id
                if is_dynamic_key_operation:
                    evidence["details"]["algorithm_string"] = algo_string
                    evidence["details"]["requires_key_tracing"] = True
                    # 不覆盖profile_id，保留UTIL.SignatureFactory等，让keysize推断去追溯密钥
                else:
                    # 非动态密钥操作：正常映射算法到profile
                    resolved_profile_id = self._map_algorithm_string_to_profile(algo_string, lang)
                    if resolved_profile_id:
                        # 更新semantic中的profile_id
                        if not semantic:
                            semantic = {}
                            evidence["semantic"] = semantic
                        semantic["profile_id"] = resolved_profile_id
                        evidence["details"]["algorithm"] = resolved_profile_id
                        evidence["details"]["algorithm_string"] = algo_string
                        evidence["details"]["algorithm_resolved"] = True
                        
                        # 从profile获取默认密钥大小（固定大小算法如PBE.MD5.DES=56位）
                        if "key_bits" not in evidence.get("details", {}):
                            profile = self._get_profile_by_id(resolved_profile_id)
                            if profile:
                                profile_params = profile.get("params", {})
                                if profile_params and "key_bits" in profile_params:
                                    evidence["details"]["key_bits"] = profile_params["key_bits"]
                                    evidence["details"]["derived_from"] = f"{algo_string} (profile default)"
                                    evidence["details"]["source"] = "profile_params"
                        
                        # 哈希函数特殊处理：自动补充输出长度作为安全长度
                        # 即使哈希函数没有"密钥"，也需要报告其输出长度作为安全强度指标
                        category = rule.get("category", "")
                        if category in ("hash", "xof", "digest") and "key_bits" not in evidence.get("details", {}):
                            from .crypto_constants import get_hash_output_bits
                            hash_bits = get_hash_output_bits(algo_string)
                            if hash_bits:
                                evidence["details"]["key_bits"] = hash_bits
                                evidence["details"]["derived_from"] = f"{algo_string} (hash output length)"
                                evidence["details"]["source"] = "hash_output_bits"
        
        # 方式2: 枚举常量 (algorithm_source.algid_table)
        # 适用：C/OpenHiTLS的HITLS_CIPHER_AES_256_GCM整数常量
        algorithm_source = semantic.get("algorithm_source", {}) if semantic else {}
        if isinstance(algorithm_source, dict) and algorithm_source.get("algid_table"):
            resolved_algo = self._resolve_algorithm_from_algid_table(
                call, code, rule, algorithm_source
            )
            if resolved_algo:
                evidence["details"]["algorithm_resolved"] = True
                evidence["details"]["algid_constant"] = resolved_algo.get("constant_name")
                
                if "profile_id" in resolved_algo:
                    # 确保 evidence["semantic"] 存在并且被正确更新
                    if "semantic" not in evidence:
                        evidence["semantic"] = {}
                    evidence["semantic"]["profile_id"] = resolved_algo["profile_id"]
                    # 同时设置 details.algorithm 以保持一致性
                    evidence["details"]["algorithm"] = resolved_algo["profile_id"]
                
                # 提取 key_bits：直接从 key_bits 字段，或从 curve_bits/group_bits 映射
                if "key_bits" in resolved_algo:
                    evidence["details"]["key_bits"] = resolved_algo["key_bits"]
                    evidence["details"]["derived_from"] = f"{resolved_algo.get('constant_name', 'algid')} (direct)"
                    evidence["details"]["source"] = "algid_table"
                elif "curve_bits" in resolved_algo:
                    # ECC 曲线：curve_bits 就是密钥大小
                    evidence["details"]["key_bits"] = resolved_algo["curve_bits"]
                    evidence["details"]["derived_from"] = f"{resolved_algo.get('constant_name', 'curve')} (curve_bits)"
                    evidence["details"]["source"] = "algid_table_curve"
                elif "group_bits" in resolved_algo:
                    # DH 组：group_bits 就是密钥大小
                    evidence["details"]["key_bits"] = resolved_algo["group_bits"]
                    evidence["details"]["derived_from"] = f"{resolved_algo.get('constant_name', 'group')} (group_bits)"
                    evidence["details"]["source"] = "algid_table_group"
                
                for key in ["cipher_family", "mode", "block_bits", "aead",
                           "pkey_family", "type", "crypto_class", "curve", "digest"]:
                    if key in resolved_algo:
                        evidence["details"][f"algid_{key}"] = resolved_algo[key]
        
        # 方式3: 参数常量 (key.param_constants)
        # 适用：EVP_PKEY_CTX_new_id(EVP_PKEY_RSA)等动态API
        # 只在方式2未设置 profile_id 时执行（避免覆盖正确的 profile_id）
        if semantic and "key" in semantic:
            key_semantic = semantic["key"]
            if isinstance(key_semantic, dict):
                param_constants_info = key_semantic.get("param_constants", {})
                if param_constants_info:
                    constants_type = param_constants_info.get("constants_type", "")
                    param_name = param_constants_info.get("param", "")
                    
                    call_args = call.get("args", [])
                    func_params = rule.get("func_params", [])
                    param_value = None
                    if func_params and param_name:
                        try:
                            param_index = func_params.index(param_name)
                            if param_index < len(call_args):
                                arg = call_args[param_index]
                                if isinstance(arg, dict):
                                    param_value = arg.get("text", "")
                                elif isinstance(arg, str):
                                    param_value = arg
                        except (ValueError, IndexError, AttributeError):
                            pass
                    
                    if param_value and constants_type:
                        algid_tables = self.kb.get("algid_tables", {})
                        algid_table = algid_tables.get(constants_type, {})
                        algo_info = algid_table.get(param_value, {})
                        if algo_info and "profile_id" in algo_info:
                            # 只在方式2（algorithm_source.algid_table）未设置 profile_id 时才设置
                            # 避免覆盖正确的 profile_id
                            if "semantic" not in evidence:
                                evidence["semantic"] = {}
                            if not evidence["semantic"].get("profile_id"):
                                evidence["semantic"]["profile_id"] = algo_info["profile_id"]
                            
                            # 但总是更新 details.algorithm（用于后续推断）
                            if not evidence["details"].get("algorithm"):
                                evidence["details"]["algorithm"] = algo_info["profile_id"]
                            
                            if "key_bits" in algo_info:
                                evidence["details"]["key_bits"] = algo_info["key_bits"]
                                evidence["details"]["derived_from"] = f"{param_value} (fixed)"
                                evidence["details"]["source"] = "algid_table"
        
        # 方式4: semantic直接定义 (固定大小算法)
        # 适用：SM2/X25519/Ed25519等固定密钥大小算法
        if semantic and "key_bits" in semantic and "key_bits" not in evidence.get("details", {}):
            evidence["details"]["key_bits"] = semantic["key_bits"]
            evidence["details"]["derived_from"] = f"{rule.get('function', 'API')} (fixed)"
            evidence["details"]["source"] = "semantic"

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 2. 密钥推断：调用keysize模块深度分析
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        
        keyinfo = None
        
        # 推断条件判断：
        # - 规则要求检查key_bits参数
        # - semantic包含size相关字段（digest_size/key_bits等）
        # - semantic包含密钥参数追溯标记（key/pubkey/privkey等）
        # - category是hash（哈希函数需要推断输出大小）
        category = rule.get("category", "")
        should_infer_keysize = (
            "key_bits" in params or
            "digest_size" in semantic or
            "key_bits" in semantic or
            "key_size" in semantic or
            "key" in semantic or
            "pubkey" in semantic or
            "privkey" in semantic or
            "hash" in semantic or
            "field_bits" in params or
            "scalar_bits" in params or
            "dk_length" in semantic or
            "output_length" in semantic or
            "key_bits_param" in semantic or
            "param_sizes" in semantic or
            "curve" in semantic or
            category == "hash" or
            category == "xof"
        )
        
        if should_infer_keysize:
            features = getattr(self, '_current_features', None) or self._features_stub(lang)
            enhanced_call = dict(call)
            
            if semantic:
                enhanced_call["semantic"] = semantic
                
            if params:
                enhanced_call["profile_params"] = params
            
            # 添加完整profile信息（用于XOF安全强度计算）
            profile_id = semantic.get("profile_id") if semantic else None
            if profile_id and self.kb:
                common_profiles_data = self.kb.get("common_profiles", {})
                profiles_list = common_profiles_data.get("rules", [])
                for profile in profiles_list:
                    if profile.get("id") == profile_id:
                        enhanced_call["profile_params"] = profile
                        break
            
            func_params = rule.get("func_params")
            if func_params:
                enhanced_call["func_params"] = func_params
                
            # 调用keysize模块（支持：常量追踪、变量追溯、参数传播等）
            keyinfo = infer_keysize_bits(lang, enhanced_call, code, features, kb_bundle=self.kb)
        
        # 处理推断结果
        if keyinfo and ("key_bits" in keyinfo):
            evidence["details"].update(keyinfo)
            
            # 确保algorithm字段存在
            if "algorithm" not in keyinfo and "profile_id" in keyinfo and keyinfo["profile_id"]:
                evidence["details"]["algorithm"] = keyinfo["profile_id"]
            
            # 从参数追踪获取的profile_id更新到semantic
            if "profile_id" in keyinfo and keyinfo["profile_id"]:
                if "semantic" not in evidence:
                    evidence["semantic"] = {}
                evidence["semantic"]["profile_id"] = keyinfo["profile_id"]
            
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            # 3. 安全评估：验证key_bits/mode/padding是否符合策略
            # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            
            # 验证密钥大小
            if "key_bits" in params:
                kb_cfg = params["key_bits"] or {}
                allow = set(kb_cfg.get("allow", []))
                disallow = set(kb_cfg.get("disallow", []))
                kb = keyinfo["key_bits"]
                
                if allow and kb not in allow:
                    evidence["violation"] = True
                    evidence["details"]["key_bits_policy"] = f"must be in {sorted(allow)}"
                elif disallow and kb in disallow:
                    evidence["violation"] = True
                    evidence["details"]["key_bits_policy"] = f"must NOT be in {sorted(disallow)}"
                    
            # 验证加密模式和填充方式
            self._check_mode_padding(call_code, params, evidence)
            return evidence

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # 兜底策略：简单整数提取（当keysize推断失败时）
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        local_ints = self._ints_from_text(call_code)
        all_ints = local_ints or hints
        if "key_bits" in params:
            kb_cfg = params["key_bits"] or {}
            key_bits = max(all_ints) if all_ints else None
            evidence["details"]["key_bits"] = key_bits
            allow = set(kb_cfg.get("allow", []))
            disallow = set(kb_cfg.get("disallow", []))
            if allow:
                if key_bits is None or key_bits not in allow:
                    evidence["violation"] = True
                    evidence["details"]["key_bits_policy"] = f"must be in {sorted(allow)}"
            elif disallow:
                if key_bits is not None and key_bits in disallow:
                    evidence["violation"] = True
                    evidence["details"]["key_bits_policy"] = f"must NOT be in {sorted(disallow)}"

        self._check_mode_padding(call_code, params, evidence)
        
        # 确保algorithm字段完整性
        if "algorithm" not in evidence.get("details", {}):
            profile_id = evidence.get("semantic", {}).get("profile_id")
            if profile_id:
                evidence["details"]["algorithm"] = profile_id
        
        return evidence

    def _check_mode_padding(self, line: str, params: Dict[str, Any], ev: Dict[str, Any]):
        """
        检查加密模式和填充方式是否符合安全策略
        
        识别内容：
        - 加密模式: ECB, GCM, CTR, CBC, CFB, OFB
        - 填充方式: OAEP, PSS, PKCS1V15, PKCS1
        
        Args:
            line: 代码行（函数调用字符串）
            params: 规则参数（包含mode/padding的allow/disallow配置）
            ev: evidence字典（结果写入此处）
        """
        line_lower = line.lower()
        
        # 检查加密模式
        if "mode" in params:
            cfg = params["mode"] or {}
            allow = {str(x).lower() for x in cfg.get("allow", [])}
            disallow = {str(x).lower() for x in cfg.get("disallow", [])}
            found = None
            # 按优先级顺序匹配（避免CBC误匹配为ECB）
            for token in ["ECB", "GCM", "CTR", "CBC", "CFB", "OFB"]:
                if token.lower() in line_lower:
                    found = token
                    break
            if found:
                ev["details"]["mode"] = found
            if allow and (not found or found.lower() not in allow):
                ev["violation"] = True
                ev["details"]["mode_policy"] = f"must be in {sorted(allow)}"
            elif disallow and found and (found.lower() in disallow):
                ev["violation"] = True
                ev["details"]["mode_policy"] = f"must NOT be in {sorted(disallow)}"

        # 检查填充方式（主要用于RSA）
        if "padding" in params:
            cfg = params["padding"] or {}
            allow = {str(x).lower() for x in cfg.get("allow", [])}
            disallow = {str(x).lower() for x in cfg.get("disallow", [])}
            found = None
            for token in ["oaep", "pss", "pkcs1v15", "pkcs1"]:
                if token in line_lower:
                    found = token.upper()
                    break
            if found:
                ev["details"]["padding"] = found
            if allow and (not found or found.lower() not in allow):
                ev["violation"] = True
                ev["details"]["padding_policy"] = f"must be in {sorted(allow)}"
            elif disallow and found and (found.lower() in disallow):
                ev["violation"] = True
                ev["details"]["padding_policy"] = f"must NOT be in {sorted(disallow)}"

    def _ints_from_text(self, text: str) -> List[int]:
        """
        从文本中提取所有整数（1-6位）
        
        使用正则 \\b(\\d{1,6})\\b 提取，用于密钥大小推断的兜底策略
        例如: "AES-256-GCM" -> [256]
        """
        return [int(x) for x in _NUM_RE.findall(text or "")]

    def _ints_from_literals(self, literals: List[Dict[str, Any]]) -> List[int]:
        """
        从字面量列表中提取所有整数
        
        用于全局常量提示（global_int_hints），辅助密钥大小推断
        """
        out: List[int] = []
        for lit in literals or []:
            try:
                out.extend(int(x) for x in _NUM_RE.findall(lit.get("value", "")))
            except Exception:
                pass
        return out

    def _features_stub(self, lang: str) -> Dict[str, Any]:
        return {"lang": lang}

    def _resolve_algorithm_from_algid_table(
        self,
        call: Dict[str, Any],
        code: str,
        rule: Dict[str, Any],
        algorithm_source: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        通用的 algid_table 查找机制
        
        支持使用枚举常量选择算法的工厂模式，如：
        - OpenHiTLS: CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES128_CBC)
        - 其他库的类似模式
        
        Args:
            call: 调用信息
            code: 完整代码
            rule: 匹配的规则
            algorithm_source: semantic.algorithm_source 配置
                {
                    "type": "param",
                    "param": "id",  # 参数名
                    "algid_enum": "CRYPT_CIPHER_AlgId",  # 枚举类型名（可选）
                    "algid_table": "CRYPT_CIPHER_AlgId"  # algid_tables 中的表名
                }
        
        Returns:
            解析到的算法信息字典，包含：
            - constant_name: 常量名称
            - profile_id: 算法 profile_id
            - 其他元数据（cipher_family, mode, key_bits等）
            如果未找到则返回 None
        """
        # 1. 提取需要查找的参数名
        param_name = algorithm_source.get("param")
        if not param_name:
            return None
        
        # 2. 获取 algid_table 名称
        algid_table_name = algorithm_source.get("algid_table")
        if not algid_table_name:
            return None
        
        # 3. 从 KB 获取 algid_tables
        if not self.kb:
            return None
        
        algid_tables = self.kb.get("algid_tables", {})
        if not algid_tables or algid_table_name not in algid_tables:
            return None
        
        algid_table = algid_tables[algid_table_name]
        
        # 4. 从 features 提取字面量常量
        features = getattr(self, '_current_features', None)
        if not features:
            return None
        
        literals = features.get("literals", [])
        call_line = call.get("line", 0)
        
        # 5. 查找匹配的常量
        # 优先查找同一行的常量，然后查找附近行的常量
        matched_constants = []
        
        for lit in literals:
            lit_value = lit.get("value", "")
            lit_line = lit.get("line", 0)
            
            # 检查常量是否在 algid_table 中
            if lit_value in algid_table:
                # 计算行号距离
                line_distance = abs(lit_line - call_line) if call_line and lit_line else 999
                matched_constants.append({
                    "constant_name": lit_value,
                    "line_distance": line_distance,
                    "algo_info": algid_table[lit_value]
                })
        
        # 6. 选择最近的匹配
        if not matched_constants:
            # 回退：尝试从代码文本中提取常量名
            call_code = call.get("code", "")
            for const_name in algid_table.keys():
                if const_name in call_code:
                    matched_constants.append({
                        "constant_name": const_name,
                        "line_distance": 0,
                        "algo_info": algid_table[const_name]
                    })
                    break
        
        if not matched_constants:
            return None
        
        # 选择距离最近的常量
        best_match = min(matched_constants, key=lambda x: x["line_distance"])
        
        # 7. 构建返回结果
        result = {
            "constant_name": best_match["constant_name"],
            **best_match["algo_info"]  # 展开所有算法元数据
        }
        
        return result
    
    def _extract_string_param(self, call: Dict[str, Any], rule: Dict[str, Any], param_name: str) -> Optional[str]:
        """
        从调用参数中提取字符串字面量（基于AST，语言无关）
        
        架构原则：
        1. 优先使用 arg['type'] 字段判断参数类型
        2. 对 string_literal 类型，直接提取 text 并移除引号
        3. 避免使用正则表达式
        
        适用于Java的MessageDigest.getInstance("MD5")等工厂方法
        
        Args:
            call: 调用信息
            rule: 规则信息
            param_name: 参数名称
        
        Returns:
            字符串字面量（去除引号），如 "MD5" -> MD5
        """
        # 方法1：从call.args提取（AST驱动）
        call_args = call.get("args", [])
        func_params = rule.get("func_params", [])
        
        if func_params and param_name in func_params:
            try:
                param_index = func_params.index(param_name)
                if param_index < len(call_args):
                    arg = call_args[param_index]
                    
                    # 优先处理dict类型的arg（包含type信息）
                    if isinstance(arg, dict):
                        arg_text = arg.get("text", "")
                        arg_type = arg.get("type", "")
                        
                        # 字符串字面量类型（语言无关）
                        # Java: string_literal
                        # Python: string
                        # C: string_literal
                        # Go: interpreted_string_literal
                        if arg_type in ("string_literal", "string", "interpreted_string_literal"):
                            # 移除引号（单引号或双引号）
                            return arg_text.strip('\'"')
                        
                        # Fallback: 如果type未识别但text看起来像字符串
                        if arg_text.startswith(('"', "'")):
                            return arg_text.strip('\'"')
                    
                    # 兼容旧格式：arg直接是字符串
                    elif isinstance(arg, str):
                        if arg.startswith(('"', "'")):
                            return arg.strip('\'"')
                        return arg
                        
            except (ValueError, IndexError, AttributeError):
                pass
        
        # 方法2：Fallback - 从call.code提取第一个参数
        # 注意：这是兜底方案，应该尽量使用方法1的AST信息
        call_args_fallback = call.get("args", [])
        if call_args_fallback and len(call_args_fallback) > 0:
            first_arg = call_args_fallback[0]
            if isinstance(first_arg, dict):
                text = first_arg.get("text", "")
                if text.startswith(('"', "'")):
                    return text.strip('\'"')
        
        return None
    
    def _map_algorithm_string_to_profile(self, algo_string: str, lang: str) -> Optional[str]:
        """
        将算法字符串映射到标准化的profile_id
        
        设计思路：
        - 使用初始化时从KB构建的动态映射表（self._algorithm_mapper）
        - 支持命名变体：连字符、下划线、大小写不敏感
        - 按长度降序匹配，优先匹配更具体的算法名
        
        示例：
        - "MD5" -> "ALG.MD5"
        - "SHA-256" -> "ALG.SHA256"
        - "PBEWithHmacSHA256AndAES_256" -> "ALG.PBE.HMACSHA256.AES256"
        
        Args:
            algo_string: 原始算法字符串
            lang: 编程语言（用于future扩展，当前未使用）
        
        Returns:
            标准化的profile_id，未找到则返回ALG.{ALGO}格式兜底
        """
        if not algo_string:
            return None
        
        # 标准化：移除连字符、下划线、空格，转大写
        algo_normalized = algo_string.upper().replace("-", "").replace("_", "").replace(" ", "")
        
        # 策略1: 直接匹配（最快，最准确）
        if algo_normalized in self._algorithm_mapper:
            return self._algorithm_mapper[algo_normalized]
        
        # 策略2: 模糊匹配（按key长度降序，避免误匹配）
        # 为什么按长度排序？
        # - 避免"SHA1"误匹配"PBEWITHHMACSHA256ANDAES_256"
        # - 优先匹配更具体的算法名
        sorted_keys = sorted(self._algorithm_mapper.keys(), key=len, reverse=True)
        for key in sorted_keys:
            if key in algo_normalized or algo_normalized in key:
                return self._algorithm_mapper[key]
        
        # 策略3: 兜底 - 返回标准化形式
        # 即使无法精确映射，也返回一个有效的标识符供后续处理
        return f"ALG.{algo_normalized}"
    
    def _get_profile_by_id(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """
        从common_profiles中查找指定profile_id的完整profile信息
        
        用于获取profile的params（如key_bits默认值）和其他元数据
        
        Args:
            profile_id: 标准化的profile ID（如"ALG.PBE.MD5.DES"）
            
        Returns:
            profile字典（包含id、category、params等），未找到则返回None
        """
        if not self.kb:
            return None
        
        common_profiles_data = self.kb.get("common_profiles", {})
        profiles_list = common_profiles_data.get("rules", [])
        for profile in profiles_list:
            if profile.get("id") == profile_id:
                return profile
        return None
    
    def _map_evp_digest_to_profile(self, evp_func_name: str) -> Optional[str]:
        """
        将EVP哈希函数名映射到profile_id
        
        适用于：EVP_sha256(), EVP_sha3_512(), EVP_blake2s256()等
        
        Args:
            evp_func_name: EVP函数名（如"EVP_sha256"）
        
        Returns:
            profile_id（如"ALG.SHA256"），未找到则返回None
        """
        # 鲁棒性检查：空值处理
        if not evp_func_name:
            return None
        
        # 移除EVP_前缀
        if evp_func_name.startswith("EVP_"):
            algo_part = evp_func_name[4:]  # 去掉"EVP_"
        else:
            algo_part = evp_func_name
        
        # 鲁棒性检查：EVP_前缀后为空
        if not algo_part:
            return None
        
        # 使用已有的算法映射器（支持SHA256/SHA3_256等）
        return self._map_algorithm_string_to_profile(algo_part, "c")
    
    def _propagate_context_info(self, findings: List[Finding], code: str) -> List[Finding]:
        """
        后处理：从后续调用向前传播算法信息，修复动态初始化API的UNKNOWN问题
        
        现在使用统一的DataFlowAnalyzer进行算法信息传播
        
        问题场景（C语言OpenSSL常见模式）：
        1. EVP_DigestInit_ex(ctx, NULL, ...) - 算法未知 (UNKNOWN)
        2. EVP_sha256() - 获取SHA256算法对象
        3. 上下文ctx使用该算法
        
        解决策略：
        - 使用统一的数据流分析器进行算法传播
        - 严格检测动态初始化API模式
        - 使用变量名/上下文名匹配确保传播准确性
        
        Args:
            findings: 初始检测结果列表
            code: 完整源代码（用于变量名提取）
            
        Returns:
            修复后的findings列表
        """
        if not findings:
            return findings
        
        # 动态初始化API类别映射
        DYNAMIC_INIT_CATEGORIES = {
            'EVP_DigestInit_ex': 'hash',
            'EVP_DigestSignInit': 'hash',
            'EVP_DigestVerifyInit': 'hash',
            'EVP_PKEY_CTX_new_id': 'pke',
            'CRYPT_EAL_PkeyNewCtx': 'pke',
        }
        
        # 按行号排序
        findings_sorted = sorted(findings, key=lambda f: f.line)
        
        # 遍历所有findings，查找需要传播信息的动态初始化API
        for i, finding in enumerate(findings_sorted):
            symbol = finding.symbol or ""
            
            # 检查是否是动态初始化API
            expected_category = None
            for api, category in DYNAMIC_INIT_CATEGORIES.items():
                if api in symbol:
                    expected_category = category
                    break
            
            if not expected_category:
                continue
            
            # 检查profile_id是否为动态类型或UNKNOWN
            profile_id = finding.evidence.get("semantic", {}).get("profile_id", "")
            current_keysize = finding.evidence.get("details", {}).get("key_bits")
            
            # 跳过条件：
            # 1. 已有明确的算法 profile_id 且 key_bits 也存在 → 完整信息，无需传播
            # 2. 是工具类 profile（UTIL./PRIM./RNG.）→ 不是算法，无需传播
            if profile_id and profile_id.startswith("ALG.") and not profile_id.startswith(("UTIL.", "PRIM.", "RNG.")):
                # 如果已有 profile_id 但没有 key_bits，仍然尝试传播 key_bits
                if current_keysize is not None:
                    continue  # 已有完整信息（profile + keysize），跳过传播
                # 否则继续传播以获取 key_bits
            
            # 特殊处理：OpenHiTLS 上下文参数传播（使用 AST + dataflow）
            # 场景：
            # CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
            # CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP256);  // 从这里获取 curve_bits
            # 或
            # CRYPT_EAL_PkeySetParam(ctx, CRYPT_PARAM_RSA_BITS, 2048);  // 从这里获取 key_bits
            if "CRYPT_EAL_PkeyNewCtx" in symbol and current_keysize is None:
                # 使用 dataflow 的 AST-based 上下文追踪
                features = getattr(self, '_current_features', {})
                if features:
                    analyzer = create_dataflow_analyzer(features, code)
                    
                    # 从 features.calls 中查找当前行的完整调用对象
                    ctx_call = None
                    for call in features.get("calls", []):
                        if call.get("line") == finding.line:
                            ctx_call = call
                            break
                    
                    if not ctx_call:
                        continue
                    
                    # 从 AST 节点中查找变量赋值信息
                    # 场景：Type *var = Function(...); 或 var = Function(...);
                    ctx_var = None
                    ast_node = ctx_call.get('_node')
                    if ast_node:
                        # code 是 str，需要转为 bytes 来使用 AST 的 byte offset
                        code_bytes = code.encode('utf-8') if isinstance(code, str) else code
                        
                        # AST 节点的父节点可能是赋值语句或声明
                        parent = ast_node.parent
                        if parent and parent.type == 'init_declarator':
                            # 声明初始化：Type *var = Function(...);
                            # 查找声明符（declarator）
                            for child in parent.children:
                                if child.type == 'pointer_declarator' or child.type == 'identifier':
                                    # 获取变量名
                                    if child.type == 'identifier':
                                        ctx_var = code_bytes[child.start_byte:child.end_byte].decode('utf-8')
                                    else:
                                        # pointer_declarator 包含 identifier 子节点
                                        for subchild in child.children:
                                            if subchild.type == 'identifier':
                                                ctx_var = code_bytes[subchild.start_byte:subchild.end_byte].decode('utf-8')
                                                break
                                    if ctx_var:
                                        break
                        elif parent and parent.type == 'assignment_expression':
                            # 赋值表达式：var = Function(...);
                            left_child = parent.children[0] if len(parent.children) > 0 else None
                            if left_child and left_child.type == 'identifier':
                                ctx_var = code_bytes[left_child.start_byte:left_child.end_byte].decode('utf-8')
                    
                    if not ctx_var:
                        continue
                    
                    # 使用提取的变量名查找后续调用
                    ctx_call_dict = {
                        "line": finding.line,
                        "code": ctx_call.get("code", ""),
                        "symbol": symbol,
                        "ctx_var": ctx_var  # 直接传递变量名
                    }
                    
                    # 查找对该上下文的后续参数设置调用
                    param_calls = analyzer.find_context_param_calls(
                        ctx_call_dict,
                        ["CRYPT_EAL_PkeySetParam", "CRYPT_EAL_PkeySetParaById"]
                    )
                    
                    for param_call in param_calls:
                        param_symbol = param_call.get("symbol", "")
                        
                        # 处理 CRYPT_EAL_PkeySetParam(ctx, CRYPT_PARAM_RSA_BITS, 2048)
                        if "CRYPT_EAL_PkeySetParam" in param_symbol:
                            args = param_call.get("args", [])
                            # 参数: [ctx, param_type, value]
                            if len(args) >= 3:
                                param_type = args[1]
                                param_value = args[2]
                                
                                # 检查是否是 RSA_BITS 参数
                                if isinstance(param_type, dict):
                                    param_type_text = param_type.get("text", "")
                                    if "CRYPT_PARAM_RSA_BITS" in param_type_text:
                                        # 提取第三个参数的整数值
                                        if isinstance(param_value, dict):
                                            value_text = param_value.get("text", "")
                                            try:
                                                bits = int(value_text)
                                                finding.evidence.setdefault("details", {})["key_bits"] = bits
                                                finding.evidence["details"]["derived_from"] = f"CRYPT_EAL_PkeySetParam line {param_call.get('line')}"
                                                finding.evidence["details"]["source"] = "openhitls_setparam"
                                                current_keysize = bits
                                                # 调试：验证设置成功
                                                print(f"[OpenHiTLS] Set key_bits={bits} for line {finding.line}, profile={finding.profile_id}")
                                                break
                                            except (ValueError, TypeError):
                                                pass
                        
                        # 处理 CRYPT_EAL_PkeySetParaById(ctx, CRYPT_ECC_NISTP256)
                        elif "CRYPT_EAL_PkeySetParaById" in param_symbol:
                            args = param_call.get("args", [])
                            # 参数: [ctx, para_id]
                            if len(args) >= 2:
                                para_id = args[1]
                                
                                # 提取 para_id 常量名
                                if isinstance(para_id, dict):
                                    para_const = para_id.get("text", "")
                                    
                                    # 从 KB 的 CRYPT_PKEY_ParaId 表查找
                                    if self.kb:
                                        algid_tables = self.kb.get("algid_tables", {})
                                        para_table = algid_tables.get("CRYPT_PKEY_ParaId", {})
                                        
                                        if para_const in para_table:
                                            para_info = para_table[para_const]
                                            # 优先使用 curve_bits，回退到 group_bits
                                            bits = para_info.get("curve_bits") or para_info.get("group_bits")
                                            
                                            if bits:
                                                finding.evidence.setdefault("details", {})["key_bits"] = bits
                                                finding.evidence["details"]["derived_from"] = f"{para_const} line {param_call.get('line')}"
                                                finding.evidence["details"]["source"] = "openhitls_paraid"
                                                current_keysize = bits
                                                break
            
            # 创建简化的call字典用于数据流分析
            call_dict = {
                "line": finding.line,
                "symbol": symbol,
                "code": finding.evidence.get("code", ""),
                "category": expected_category,
                "semantic": finding.evidence.get("semantic", {}),  # 包含当前的semantic信息
                "details": finding.evidence.get("details", {})     # 包含当前的details信息
            }
            
            # 构建features用于数据流分析（从findings提取calls）
            calls = []
            for f in findings_sorted:
                calls.append({
                    "line": f.line,
                    "symbol": f.symbol or "",
                    "code": f.evidence.get("code", ""),
                    "category": f.category or "",
                    "semantic": f.evidence.get("semantic", {}),
                    "details": f.evidence.get("details", {})
                })
            
            # 从当前features获取语言信息（在analyze()中保存）
            lang = self._current_features.get("lang", "go").lower()
            features = {
                "calls": calls,
                "lang": lang
            }
            
            # 使用数据流分析器传播算法信息
            analyzer = create_dataflow_analyzer(features, code)
            propagation_result = analyzer.propagate_algorithm_info(call_dict, expected_category)
            
            if propagation_result:
                next_profile, next_keysize = propagation_result
                finding.evidence.setdefault("semantic", {})["profile_id"] = next_profile
                finding.evidence.setdefault("details", {})["key_bits"] = next_keysize
                
                # 更新 profile_id (Finding 对象使用 profile_id 而不是 profile)
                if next_profile:
                    finding.profile_id = next_profile
            elif expected_category == "hash" and "EVP_DigestInit" in symbol:
                # 处理内联调用：EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL)
                # 优先使用AST提取的nested_call信息
                algo_func_name = None
                
                # 从_current_features中查找对应的call
                if hasattr(self, '_current_features'):
                    calls = self._current_features.get("calls", [])
                    for call in calls:
                        if call.get("line") == finding.line:
                            args = call.get("args", [])
                            # 查找第二个参数（算法参数，索引为1）
                            if len(args) > 1:
                                algo_arg = args[1]
                                if isinstance(algo_arg, dict):
                                    # AST已提取嵌套函数名
                                    algo_func_name = algo_arg.get("nested_call")
                                    if not algo_func_name:
                                        algo_func_name = algo_arg.get("function")  # 向后兼容
                            break
                
                # Fallback: 正则提取（仅在AST未提供信息时使用）
                if not algo_func_name:
                    call_code = finding.evidence.get("code", "")
                    if call_code:
                        import re
                        evp_matches = re.findall(r'\b(EVP_\w+)\s*\(', call_code)
                        for match in evp_matches:
                            if match != symbol.split('(')[0]:
                                algo_func_name = match
                                break
                
                # 映射EVP函数名到算法profile（无需查KB规则）
                # 例如：EVP_sha256() -> ALG.SHA256, EVP_sha3_256() -> ALG.SHA3_256
                if algo_func_name:
                    # 使用已有的算法映射器
                    profile_id = self._map_evp_digest_to_profile(algo_func_name)
                    if profile_id:
                        finding.evidence.setdefault("semantic", {})["profile_id"] = profile_id
                        # 从profile获取digest_size
                        profile = self._get_profile_by_id(profile_id)
                        if profile:
                            # 哈希算法的key_bits通常就是输出长度
                            algo_family = profile.get("algorithm_family", "")
                            if algo_family:
                                from .crypto_constants import get_hash_output_bits
                                digest_bits = get_hash_output_bits(algo_family)
                                if digest_bits:
                                    finding.evidence.setdefault("details", {})["key_bits"] = digest_bits
                        finding.profile_id = profile_id
        
        return findings_sorted
    
    def _get_code_line(self, code: str, line_num: int) -> Optional[str]:
        """
        从源代码中提取指定行的内容
        
        Args:
            code: 完整源代码
            line_num: 行号（1-based）
            
        Returns:
            该行的代码内容，如果行号超出范围返回None
        """
        if not code or line_num <= 0:
            return None
        
        lines = code.split('\n')
        if line_num > len(lines):
            return None
        
        return lines[line_num - 1]


