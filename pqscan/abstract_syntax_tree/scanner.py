"""
AST 层统一扫描入口
职责：快速提取加密 API 调用候选集
"""

from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import re

from pqscan.analysis.candidate import Candidate, Location, Scope, CallContext, APIType
from pqscan.abstract_syntax_tree.parser import get_parser
# extract_features 在 __init__.py 中定义，导入时会有循环依赖
# 所以在函数内部导入


def _is_concrete_profile_id(profile_id: Any) -> bool:
    if not isinstance(profile_id, str):
        return False
    text = profile_id.upper()
    if text in {"ALG.CSPRNG", "PRIM.CSPRNG", "UTIL.RNGFACTORY"} or text.startswith("RNG."):
        return False
    return profile_id.startswith("ALG.") and not profile_id.startswith("UTIL.") and profile_id != "UNKNOWN"


def _normalize_c_include(value: Any) -> str:
    text = str(value or "").strip().strip("<>\"'")
    return text.replace("\\", "/").lower()


def _c_library_family(include_or_rule_import: Any) -> str:
    text = _normalize_c_include(include_or_rule_import)
    if not text:
        return ""
    if text.startswith("openssl/") or text.startswith("crypto/") or text in {"openssl", "libcrypto"}:
        return "openssl"
    if text.startswith("gmssl/") or text == "gmssl":
        return "gmssl"
    if text.startswith("gnutls/") or text == "gnutls.h":
        return "gnutls"
    if text == "sodium.h" or text.startswith("sodium/") or text.startswith("libsodium/"):
        return "libsodium"
    if text.startswith("hitls/") or text.startswith("openhitls/") or text.startswith("bsl/") or text.startswith("crypt_"):
        return "openhitls"
    if text.startswith("tongsuo/") or text == "tongsuo":
        return "tongsuo"
    return ""


def _c_library_family_from_symbol(symbol: Any) -> str:
    text = str(symbol or "").strip().upper()
    if not text:
        return ""
    if text.startswith((
        "EVP_", "RSA_", "DSA_", "DH_", "EC_", "ECDH_", "ECDSA_", "AES_",
        "DES_", "SHA", "MD5", "HMAC", "CMAC", "HKDF", "PKCS5_", "PKCS12_",
        "X509_", "PEM_", "BIO_", "BN_",
    )):
        return "openssl"
    if text.startswith(("GNUTLS_",)):
        return "gnutls"
    if text.startswith(("SODIUM_", "CRYPTO_", "RANDOMBYTES_")):
        return "libsodium"
    if text.startswith(("HITLS_", "CRYPT_", "BSL_")):
        return "openhitls"
    return ""


def _rule_def_for_scan(rule: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(rule, dict):
        return {}
    if rule.get("match") or rule.get("api"):
        return rule.get("match") or rule.get("api") or {}
    result: Dict[str, Any] = {}
    if "imports" in rule:
        result["imports"] = rule.get("imports") or []
    if "function" in rule:
        result["symbols"] = [rule.get("function")]
    return result


def _filter_c_rules_by_imports(rules: List[Dict[str, Any]], imports: List[str]) -> List[Dict[str, Any]]:
    active_families = {
        family
        for family in (_c_library_family(imp) for imp in imports or [])
        if family
    }
    if not active_families:
        return []

    filtered: List[Dict[str, Any]] = []
    for rule in rules or []:
        rd = _rule_def_for_scan(rule)
        rule_imports = rd.get("imports") or []
        rule_families = {
            family
            for family in (_c_library_family(imp) for imp in rule_imports)
            if family
        }
        if not rule_families:
            symbols = rd.get("symbols") or []
            rule_families = {
                family
                for family in (_c_library_family_from_symbol(symbol) for symbol in symbols)
                if family
            }
        if rule_families and rule_families.intersection(active_families):
            filtered.append(rule)
    return filtered


def _filter_c_rules_by_call_symbols(rules: List[Dict[str, Any]], api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    active_families = {
        family
        for call in api_calls or []
        for family in (
            _c_library_family_from_symbol(str(call.get("resolved_symbol") or call.get("symbol") or "")),
            _c_library_family_from_symbol(str(call.get("symbol") or "")),
        )
        if family
    }
    if not active_families:
        return []

    filtered: List[Dict[str, Any]] = []
    for rule in rules or []:
        rd = _rule_def_for_scan(rule)
        rule_imports = rd.get("imports") or []
        rule_families = {
            family
            for family in (_c_library_family(imp) for imp in rule_imports)
            if family
        }
        if not rule_families:
            symbols = rd.get("symbols") or []
            rule_families = {
                family
                for family in (_c_library_family_from_symbol(symbol) for symbol in symbols)
                if family
            }
        if rule_families and rule_families.intersection(active_families):
            filtered.append(rule)
    return filtered


def _wrapper_profile_maps(kb: Dict[str, Any]) -> List[Dict[str, Any]]:
    maps: List[Dict[str, Any]] = []
    for key in ("_local_wrapper_profiles", "_cross_file_wrapper_profiles", "wrapper_profiles"):
        value = kb.get(key, {}) if isinstance(kb, dict) else {}
        if isinstance(value, dict) and value:
            maps.append(value)
    return maps


def _normalize_func_tail(symbol: Any) -> str:
    text = str(symbol or "").strip()
    if "::" in text:
        text = text.split("::")[-1]
    if "." in text:
        text = text.split(".")[-1]
    return text


def _resolve_wrapper_profile(symbol: str, wrapper_maps: List[Dict[str, Any]]) -> Optional[str]:
    if not symbol:
        return None
    try:
        from pqscan.analysis.wrapper_summary import is_c_non_crypto_callsite_symbol
        if is_c_non_crypto_callsite_symbol(symbol):
            return None
    except Exception:
        pass
    tail = _normalize_func_tail(symbol)
    keys = [symbol, symbol.lower(), tail, tail.lower()]
    for mapping in wrapper_maps:
        for key in keys:
            value = mapping.get(key)
            if value:
                return value
    return None


def _is_random_only_rule(rule: Dict[str, Any]) -> bool:
    """Return True for standalone RNG/randomness APIs that should not be reported."""
    if not isinstance(rule, dict):
        return False
    semantic = rule.get("semantic", {}) if isinstance(rule.get("semantic", {}), dict) else {}
    profile_id = str(semantic.get("profile_id") or semantic.get("profile") or "").upper()
    if profile_id.startswith("RNG.") or profile_id in {"PRIM.CSPRNG", "UTIL.RNGFACTORY", "ALG.CSPRNG"}:
        return True
    operation = str(semantic.get("operation") or "").lower()
    if operation.startswith("random") or operation.startswith("rand_"):
        return True
    api_id = str(rule.get("api_id") or rule.get("id") or "").lower()
    return ".random" in api_id or ".rand" in api_id


def _select_best_rule_for_call(lang: str, call: Dict[str, Any], rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Choose the best-matching rule for a concrete call when multiple rules match.

    The Python KB contains repeated/overloaded APIs where the same symbol can map
    to multiple rules and the disambiguation must come from literals/arguments
    rather than symbol/import matching alone. When we cannot distinguish two
    competing concrete profiles, return None instead of guessing.
    """
    if not rules:
        return None
    if len(rules) == 1:
        return rules[0]

    args = call.get("args", []) or []
    arg_texts = []
    for arg in args:
        if isinstance(arg, dict):
            arg_texts.append(str(arg.get("text") or arg.get("value") or ""))
        else:
            arg_texts.append(str(arg))
    haystack = " ".join([
        str(call.get("symbol") or ""),
        str(call.get("code") or ""),
        *arg_texts,
    ]).lower()
    literal_tokens = set(
        token.lower()
        for token in re.findall(r"[a-z0-9_./-]+", haystack)
        if token
    )

    def _rule_score(rule: Dict[str, Any]) -> tuple[int, int, int]:
        score = 0
        semantic = rule.get("semantic", {}) if isinstance(rule.get("semantic", {}), dict) else {}
        profile_id = str(semantic.get("profile_id") or "").strip()
        rule_def = _rule_def_for_scan(rule)
        rule_literals = [str(item).strip().lower() for item in (rule_def.get("literals") or []) if str(item).strip()]
        for literal in rule_literals:
            if literal and (literal in haystack or literal in literal_tokens):
                score += 200

        for key in ("mode", "padding", "curve"):
            value = semantic.get(key)
            if isinstance(value, str):
                token = value.strip().lower()
                if token and (token in haystack or token in literal_tokens):
                    score += 80

        for key in ("padding_scheme", "kex_algorithm_obj", "hash_alg_obj"):
            value = semantic.get(key)
            if isinstance(value, dict):
                param = value.get("param")
                if isinstance(param, str):
                    score += 5

        for token in ("oaep", "pss", "pkcs1v15", "pkcs1_15", "ecdh", "mgf1", "gcm", "ccm", "ctr", "cbc", "ecb", "ocb"):
            if token in haystack:
                score += 20

        concrete_rank = 1 if profile_id.startswith("ALG.") and not profile_id.startswith(("UTIL.", "PRIM.", "RNG.")) else 0
        specificity = len(profile_id.split(".")) if profile_id else 0
        return (score, concrete_rank, specificity)

    scored = sorted(((_rule_score(rule), idx, rule) for idx, rule in enumerate(rules)), reverse=True)
    best_score, _, best_rule = scored[0]
    if len(scored) == 1:
        return best_rule

    second_score, _, second_rule = scored[1]
    best_pid = str((best_rule.get("semantic", {}) or {}).get("profile_id") or "")
    second_pid = str((second_rule.get("semantic", {}) or {}).get("profile_id") or "")
    if best_score == second_score and best_pid and second_pid and best_pid != second_pid:
        return None
    return best_rule


def scan_candidates(
    code: str,
    lang: str,
    kb: Dict[str, Any],
    file_path: Optional[str] = None
) -> List[Candidate]:
    """
    Phase 1: AST 快速候选提取
    
    Args:
        code: 源代码字符串
        lang: 语言类型 ('c', 'python', 'go', 'java')
        kb: 知识库（API 规则、策略）
        file_path: 文件路径（可选）
    
    Returns:
        候选列表 [Candidate(...), ...]
        
    职责：
        - 解析 AST
        - 识别加密 API 调用
        - 提取基本参数（字面量）
        - 构建候选对象
        
    不做：
        - 复杂数据流分析
        - 跨函数追踪
        - 参数精确推导（留给 symbolic 层）
    """
    kb = dict(kb or {})
    kb.setdefault("policy", {})
    kb.setdefault("merged_rules", [])

    # 1. 解析 AST
    parser = get_parser(lang)
    tree = parser.parse(code.encode('utf-8'))
    root = tree.root_node
    
    # 2. 提取 import / alias / attributes / API 调用
    from pqscan.abstract_syntax_tree.extractor import (
        extract_attributes,
        extract_calls,
        extract_imports_with_aliases,
    )
    from pqscan.loader import (
        find_rules_for_call,
        find_rules_for_call_precise_c,
        find_rules_for_call_precise_go,
        find_rules_for_call_precise_java,
        find_rules_for_call_precise_python,
    )

    imports, alias_map = extract_imports_with_aliases(root, code, lang)
    c_wrapper_maps: List[Dict[str, Any]] = []
    if lang == "c":
        c_direct_rules = _filter_c_rules_by_imports(kb.get("merged_rules", []), imports)
        c_wrapper_maps = _wrapper_profile_maps(kb)

    attributes = extract_attributes(root, code, lang="python", alias_map=alias_map)
    api_calls = extract_calls(root, code, lang, alias_map=alias_map, imports=imports)
    if lang == "c":
        if not c_direct_rules:
            c_direct_rules = _filter_c_rules_by_call_symbols(kb.get("merged_rules", []), api_calls)
        if not c_direct_rules and not c_wrapper_maps:
            return []
        # C/C++ rule matching is expensive and should be scoped to libraries that
        # are actually included by this translation unit or directly invoked by
        # native crypto symbols in the current file. Wrapper-derived candidates
        # are handled separately below.
        kb["merged_rules"] = c_direct_rules

    features_from_kb = (kb or {}).get('features', {}) if isinstance(kb, dict) else {}
    line_to_func: dict[int, str] = {}
    for func in features_from_kb.get('functions', []) or []:
        if not isinstance(func, dict):
            continue
        func_name = str(func.get('normalized_name') or func.get('name') or '').strip()
        start_line = int(func.get('start_line', 0) or 0)
        end_line = int(func.get('end_line', 0) or 0)
        if not func_name or not start_line or not end_line:
            continue
        for line_no in range(start_line, end_line + 1):
            line_to_func[line_no] = func_name

    for call in api_calls:
        if not isinstance(call, dict):
            continue
        owner = str(call.get('owner_function_normalized') or call.get('owner_function') or '').strip()
        if owner:
            continue
        line_no = int(call.get('line', 0) or 0)
        inferred_owner = line_to_func.get(line_no)
        if inferred_owner:
            call['owner_function'] = inferred_owner
            call['owner_function_normalized'] = inferred_owner
    
    debug_phase1 = False
    try:
        import os
        debug_phase1 = os.environ.get("PQSCAN_DEBUG_PHASE1", "").strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        debug_phase1 = False
    if debug_phase1:
        import sys
        sys.stderr.write(f"[DEBUG scanner] extract_calls returned {len(api_calls)} calls\n")
        sys.stderr.flush()
        if api_calls:
            for i, call in enumerate(api_calls[:3]):
                symbol = call.get('symbol', 'NO_SYMBOL')  # ★ 修复：使用'symbol'而非'name'
                line = call.get('line', 'NO_LINE')
                sys.stderr.write(f"  Call {i}: line={line} symbol={symbol}\n")
                sys.stderr.flush()
    
    features = {
        "imports": imports,
        "import_aliases": alias_map,
        "attributes": attributes,
    }

    precise_matchers: Dict[str, Callable[[Dict[str, Any], Dict[str, Any], Dict[str, Any]], List[Dict[str, Any]]]] = {
        "go": find_rules_for_call_precise_go,
        "python": find_rules_for_call_precise_python,
        "java": find_rules_for_call_precise_java,
        "c": find_rules_for_call_precise_c,
    }

    def _find_matching_rules(call: Dict[str, Any]) -> List[Dict[str, Any]]:
        if lang == "c" and c_wrapper_maps:
            wrapper_profile = _resolve_wrapper_profile(call.get("symbol", ""), c_wrapper_maps)
            if wrapper_profile:
                return [{
                    "rule_id": "PIPELINE.C.WRAPPER_DERIVED",
                    "semantic": {"profile_id": wrapper_profile},
                    "match": {"symbols": [call.get("symbol", "")]},
                }]

        matcher = precise_matchers.get(lang)
        if matcher is not None:
            try:
                rules = matcher(call, features, kb)
                if rules:
                    return [rule for rule in rules if not _is_random_only_rule(rule)]
            except Exception:
                # 精确匹配失败时，再回退到 legacy matcher，避免单个调用的结构异常拖垮整文件扫描。
                pass
        return [rule for rule in find_rules_for_call(call.get("symbol", ""), imports, kb) if not _is_random_only_rule(rule)]

    # 3. 构建候选集
    candidates = []

    def _build_java_value_maps() -> tuple[dict, dict]:
        """从 Java 的变量/字段赋值中构建可回代的表达式映射。"""
        local_map: dict = {}
        global_map: dict = {}
        if lang != 'java':
            return local_map, global_map

        features = (kb or {}).get('features', {}) if isinstance(kb, dict) else {}
        assignments = []
        for key in ('var_assignments', 'field_assignments'):
            value = features.get(key, [])
            if isinstance(value, list):
                assignments.extend(value)

        # Build same-file function metadata for interprocedural propagation.
        func_params: dict[str, list[str]] = {}
        func_params_lc: dict[str, list[str]] = {}
        func_name_map: dict[str, str] = {}
        for func in features.get('functions', []) or []:
            if not isinstance(func, dict):
                continue
            fname = str(func.get('name', '') or '').strip()
            if not fname:
                continue
            params = [str(p) for p in (func.get('params', []) or []) if str(p).strip()]
            func_params[fname] = params
            func_params_lc[fname.lower()] = params
            func_name_map[fname.lower()] = fname

        # Call-site param bindings: callee_fn -> {param_name: resolved_value}
        param_bindings: dict[str, dict[str, str]] = {}

        def _normalize_func_name(name: str) -> str:
            text = str(name or '').strip()
            if not text:
                return ''
            if '::' in text:
                text = text.split('::')[-1]
            if '.' in text:
                text = text.split('.')[-1]
            return text

        def _resolve_with_maps(expr_text: str, func_name: str, max_hops: int = 6) -> str:
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

            visited: set[tuple[str, str]] = set()

            def _inner(text: str, scope: str, hops: int) -> str:
                text = _strip_outer_parens((text or '').strip())
                if not text or hops <= 0:
                    return text

                key = (scope, text)
                if key in visited:
                    return text
                visited.add(key)

                if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
                    return text[1:-1]

                lowered = text.lower()
                if lowered.startswith('string.valueof(') and text.endswith(')'):
                    return _inner(text[text.find('(') + 1:-1], scope, hops - 1)
                if lowered.endswith('.tochararray()'):
                    return _inner(text[:text.rfind('.toCharArray()')], scope, hops - 1)

                local_value = local_map.get(scope, {}).get(text)
                if local_value is not None:
                    return _inner(str(local_value), scope, hops - 1)

                binding_value = param_bindings.get(scope, {}).get(text)
                if binding_value is not None:
                    return _inner(str(binding_value), scope, hops - 1)

                global_value = global_map.get(text)
                if global_value is None:
                    global_value = global_map.get(text.lower())
                if global_value is not None:
                    return _inner(str(global_value), scope, hops - 1)

                return text

            return _inner(expr, func_name, max_hops)

        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            func_name = str(assignment.get('function', 'global') or 'global')
            var_name = assignment.get('name') or assignment.get('field')
            value = assignment.get('expr_value', assignment.get('value'))
            if not var_name or value is None:
                continue
            local_map.setdefault(func_name, {})[str(var_name)] = str(value)
            global_map[str(var_name)] = str(value)

        # Resolve same-file calls into callee param bindings using the caller's scope.
        for call in features.get('calls', []) or []:
            if not isinstance(call, dict):
                continue

            callee_raw = str(call.get('symbol', '') or '').strip()
            callee = _normalize_func_name(callee_raw)
            if not callee:
                continue

            callee_key = callee.lower()
            target_func = func_name_map.get(callee_key)
            if not target_func:
                continue

            args = call.get('args', []) or []
            if not isinstance(args, list) or not args:
                continue

            caller_scope = str(
                call.get('owner_function_normalized')
                or call.get('owner_function')
                or ''
            ).strip()
            if not caller_scope:
                continue

            params = func_params.get(target_func) or func_params_lc.get(callee_key) or []
            if not params:
                continue

            bindings = param_bindings.setdefault(target_func, {})
            for idx, param_name in enumerate(params):
                if idx >= len(args):
                    break
                arg = args[idx]
                if not isinstance(arg, dict):
                    continue
                arg_text = arg.get('text') or arg.get('value')
                if arg_text is None:
                    continue
                resolved = _resolve_with_maps(str(arg_text), caller_scope)
                if resolved:
                    bindings[param_name] = resolved

        # Merge param bindings into the local map so downstream resolution can reuse them.
        for fname, binds in param_bindings.items():
            if not binds:
                continue
            local_map.setdefault(fname, {}).update(binds)
        return local_map, global_map

    def _build_python_value_maps() -> tuple[dict, dict, dict, dict]:
        """Build same-file Python variable/field expression maps for arg disambiguation."""
        local_map: dict = {}
        global_map: dict = {}
        local_history: dict = {}
        global_history: dict = {}
        if lang != 'python':
            return local_map, global_map, local_history, global_history

        features = (kb or {}).get('features', {}) if isinstance(kb, dict) else {}
        assignments = []
        for key in ('var_assignments', 'field_assignments'):
            value = features.get(key, [])
            if isinstance(value, list):
                assignments.extend(value)

        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            func_name = str(assignment.get('function', 'global') or 'global')
            var_name = assignment.get('name')
            if not var_name and assignment.get('object') and assignment.get('field'):
                var_name = f"{assignment.get('object')}.{assignment.get('field')}"
            value = assignment.get('value')
            if not var_name or value is None:
                continue
            local_map.setdefault(func_name, {})[str(var_name)] = str(value)
            global_map[str(var_name)] = str(value)
            line_no = int(assignment.get('line', 0) or 0)
            local_history.setdefault(func_name, {}).setdefault(str(var_name), []).append((line_no, str(value)))
            global_history.setdefault(str(var_name), []).append((line_no, str(value)))

        return local_map, global_map, local_history, global_history

    def _build_go_param_length_maps() -> dict[str, dict[str, int]]:
        """Extract fixed byte lengths from Go signatures such as `key *[32]byte`."""
        result: dict[str, dict[str, int]] = {}
        if lang != 'go':
            return result

        features = (kb or {}).get('features', {}) if isinstance(kb, dict) else {}
        for func in features.get('functions', []) or []:
            if not isinstance(func, dict):
                continue
            func_name = str(func.get('normalized_name') or func.get('name') or '').strip()
            src = str(func.get('src') or '')
            params = [str(p).strip() for p in (func.get('params', []) or []) if str(p).strip()]
            if not func_name or not src or not params:
                continue

            signature = src.split('{', 1)[0]
            lengths: dict[str, int] = {}
            for param in params:
                m = re.search(rf'\b{re.escape(param)}\s+\*?\[(\d+)\]byte\b', signature)
                if not m:
                    continue
                try:
                    lengths[param] = int(m.group(1))
                except ValueError:
                    continue
            if lengths:
                result[func_name] = lengths
        return result

    def _annotate_go_signature_arg_lengths(calls: List[Dict[str, Any]]) -> None:
        """Annotate Go call args with fixed byte lengths derived from function signatures."""
        if lang != 'go':
            return
        fixed_maps = _build_go_param_length_maps()
        if not fixed_maps:
            return

        for call in calls or []:
            if not isinstance(call, dict):
                continue
            func_name = str(
                call.get('owner_function_normalized')
                or call.get('owner_function')
                or call.get('function')
                or ''
            ).strip()
            if not func_name:
                continue
            param_lengths = fixed_maps.get(func_name, {})
            if not param_lengths:
                continue
            for arg in call.get('args', []) or []:
                if not isinstance(arg, dict) or isinstance(arg.get('length_bytes'), int):
                    continue
                arg_text = str(arg.get('text') or '').strip()
                if not arg_text:
                    continue
                base_name = ''
                m = re.fullmatch(r'([A-Za-z_]\w*)\s*\[\s*(?:.*?)\s*:\s*(?:.*?)\s*\]', arg_text)
                if m:
                    base_name = m.group(1)
                elif re.fullmatch(r'[A-Za-z_]\w*', arg_text):
                    base_name = arg_text
                if not base_name:
                    continue
                length_bytes = param_lengths.get(base_name)
                if isinstance(length_bytes, int):
                    arg['length_bytes'] = length_bytes
                    arg['length_source'] = 'go_signature_fixed_array_param'

    def _resolve_java_expr(expr_text: str, func_name: str, local_map: dict, global_map: dict) -> str:
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

        visited: set[str] = set()

        def _inner(text: str) -> str:
            text = _strip_outer_parens((text or '').strip())
            if not text:
                return text
            if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
                return text[1:-1]

            lowered = text.lower()
            if lowered.startswith('string.valueof(') and text.endswith(')'):
                return _inner(text[text.find('(') + 1:-1])
            if lowered.endswith('.tochararray()'):
                return _inner(text[:text.rfind('.toCharArray()')])

            if text.isidentifier() and text not in visited:
                visited.add(text)
                local_value = local_map.get(func_name, {}).get(text)
                if local_value is not None:
                    return _inner(str(local_value))
                global_value = global_map.get(text)
                if global_value is None:
                    global_value = global_map.get(text.lower())
                if global_value is not None:
                    return _inner(str(global_value))
            if '.' in text:
                tail = text.rsplit('.', 1)[-1].strip()
                if tail:
                    local_value = local_map.get(func_name, {}).get(tail)
                    if local_value is not None:
                        return _inner(str(local_value))
                    global_value = global_map.get(tail)
                    if global_value is None:
                        global_value = global_map.get(tail.lower())
                    if global_value is not None:
                        return _inner(str(global_value))
            return text

        return _inner(expr)

    def _infer_java_length_bytes(expr_text: str, func_name: str, local_map: dict, global_map: dict) -> Optional[int]:
        expr = (expr_text or '').strip()
        if not expr:
            return None

        def _strip_outer_parens(text: str) -> str:
            text = text.strip()
            while text.startswith('(') and text.endswith(')'):
                inner = text[1:-1].strip()
                if not inner:
                    break
                text = inner
            return text

        def _parse_java_string_literal(text: str) -> Optional[str]:
            text = str(text or '').strip()
            if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
                try:
                    import ast
                    value = ast.literal_eval(text)
                    if isinstance(value, str):
                        return value
                except Exception:
                    return text[1:-1]
            return None

        def _split_args(text: str) -> list[str]:
            args: list[str] = []
            current: list[str] = []
            depth = 0
            in_string = False
            quote = ''
            escaped = False
            for ch in str(text or ''):
                if in_string:
                    current.append(ch)
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == quote:
                        in_string = False
                    continue
                if ch in {'"', "'"}:
                    in_string = True
                    quote = ch
                    current.append(ch)
                    continue
                if ch in '([{':
                    depth += 1
                    current.append(ch)
                    continue
                if ch in ')]}':
                    depth = max(0, depth - 1)
                    current.append(ch)
                    continue
                if ch == ',' and depth == 0:
                    part = ''.join(current).strip()
                    if part:
                        args.append(part)
                    current = []
                    continue
                current.append(ch)
            part = ''.join(current).strip()
            if part:
                args.append(part)
            return args

        def _digest_bytes_from_algorithm(text: str) -> Optional[int]:
            token = str(text or '').strip().upper().replace('_', '-')
            if not token:
                return None
            digest_map = {
                'MD5': 16,
                'SHA1': 20,
                'SHA-1': 20,
                'SHA224': 28,
                'SHA-224': 28,
                'SHA256': 32,
                'SHA-256': 32,
                'SHA384': 48,
                'SHA-384': 48,
                'SHA512': 64,
                'SHA-512': 64,
            }
            return digest_map.get(token)

        visited: set[tuple[str, str]] = set()

        def _inner(text: str, hops: int = 8) -> Optional[int]:
            text = _strip_outer_parens((text or '').strip())
            if not text or hops <= 0:
                return None

            key = (func_name, text)
            if key in visited:
                return None
            visited.add(key)

            literal_value = _parse_java_string_literal(text)
            if literal_value is not None:
                try:
                    return len(literal_value.encode('utf-8'))
                except Exception:
                    return len(literal_value)

            resolved = _resolve_java_expr(text, func_name, local_map, global_map)
            if resolved and resolved != text:
                bits = _inner(resolved, hops - 1)
                if bits is not None:
                    return bits
                text = _strip_outer_parens(str(resolved).strip())

            m = re.fullmatch(r'(.+)\.getBytes\s*\([^)]*\)', text)
            if m:
                return _inner(m.group(1).strip(), hops - 1)

            m = re.fullmatch(r'new\s+SecretKeySpec\s*\((.+)\)', text, re.S)
            if m:
                args = _split_args(m.group(1))
                if args:
                    return _inner(args[0], hops - 1)

            m = re.fullmatch(r'(?:Arrays\.)?copyOf\s*\((.+)\)', text)
            if m:
                args = _split_args(m.group(1))
                if len(args) >= 2:
                    try:
                        return int(args[1], 0)
                    except Exception:
                        pass

            m = re.fullmatch(r'new\s+byte\s*\[\s*\]\s*\{(.+)\}', text, re.S)
            if m:
                items = _split_args(m.group(1))
                if items:
                    return len(items)

            m = re.fullmatch(r'([A-Za-z_]\w*)\.digest\s*\(\s*\)', text)
            if m:
                receiver = m.group(1)
                receiver_expr = local_map.get(func_name, {}).get(receiver)
                if receiver_expr is None:
                    receiver_expr = global_map.get(receiver) or global_map.get(receiver.lower())
                receiver_expr = str(receiver_expr or '').strip()
                dm = re.search(r'MessageDigest\.getInstance\s*\(\s*(".*?"|\'.*?\')\s*\)', receiver_expr)
                if dm:
                    alg_text = _parse_java_string_literal(dm.group(1))
                    digest_bytes = _digest_bytes_from_algorithm(alg_text or '')
                    if digest_bytes is not None:
                        return digest_bytes
                return None

            return None

        return _inner(expr)

    java_local_map, java_global_map = _build_java_value_maps()
    python_local_map, python_global_map, python_local_history, python_global_history = _build_python_value_maps()
    go_param_length_map = _build_go_param_length_maps()
    _annotate_go_signature_arg_lengths(api_calls)

    def _resolve_python_expr(expr_text: str, func_name: str, line_no: int = 0) -> str:
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

        visited: set[tuple[str, str]] = set()

        def _lookup_history(history: dict, key: str, line_value: int):
            entries = history.get(key, [])
            if not entries:
                return None
            best = None
            for entry_line, entry_value in entries:
                if line_value and entry_line and entry_line > line_value:
                    continue
                if best is None or entry_line >= best[0]:
                    best = (entry_line, entry_value)
            if best is not None:
                return best[1]
            return entries[-1][1]

        def _inner(text: str, scope: str, hops: int = 6) -> str:
            text = _strip_outer_parens((text or '').strip())
            if not text or hops <= 0:
                return text

            visit_key = (scope, text)
            if visit_key in visited:
                return text
            visited.add(visit_key)

            lowered = text.lower()
            if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
                return text[1:-1]
            if lowered.startswith('bytes(') and text.endswith(')'):
                return text
            if lowered.endswith('.encode()'):
                return _inner(text[:text.rfind('.encode()')], scope, hops - 1)

            local_value = _lookup_history(python_local_history.get(scope, {}), text, line_no)
            if local_value is None:
                local_value = python_local_map.get(scope, {}).get(text)
            if local_value is not None:
                return _inner(str(local_value), scope, hops - 1)

            global_value = _lookup_history(python_global_history, text, line_no)
            if global_value is None:
                global_value = python_global_map.get(text)
            if global_value is None:
                global_value = _lookup_history(python_global_history, text.lower(), line_no)
            if global_value is None:
                global_value = python_global_map.get(text.lower())
            if global_value is not None:
                return _inner(str(global_value), scope, hops - 1)

            return text

        return _inner(expr, str(func_name or 'global') or 'global')
    
    for call in api_calls:
        matched_rules = _find_matching_rules(call)
        if not matched_rules:
            continue

        # 创建候选对象
        location = Location(
            file=file_path or '<string>',
            line=call.get('line', 0),
            column=call.get('column', 0)
        )
        
        scope = Scope(
            function_name=call.get('owner_function_normalized') or call.get('owner_function') or call.get('function'),
            module_name=file_path
        )
        
        call_context = CallContext(
            call_expr=call.get('symbol', ''),  # ★ 修复：应该是'symbol'而不是'name'
            positional_args=[arg.get('text', '') if isinstance(arg, dict) else str(arg) 
                           for arg in call.get('args', [])],
            assigned_to=call.get('assigned_to')
        )
        
        # [Task 13.2.2] 提取literal_args：从args中提取字面量值
        literal_args = {}
        args_list = call.get('args', [])
        func_name = call.get('owner_function_normalized') or call.get('owner_function') or call.get('function', '')
        for idx, arg in enumerate(args_list):
            if isinstance(arg, dict):
                if isinstance(arg.get('length_bytes'), int):
                    literal_args[f'arg{idx}'] = int(arg['length_bytes'])
                    if isinstance(arg.get('length_source'), str) and arg.get('length_source').strip():
                        literal_args.setdefault('_arg_sources', {})[f'arg{idx}'] = arg.get('length_source').strip()
                    continue
                # 如果arg有'value'字段，表示已解析的字面量
                if 'value' in arg:
                    literal_args[f'arg{idx}'] = arg['value']
                # 如果arg有'text'字段但不是标识符，也提取
                elif 'text' in arg:
                    arg_text = arg['text']
                    if lang == 'java':
                        resolved = _resolve_java_expr(arg_text, func_name, java_local_map, java_global_map)
                        if resolved and resolved != arg_text:
                            literal_args[f'arg{idx}'] = resolved
                            length_bytes = _infer_java_length_bytes(str(resolved), func_name, java_local_map, java_global_map)
                            if isinstance(length_bytes, int):
                                arg['length_bytes'] = length_bytes
                                arg['length_source'] = 'java_expr_fixed_length'
                                literal_args[f'arg{idx}'] = length_bytes
                                literal_args.setdefault('_arg_sources', {})[f'arg{idx}'] = 'java_expr_fixed_length'
                            continue
                        length_bytes = _infer_java_length_bytes(arg_text, func_name, java_local_map, java_global_map)
                        if isinstance(length_bytes, int):
                            arg['length_bytes'] = length_bytes
                            arg['length_source'] = 'java_expr_fixed_length'
                            literal_args[f'arg{idx}'] = length_bytes
                            literal_args.setdefault('_arg_sources', {})[f'arg{idx}'] = 'java_expr_fixed_length'
                            continue
                    if lang == 'python':
                        if arg.get('type') == 'keyword_argument' and '=' in str(arg_text):
                            _kw_name, _kw_value = str(arg_text).split('=', 1)
                            resolved = _resolve_python_expr(_kw_value, func_name, int(call.get('line', 0) or 0))
                            if resolved and resolved != _kw_value:
                                literal_args[str(_kw_name).strip()] = resolved
                                literal_args[f'arg{idx}'] = resolved
                                continue
                        resolved = _resolve_python_expr(str(arg_text), func_name, int(call.get('line', 0) or 0))
                        if resolved and resolved != arg_text:
                            literal_args[f'arg{idx}'] = resolved
                            if arg.get('type') == 'keyword_argument' and isinstance(arg.get('name'), str):
                                literal_args[str(arg.get('name')).strip()] = resolved
                            continue
                    # 尝试解析为整数
                    try:
                        literal_args[f'arg{idx}'] = int(arg_text)
                    except ValueError:
                        if lang == 'go':
                            fixed_lengths = go_param_length_map.get(str(func_name or ''), {})
                            arg_text_str = str(arg_text or '').strip()
                            base_name = ''
                            m = re.fullmatch(r'([A-Za-z_]\w*)\s*\[\s*(?:.*?)\s*:\s*(?:.*?)\s*\]', arg_text_str)
                            if m:
                                base_name = m.group(1)
                            elif re.fullmatch(r'[A-Za-z_]\w*', arg_text_str):
                                base_name = arg_text_str
                            if base_name:
                                length_bytes = fixed_lengths.get(base_name)
                                if isinstance(length_bytes, int):
                                    arg['length_bytes'] = length_bytes
                                    arg['length_source'] = 'go_signature_fixed_array_param'
                                    literal_args[f'arg{idx}'] = length_bytes
                                    literal_args.setdefault('_arg_sources', {})[f'arg{idx}'] = 'go_signature_fixed_array_param'
                                    continue
                        # 保存为文本（可能是变量名）
                        literal_args[f'arg{idx}'] = arg_text
            elif isinstance(arg, (int, float)):
                # 直接是数值
                literal_args[f'arg{idx}'] = arg
            else:
                # 其他类型保存为字符串
                literal_args[f'arg{idx}'] = str(arg)
        
        selected_rule = _select_best_rule_for_call(lang, call, matched_rules)
        semantic = selected_rule.get("semantic", {}) if isinstance(selected_rule, dict) else {}
        profile_id = semantic.get("profile_id") if isinstance(semantic, dict) else None
        if lang in {"c", "cpp"} and not _is_concrete_profile_id(profile_id) and isinstance(semantic, dict):
            alg_source = semantic.get("algorithm_source")
            if isinstance(alg_source, dict):
                func_params = selected_rule.get("func_params", []) if isinstance(selected_rule, dict) else []
                alg_idx = None
                alg_param = alg_source.get("param")
                if alg_param in func_params:
                    alg_idx = func_params.index(alg_param)
                elif isinstance(alg_source.get("index"), int):
                    alg_idx = int(alg_source["index"])
                if isinstance(alg_idx, int) and 0 <= alg_idx < len(args_list):
                    arg = args_list[alg_idx]
                    if isinstance(arg, dict):
                        nested_symbol = str(
                            arg.get("nested_call")
                            or arg.get("function")
                            or arg.get("text")
                            or arg.get("value")
                            or ""
                        ).strip()
                        if nested_symbol.endswith(")") and "(" in nested_symbol:
                            nested_symbol = nested_symbol.split("(", 1)[0].strip()
                        if nested_symbol:
                            nested_rules = [
                                rule
                                for rule in find_rules_for_call(nested_symbol, imports, kb)
                                if not _is_random_only_rule(rule)
                            ]
                            for nested_rule in nested_rules:
                                nested_semantic = nested_rule.get("semantic", {}) if isinstance(nested_rule, dict) else {}
                                nested_profile = nested_semantic.get("profile_id") if isinstance(nested_semantic, dict) else None
                                if _is_concrete_profile_id(nested_profile):
                                    profile_id = nested_profile
                                    break
            if not _is_concrete_profile_id(profile_id):
                for arg in args_list:
                    if not isinstance(arg, dict):
                        continue
                    nested_symbol = str(
                        arg.get("nested_call")
                        or arg.get("function")
                        or arg.get("text")
                        or arg.get("value")
                        or ""
                    ).strip()
                    if nested_symbol.endswith(")") and "(" in nested_symbol:
                        nested_symbol = nested_symbol.split("(", 1)[0].strip()
                    if not nested_symbol:
                        continue
                    nested_rules = [
                        rule
                        for rule in find_rules_for_call(nested_symbol, imports, kb)
                        if not _is_random_only_rule(rule)
                    ]
                    for nested_rule in nested_rules:
                        nested_semantic = nested_rule.get("semantic", {}) if isinstance(nested_rule, dict) else {}
                        nested_profile = nested_semantic.get("profile_id") if isinstance(nested_semantic, dict) else None
                        if _is_concrete_profile_id(nested_profile):
                            profile_id = nested_profile
                            break
                    if _is_concrete_profile_id(profile_id):
                        break

        candidate = Candidate(
            location=location,
            symbol=call.get('symbol', ''),  # ★ 修复：应该是'symbol'而不是'name'
            api_type=APIType.UNKNOWN,
            language=lang,
            ast_node=call.get('_node'),
            scope=scope,
            call_context=call_context,
            literal_args=literal_args,  # [Task 13.2.2] 填充literal_args
            assigned_to=call.get('assigned_to'),  # ★ 新增：赋值目标
            confidence=1.0,
            profile_id=profile_id,
            matched_rules=list(matched_rules),
        )
        candidates.append(candidate)
    
    return candidates


def quick_scan(code: str, lang: str) -> List[Dict[str, Any]]:
    """
    极简扫描（不依赖 KB）
    用于快速预览或测试
    
    Returns:
        [{'line': 10, 'symbol': 'RSA_generate_key', ...}, ...]
    """
    # 延迟导入
    from pqscan.abstract_syntax_tree import extract_features
    features = extract_features(code, lang=lang)
    return features.get('api_calls', [])
