#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   __init__.py
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/18 16:46   1.1         knowledge interface (generalized dispatch + robust symbol/import collection)
"""

# pqscan/loader/__init__.py
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional

# 尝试导入新版加载器
try:
    from pqscan.loader.loader_v2 import (
        load_kb_v2,
        load_common_profiles,
        get_profile,
    )
    HAS_V2_LOADER = True
except ImportError:
    HAS_V2_LOADER = False

# 延迟导入旧版加载器
def _load_v1(kb_dir, language):
    from pqscan.loader.loader import load_all_kb
    return load_all_kb(kb_dir, language)

from pqscan.loader.matcher import (
    match_library_call,
    apply_policy_on_rule,
    match_wrapper_for_function,
    match_library_call_precise,
)

# 导出算法映射器
from pqscan.loader.algorithm_mapper import (
    AlgorithmMapper,
    AlgorithmInfo,
    get_algorithm,
    get_global_mapper,
)

def load_kb(kb_dir: Path, language: str = 'go', use_v2: bool = True) -> Dict[str, Any]:
    """
    统一的知识库加载接口
    
    Args:
        kb_dir: 知识库目录
        language: 语言（go/python/java/c）
        use_v2: 是否使用新版加载器（优先使用apis/目录）
    
    Returns:
        知识库bundle，包含merged_rules等
    """
    if use_v2 and HAS_V2_LOADER:
        # 尝试使用新版加载器
        try:
            kb_v2 = load_kb_v2(kb_dir, language)
            # 补充旧版兼容字段
            if 'wrapper_rules' not in kb_v2:
                kb_v2['wrapper_rules'] = []
            if 'llm' not in kb_v2:
                kb_v2['llm'] = {}
            if 'policy' not in kb_v2:
                kb_v2['policy'] = {}
            return kb_v2
        except (FileNotFoundError, KeyError) as e:
            print(f"Warning: V2 loader failed ({e}), fallback to V1")
    
    # 回退到旧版加载器
    return _load_v1(kb_dir, language)

# ------------------------------
# 通用工具（标准化 & 变体展开）
# ------------------------------
from .utils import _norm_mod, _endswith_or_eq, _last_seg, _last2_segs

def _explode_symbol_variants(sym: str) -> Set[str]:
    """
    将一个符号展开为多种变体，便于兜底匹配：
      - 原样：Crypto.Cipher.AES.new
      - 两段尾部：AES.new
      - 一段尾部：AES / new
    """
    if not sym:
        return set()
    sym = _norm_mod(sym)
    parts = sym.split(".")
    out = {sym}
    if len(parts) >= 2:
        out.add(".".join(parts[-2:]))  # AES.new
    if parts:
        out.add(parts[-1])             # new
    if len(parts) >= 1:
        out.add(parts[0])              # 顶层名（较激进，谨慎使用）
    return out

def _collect_observed_sets(features: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """
    收集"已观察到"的 import / symbol 名称集合（含多种变体）：
      - imports：原始导入、别名映射（key/val）、以及每个导入的末段（如 AES）
      - symbols：calls 和 attributes 的 symbol/fq_symbol，以及它们的变体
      - 额外：把 import_aliases 的别名（key）直接加入 symbols（典型场景：from X import AES）
    """
    have_imps: Set[str] = set()
    have_syms: Set[str] = set()

    imports = features.get("imports") or []
    alias_map: Dict[str, str] = features.get("import_aliases") or {}

    # 1) 导入：原始 + 别名 key/val
    for imp in imports:
        have_imps.add(_norm_mod(imp))
        # 把导入末段也记为一个"可能的类/模块名"，便于匹配规则 symbols:["AES"]
        tail = _last_seg(imp)
        if tail:
            have_syms.add(tail)

    for k, v in alias_map.items():
        have_imps.add(_norm_mod(k))
        have_imps.add(_norm_mod(v))
        # 别名本身常被当作"类/模块"名使用（如 AES），加入 symbols
        if k:
            have_syms.add(k)
        # 全名的末段也可能对匹配有用
        tail = _last_seg(v)
        if tail:
            have_syms.add(tail)

    # 2) 调用/属性：加入 symbol 与 fq_symbol 及其变体
    def _push_sym(container: Set[str], val: str):
        if val:
            for s in _explode_symbol_variants(val):
                container.add(s)

    for c in (features.get("calls") or []):
        for k in ("fq_symbol", "symbol"):
            v = c.get(k)
            if v:
                _push_sym(have_syms, v)

    for a in (features.get("attributes") or []):
        for k in ("fq_symbol", "symbol"):
            v = a.get(k)
            if v:
                _push_sym(have_syms, v)

    return have_imps, have_syms

def _check_package_consistency(call_symbol: str, rule_api_str: str, lang: str) -> bool:
    """
    检查调用符号和规则API的包名是否一致
    
    Args:
        call_symbol: 调用符号，如 "aes.NewCipher", "Cipher.getInstance"
        rule_api_str: 规则API字符串，如 "crypto/aes.NewCipher", "javax.crypto.Cipher.getInstance"
        lang: 编程语言
    
    Returns:
        True if package names are consistent, False otherwise
    """
    if lang == "go":
        # Go: call_symbol="aes.NewCipher", rule_api="crypto/aes.NewCipher"
        call_parts = call_symbol.split(".")
        if len(call_parts) >= 2:
            call_pkg = call_parts[0].lower()  # "aes"
            # 规则API必须包含相同的包名
            if call_pkg in rule_api_str.lower():
                return True
            return False
    elif lang == "java":
        # Java: call_symbol="Cipher.getInstance", rule_api="javax.crypto.Cipher.getInstance"
        call_parts = call_symbol.split(".")
        if len(call_parts) >= 2:
            call_class = call_parts[0].lower()  # "cipher"
            # 规则API必须包含相同的类名
            if call_class in rule_api_str.lower():
                return True
            return False
    return True  # 其他语言暂时放行

def _fallback_suffix_match_rules(lang: str, features: Dict[str, Any], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    have_imps, have_syms = _collect_observed_sets(features)
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    
    filtered_syms = list(have_syms)

    for r in (kb_bundle.get("merged_rules") or []):
        api = r.get("api") or {}
        if not api:
            continue

        req_imps = api.get("imports") or []
        req_syms = api.get("symbols") or []

        # imports 要求：全部满足
        if req_imps:
            ok = True
            for req in req_imps:
                if not any(_endswith_or_eq(h, req) for h in have_imps):
                    ok = False
                    break
            if not ok:
                continue

        # symbols 要求：全部满足（使用过滤后的符号列表）
        if req_syms:
            ok = True
            for req in req_syms:
                valid_match = False
                for h in filtered_syms:
                    if _endswith_or_eq(h, req):
                        # 过滤：检查包名一致性（Go/Java）
                        rule_api_strs = []
                        for api_entry in ([api] if isinstance(api, dict) else api if isinstance(api, list) else []):
                            if isinstance(api_entry, dict):
                                for v in api_entry.values():
                                    if isinstance(v, str):
                                        rule_api_strs.append(v)
                                    elif isinstance(v, list):
                                        rule_api_strs.extend([s for s in v if isinstance(s, str)])
                        
                        # 如果有API字符串，检查包名一致性
                        if rule_api_strs:
                            if any(_check_package_consistency(h, api_str, lang) for api_str in rule_api_strs):
                                valid_match = True
                                break
                        else:
                            # 没有API字符串时，至少匹配上了就认可
                            valid_match = True
                            break
                
                if not valid_match:
                    ok = False
                    break
            
            if not ok:
                continue

        rr = apply_policy_on_rule(r, kb_bundle.get("policy"))
        rid = rr.get("rule_id") or rr.get("id")
        if rid in seen:
            continue
        seen.add(rid)
        out.append(rr)
    return out

# ------------------------------
# KB 装载
# ------------------------------
def load_kb_and_policy(kb_dir: Path, language: str = None, use_v2: bool = True) -> Dict[str, Any]:
    """
    一次性加载全部 KB（common + language + policy）
    
    Args:
        kb_dir: 知识库目录
        language: 语言（go/python/java/c）
        use_v2: 是否优先使用新版加载器（apis/目录）
    """
    return load_kb(kb_dir, language, use_v2=use_v2)

def find_rules_for_call(symbol: str, imports: List[str], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """根据符号名和导入包在知识库中查找匹配规则（legacy）"""
    rules = match_library_call(symbol, imports, kb_bundle["merged_rules"])
    return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]

# ------------------------------
# 精确匹配（语言无关 + 语言专属）
# ------------------------------
def find_rules_for_call_precise_go(call: Dict[str, Any], features: Dict[str, Any], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    pkg_alias = call.get("pkg")
    member    = call.get("member")
    pkg_full  = call.get("pkg_full")  # [FIX Phase 19] 获取完整包路径
    alias_map = features.get("import_aliases", {}) or {}
    imports   = features.get("imports", []) or []
    rules = match_library_call_precise(
        pkg_alias=pkg_alias,
        member=member,
        pkg_full=pkg_full,  # [FIX Phase 19] 传递pkg_full
        import_aliases=alias_map,
        imports=imports,
        merged_rules=kb_bundle["merged_rules"],
    )
    return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]

def _split_mod_alias(pkg_alias: str, import_aliases: Dict[str, str]) -> Tuple[str, str]:
    """
    将 pkg_alias 拆解为 (candidate_alias, candidate_fq_module)
    - 如果 pkg_alias 本身是别名（在 alias_map 的 key 中），则：
        alias = pkg_alias, fq = alias_map[alias]
    - 否则：尝试把 pkg_alias 当作 FQ 模块名，并取末段作为 alias 候选
    """
    alias = None
    fq = None
    if pkg_alias in import_aliases:
        alias = pkg_alias
        fq = import_aliases.get(pkg_alias)
    else:
        # pkg_alias 可能就是 FQ 模块名
        fq = _norm_mod(pkg_alias) if pkg_alias else None
        alias = _last_seg(fq) if fq else None
    return alias, fq

def match_and_apply_precise(pkg_alias: str, member: str, import_aliases: Dict[str, str],
                            imports: List[str], kb_bundle: Dict[str, Any], 
                            code_snippet: str = None, call: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """
    精确匹配规则（支持 alias 展开 + literals 检查）
    
    Args:
        pkg_alias: 包别名或包名
        member: 成员/方法名
        import_aliases: import 别名映射
        imports: 文件导入列表
        kb_bundle: 知识库数据
        code_snippet: 代码片段（可选，用于 literals 检查）
        call: 原始调用信息（可选，用于提取 code 和 literals）
    """
    alias, fq = _split_mod_alias(pkg_alias, import_aliases)

    # 从 call 中提取代码片段和字面量
    code = code_snippet or (call.get("code") if call else None)
    literals = None
    if call and call.get("code"):
        # 从代码片段中抽取所有字符串字面量
        code = call.get("code", "")
        import re
        # 匹配双引号或单引号中的内容
        literals = re.findall(r'["\']([^"\']*)["\']', code)

    def _try(pkg_like: str, mem_like: str) -> List[Dict[str, Any]]:
        rules = match_library_call_precise(
            pkg_alias=pkg_like,
            member=mem_like,
            import_aliases=import_aliases or {},
            imports=imports or [],
            merged_rules=kb_bundle["merged_rules"],
            code_snippet=code,
            literals=literals
        )
        return [apply_policy_on_rule(r, kb_bundle.get("policy")) for r in rules]

    # 尝试组合：alias/fq 与 member 的不同形式
    candidates: List[Tuple[str, str]] = []
    for p in filter(None, {pkg_alias, alias, fq}):
        for m in filter(None, {member}):
            candidates.append((p, m))
        # 常见“类.工厂方法”/“模块.函数”混用的健壮性补充
        # 例如：AES.new / new / AES / AES.new
        for m in ("new", "AES", "AES.new"):
            candidates.append((p, m))

    seen: Set[Tuple[str, str]] = set()
    for p, m in candidates:
        k = (_norm_mod(p), m)
        if k in seen:
            continue
        seen.add(k)
        rules = _try(p, m)
        if rules:
            return rules
    return []

def find_rules_for_call_precise_python(call: Dict[str, Any], features: Dict[str, Any], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    [Phase 19 AST] Python：基于AST的精确包匹配
    优先使用pkg_full（从alias_map解析的完整包路径）进行精确匹配
    回退策略:
      - 使用 attributes 中的 fq_symbol
      - 从 symbol 文本回推 (pkg, member)
      - legacy匹配
    """
    from pqscan.loader.matcher import match_library_call_precise
    
    alias_map = features.get("import_aliases") or {}
    imports   = features.get("imports") or []
    attrs     = features.get("attributes") or []
    symbol    = call.get("symbol") or ""
    pkg       = call.get("pkg")
    pkg_full  = call.get("pkg_full")  # [FIX Phase 19] 获取完整包路径
    pkg_full_candidates = call.get("pkg_full_candidates") or []
    member    = call.get("member")
    line      = call.get("line")
    resolved_symbol = call.get("resolved_symbol") or ""
    resolved_member = call.get("resolved_member") or ""
    non_crypto_terminals = {
        "encode", "decode", "digest", "hexdigest", "hex",
        "str", "bytes", "bytearray", "join", "get", "keys", "values", "items",
        "append", "extend", "replace", "split", "strip", "lstrip", "rstrip",
        "lower", "upper", "capitalize", "format", "startswith", "endswith",
        "read", "write", "open", "close", "dump", "dumps", "load", "loads",
        "force_str", "value_to_string", "to_string", "as_string",
    }
    generic_namespaces = {
        "objects", "flags", "headers", "meta", "data", "attrs", "params",
        "kwargs", "config", "settings", "options",
    }

    def _looks_like_crypto_name(text: str) -> bool:
        compact = re.sub(r"[^a-z0-9]+", "", str(text or "").lower())
        if not compact:
            return False
        return any(token in compact for token in (
            "aes", "des", "rsa", "dsa", "dh", "ecdh", "ecdsa", "ed25519", "ed448",
            "x25519", "x448", "curve25519", "mlkem", "mldsa", "dilithium", "kyber",
            "falcon", "sphincs", "hmac", "cmac", "hkdf", "pbkdf", "pbkdf2", "scrypt",
            "bcrypt", "argon", "sha", "shake", "md5", "sha1", "sha2", "sha3",
            "chacha", "poly1305", "salsa20", "secretbox", "box", "cipher", "mac",
            "digest", "hash", "encrypt", "decrypt", "sign", "verify", "wrap",
            "unwrap", "oaep", "pss", "gcm", "cbc", "ctr", "ecb", "x509", "cert",
            "privatekey", "publickey", "keypair", "keygen", "nonce", "iv",
        ))

    def _terminal_name(text: str) -> str:
        value = str(text or "").strip()
        if not value:
            return ""
        if "." in value:
            value = value.rsplit(".", 1)[-1]
        return value.strip()

    def _apply_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]

    def _try_precise(pkg_alias: str, member_name: str, pkg_full_name: str | None) -> List[Dict[str, Any]]:
        if not member_name:
            return []
        rules = match_library_call_precise(
            pkg_alias=pkg_alias,
            member=member_name,
            pkg_full=pkg_full_name,
            import_aliases=alias_map,
            imports=imports,
            merged_rules=kb_bundle["merged_rules"],
        )
        if rules:
            return _apply_rules(rules)
        ctor_rules = match_library_call_precise(
            pkg_alias=pkg_alias,
            member=f"{member_name}.__init__",
            pkg_full=pkg_full_name,
            import_aliases=alias_map,
            imports=imports,
            merged_rules=kb_bundle["merged_rules"],
        )
        if ctor_rules:
            return _apply_rules(ctor_rules)
        return []

    terminal = (
        _terminal_name(resolved_member)
        or _terminal_name(member)
        or _terminal_name(symbol)
    ).lower()
    full_text = str(resolved_symbol or symbol or "").strip()
    parts = [part.strip().lower() for part in full_text.split(".") if part.strip()]
    if terminal in non_crypto_terminals and not _looks_like_crypto_name(full_text):
        return []
    if parts and parts[-1] in non_crypto_terminals and not _looks_like_crypto_name(full_text):
        return []
    if len(parts) >= 2 and parts[-1] in {"get", "join"} and any(part in generic_namespaces for part in parts[:-1]):
        return []
    if ")." in full_text and terminal not in {
        "new",
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "update",
        "final",
        "finalize",
        "dofinal",
    } and not _looks_like_crypto_name(full_text):
        return []

    # 1) [Phase 19] 优先使用AST提取的pkg/pkg_full进行精确匹配
    if pkg or member:
        rules = _try_precise(pkg, member, pkg_full)
        if rules:
            return rules
        for candidate_pkg_full in pkg_full_candidates:
            rules = _try_precise(pkg, member, candidate_pkg_full)
            if rules:
                return rules

    # 1.5) Prefer the extractor's resolved symbol when available. This helps
    # Python imports such as "from ... import padding" where the KB stores a
    # relative module path and the AST stores the fully-qualified path.
    if resolved_symbol and "." in resolved_symbol:
        p, m = resolved_symbol.rsplit(".", 1)
        rules = _try_precise(p, resolved_member or m, p)
        if rules:
            return rules

    # 2) attributes：与当前调用同行的 fq 符号
    for a in attrs:
        try:
            if a.get("line") == line and a.get("fq_symbol"):
                fq_sym = _norm_mod(a["fq_symbol"])               # e.g. Crypto.Cipher.AES.new
                if "." in fq_sym:
                    p, m = fq_sym.rsplit(".", 1)
                    rules = _try_precise(p, m, p)
                    if rules:
                        return rules
        except Exception:
            pass

    # 3) 从 symbol 文本回推 (pkg, member)
    if symbol and "." in symbol:
        p, m = symbol.rsplit(".", 1)                             # e.g. ("AES","new")
        rules = _try_precise(p, m, None)
        if rules:
            return rules

    # 4) 回退：legacy
    return find_rules_for_call(symbol, imports, kb_bundle)

def find_rules_for_call_precise_java(call: Dict[str, Any], features: Dict[str, Any], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    [Phase 19 AST] Java：基于AST的精确包匹配
    优先使用pkg_full进行精确匹配，支持静态方法调用（如KeyGenerator.getInstance）
    """
    from pqscan.loader.matcher import match_library_call_precise
    
    symbol = call.get("symbol") or ""
    alias_map = features.get("import_aliases") or {}
    imports = features.get("imports") or []
    pkg = call.get("pkg")
    pkg_full = call.get("pkg_full")  # [FIX Phase 19] 获取完整包路径
    pkg_full_candidates = call.get("pkg_full_candidates") or []  # [FIX] 通配符导入候选
    member = call.get("member")
    receiver_type = call.get("receiver_type")

    # 1) [Phase 19] 优先使用AST提取的pkg/pkg_full进行精确匹配
    if pkg or member:
        rules = match_library_call_precise(
            pkg_alias=pkg,
            member=member,
            pkg_full=pkg_full,  # [FIX Phase 19] 传递pkg_full
            import_aliases=alias_map,
            imports=imports,
            merged_rules=kb_bundle["merged_rules"],
        )
        if rules:
            return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]
        
        # 1.5) [FIX] 如果没有pkg_full但有pkg_full_candidates（通配符导入），尝试每个候选
        if not pkg_full and pkg_full_candidates:
            for candidate_pkg_full in pkg_full_candidates:
                rules = match_library_call_precise(
                    pkg_alias=pkg,
                    member=member,
                    pkg_full=candidate_pkg_full,
                    import_aliases=alias_map,
                    imports=imports,
                    merged_rules=kb_bundle["merged_rules"],
                )
                if rules:
                    return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]

        # 1.6) Receiver-object calls such as kg.init(256): the receiver name is
        # just a local variable, but the AST type resolver may have recovered
        # receiver_type=KeyGenerator. Use that type to match JCA instance APIs.
        if receiver_type and member:
            receiver_type = str(receiver_type).strip()
            receiver_candidates = []
            for imp in imports:
                imp_text = str(imp or '').strip()
                if imp_text.endswith('.*'):
                    receiver_candidates.append(f"{imp_text[:-2]}.{receiver_type}")
                elif imp_text.endswith(f".{receiver_type}"):
                    receiver_candidates.append(imp_text)
            if not receiver_candidates:
                receiver_candidates.append(receiver_type)
            for candidate_pkg_full in receiver_candidates:
                rules = match_library_call_precise(
                    pkg_alias=receiver_type,
                    member=member,
                    pkg_full=candidate_pkg_full,
                    import_aliases=alias_map,
                    imports=imports,
                    merged_rules=kb_bundle["merged_rules"],
                )
                if rules:
                    return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]

    # 2) 回退：从symbol文本回推
    if symbol and "." in symbol:
        parts = symbol.split(".")
        member = parts[-1]
        pkg_candidate = ".".join(parts[:-1])
        # 允许后缀匹配（import java.security.Signature; -> 调用 Signature.getInstance）
        if any(_endswith_or_eq(pkg_candidate, imp) or _endswith_or_eq(imp, pkg_candidate) for imp in imports):
            rules = match_library_call_precise(
                pkg_alias=pkg_candidate,
                member=member,
                pkg_full=None,
                import_aliases=alias_map,
                imports=imports,
                merged_rules=kb_bundle["merged_rules"],
            )
            if rules:
                return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]
    
    return find_rules_for_call(symbol, imports, kb_bundle)

def find_rules_for_call_precise_c(call: Dict[str, Any], features: Dict[str, Any], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    # C/C：多为前缀函数名；使用精确匹配以支持 literal 过滤
    from pqscan.loader.matcher import match_library_call_precise, _rule_def, _precise_symbol_match
    import re
    
    symbol = call.get("symbol") or ""
    alias_map = features.get("import_aliases") or {}
    imports = features.get("imports") or []
    
    if symbol:
        # 从调用代码中提取字面量
        code = call.get("code", "")
        literals = re.findall(r'["\']([^"\']*)["\']', code) if code else []
        
        # 使用精确匹配以支持字面量过滤（C中没有pkg.member的概念，symbol就是函数名）
        rules = match_library_call_precise(
            pkg_alias=None,
            member=None,
            import_aliases=alias_map,
            imports=imports,
            merged_rules=kb_bundle.get("merged_rules", []),
            symbol=symbol,
            code_snippet=code,
            literals=literals
        )
        
        if rules:
            return [apply_policy_on_rule(r, kb_bundle.get("policy")) for r in rules]

        # C/C++ downstream projects often wrap or indirectly include OpenSSL
        # headers, so the current translation unit may invoke native APIs
        # without an immediately visible #include <openssl/...>. In that case,
        # keep strict symbol equality but relax the import requirement.
        strict_symbol_only = []
        for rule in kb_bundle.get("merged_rules", []) or []:
            rd = _rule_def(rule)
            r_symbols = rd.get("symbols") or []
            if r_symbols and any(_precise_symbol_match(symbol, rs) for rs in r_symbols):
                strict_symbol_only.append(rule)
        if strict_symbol_only:
            return [apply_policy_on_rule(r, kb_bundle.get("policy")) for r in strict_symbol_only]
        
        # 回退到简单符号匹配（当没有精确匹配时）
        return find_rules_for_call(symbol, imports, kb_bundle)
    return []

def find_rules_for_call_precise_dispatch(lang: str, call: Dict[str, Any], features: Dict[str, Any], kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    lang = (lang or "").lower()
    
    symbol = call.get("symbol", "")
    member = call.get("member", "")
    pkg = call.get("pkg")
    
    # 语言精确匹配
    if lang == "go":
        rules = find_rules_for_call_precise_go(call, features, kb_bundle)
    elif lang == "python":
        rules = find_rules_for_call_precise_python(call, features, kb_bundle)
    elif lang == "java":
        rules = find_rules_for_call_precise_java(call, features, kb_bundle)
    elif lang in ("c", "cpp", "c++", "cxx"):
        rules = find_rules_for_call_precise_c(call, features, kb_bundle)
    else:
        rules = find_rules_for_call(call.get("symbol", ""), features.get("imports", []), kb_bundle)

    if rules:
        return rules

    # [FIX] 兜底匹配：只对没有明确包前缀的调用生效
    # 有包前缀的调用（如cipher.NewCFBEncrypter）如果精确匹配失败，说明它不在规则库中
    # 不应该通过兜底匹配去匹配所有规则
    # 
    # [FIX 2024-12-09] 完全禁用兜底匹配
    # 兜底匹配会导致大量误报，例如用户定义的函数test_aes_128_cbc()匹配所有AES规则
    # 正确的做法是只匹配明确定义在规则库中的API
    return []
    
    # 注释掉的原始兜底匹配代码（保留以便将来参考）
    # if pkg:
    #     # 有包前缀但精确匹配失败，直接返回空（不进入兜底匹配）
    #     return []
    # 
    # # 最后兜底：后缀/相等匹配（只用于没有pkg前缀的调用）
    # return _fallback_suffix_match_rules(lang, features, kb_bundle)

# ------------------------------
# Wrapper 匹配
# ------------------------------
def find_rules_for_function(func_name: str, kb_bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules = match_wrapper_for_function(func_name, kb_bundle.get("wrapper_rules", []))
    return [apply_policy_on_rule(r, kb_bundle["policy"]) for r in rules]
