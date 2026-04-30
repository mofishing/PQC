#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   matcher.py
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/18 16:48   1.1         Rule matching (support 'api' or 'match', richer symbol/import matching)
"""

import re
from functools import lru_cache
from typing import List, Dict, Any, Iterable

# ------------------------------
# helpers
# ------------------------------
from .utils import _norm_mod, _last_seg, _endswith_or_eq

@lru_cache(maxsize=4096)
def _rx_from_glob(glob: str) -> re.Pattern:
    # 支持简单 * 通配
    g = _norm_mod(glob)
    rx = "^" + re.escape(g).replace(r"\*", ".*") + "$"
    return re.compile(rx)

def _any_match(candidates: Iterable[str], pattern: str) -> bool:
    """任一候选与 pattern（支持 *）匹配或为后缀相等"""
    if not pattern:
        return False
    rx = _rx_from_glob(pattern)
    
    # [FIX Phase 19] 特殊处理：如果pattern和candidate都有包前缀且member相同，要求包必须匹配
    # 例如：elliptic.GenerateKey不应该匹配ecdsa.GenerateKey
    pattern_norm = _norm_mod(pattern)
    pattern_has_pkg = "." in pattern_norm
    
    for c in candidates or []:
        cc = _norm_mod(c or "")
        if not cc:
            continue
        if rx.match(cc):
            return True
        
        # [FIX Phase 19] 如果pattern和candidate都有包前缀且member相同，进行包前缀检查
        if pattern_has_pkg and "." in cc:
            pattern_parts = pattern_norm.rsplit(".", 1)
            candidate_parts = cc.rsplit(".", 1)
            
            if len(pattern_parts) == 2 and len(candidate_parts) == 2:
                pattern_pkg, pattern_member = pattern_parts
                candidate_pkg, candidate_member = candidate_parts
                
                # 如果member相同，要求包也必须匹配
                if pattern_member == candidate_member:
                    # 包必须完全匹配或后缀匹配
                    if candidate_pkg == pattern_pkg or candidate_pkg.endswith("." + pattern_pkg) or pattern_pkg.endswith("." + candidate_pkg):
                        # 包匹配，允许通过后续检查
                        if _endswith_or_eq(cc, pattern):
                            return True
                    # 包不匹配但member相同，直接跳过（防止误匹配）
                    continue
        
        # 宽松匹配：后缀/相等语义（便于 'AES' 命中 'Crypto.Cipher.AES.new'）
        if _endswith_or_eq(cc, pattern):
            return True
    return False

def _rule_def(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    统一取规则里的匹配域：
    - 旧版规则：优先 'match'，其次 'api'，结构为 { "imports": [...], "symbols": [...], "literals": [...] }
    - 新版规则：直接在顶层有 'function', 'imports', 'literals'，需要转换为统一格式
    """
    # 优先使用旧版结构（兼容性）
    if rule.get("match") or rule.get("api"):
        return (rule.get("match") or rule.get("api") or {})
    
    # 新版规则：将 function 字段转换为 symbols
    result = {}
    if "imports" in rule:
        result["imports"] = rule["imports"]
    if "function" in rule:
        # 将 function 转换为 symbols（保持列表格式）
        result["symbols"] = [rule["function"]]
    if "literals" in rule:
        result["literals"] = rule["literals"]
    
    return result


def _precise_symbol_match(candidate: str, rule_symbol: str) -> bool:
    """Strict-but-normalized symbol comparison for precise matching.

    V2 KB symbols sometimes omit the top-level package prefix while AST extraction
    keeps the fully-qualified import path. We still require the terminal member to
    match, but allow one side to be a normalized suffix of the other when the
    package path is otherwise consistent.
    """
    cand = _norm_mod(candidate or "")
    rule = _norm_mod(rule_symbol or "")
    if not cand or not rule:
        return False
    if cand == rule:
        return True
    if "." not in cand or "." not in rule:
        return False

    cand_member = cand.rsplit(".", 1)[-1]
    rule_member = rule.rsplit(".", 1)[-1]
    if cand_member != rule_member:
        return False

    return _endswith_or_eq(cand, rule) or _endswith_or_eq(rule, cand)


# ------------------------------
# precise matching
# ------------------------------
def match_library_call_precise(
    *,
    pkg_alias: str,
    member: str,
    import_aliases: Dict[str, str],
    imports: List[str],
    merged_rules: List[Dict[str, Any]],
    fq_symbol: str = None,
    symbol: str = None,
    code_snippet: str = None,
    literals: List[str] = None,
    pkg_full: str = None,  # [FIX Phase 19] 添加pkg_full参数（完整包路径）
    library_apis: Dict[str, set] = None  # [NEW] 库API白名单：{library_name: {api_names}}
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    # [FIX Phase 19] 解析别名 -> 全名，优先使用传入的pkg_full
    if not pkg_full and pkg_alias:
        if pkg_alias not in import_aliases:
            # 别名未在 import_aliases 出现，严格模式：认为不是库调用
            # 这里不直接返回，让"无别名但有符号"场景还能靠 candidates 匹配到
            pass
        else:
            pkg_full = import_aliases[pkg_alias]

    # 构造本次调用的候选"符号"集合
    # 仅保留足够精确的形式，避免把通用成员名（如 New / Make / Len）误判为密码 API。
    candidates: List[str] = []
    if pkg_alias and member:
        candidates.append(f"{pkg_alias}.{member}")
    if pkg_full and member:
        candidates.append(f"{_norm_mod(pkg_full)}.{member}")
        candidates.append(member)
    if pkg_full:
        candidates.append(_norm_mod(pkg_full))
    # 优先加入 fq_symbol 和 symbol
    if fq_symbol:
        candidates.append(fq_symbol)
    if symbol:
        candidates.append(symbol)
    
    # [FIX 2026-04-15] 严格模式：所有规则都需要更强的验证
    # 防止通用符号或任何不确定来源的调用被误匹配
    # 如果没有明确的包前缀，则需要特别谨慎
    # [FIX] 强制 import 验证

    for rule in merged_rules or []:
        # 仅库规则或未显式指定层的规则
        layers = rule.get("layer") or ["library"]
        if "library" not in layers:
            continue

        m = _rule_def(rule)
        r_symbols = m.get("symbols") or []
        r_imports = m.get("imports") or []
        r_literals = m.get("literals") or []

        # import 条件（OR 语义）：
        # [FIX 2026-04-15] 严格模式: 如果规则要求特定库，必须在文件导入中找到
        imp_ok = True
        if r_imports:
            imp_ok = False
            have_imports = set(_norm_mod(i) for i in (imports or []))
            
            # [FIX Phase 19] 如果有pkg_full，必须精确匹配规则imports（避免elliptic匹配ecdsa）
            if pkg_full:
                # 检查pkg_full是否精确匹配规则的某个import
                for ri in r_imports:
                    if _endswith_or_eq(pkg_full, ri):
                        imp_ok = True
                        break
                
                # [FIX 2026-02-06] 如果精确匹配失败，尝试父包匹配
                # 例如：pkg_full='cryptography.hazmat.primitives.asymmetric.rsa',
                #       have_imports=['cryptography.hazmat.primitives.asymmetric'],
                #       r_imports=['cryptography.hazmat.primitives.asymmetric.rsa']
                # 检查 pkg_full 的父包是否在 have_imports 中
                if not imp_ok and have_imports:
                    # 提取 pkg_full 的所有父包
                    pkg_parts = pkg_full.split('.')
                    pkg_parents = ['.'.join(pkg_parts[:i]) for i in range(1, len(pkg_parts))]
                    
                    # 检查任何父包是否在 have_imports 中
                    if any(parent in have_imports or any(_endswith_or_eq(have, parent) for have in have_imports) for parent in pkg_parents):
                        imp_ok = True
            else:
                # 没有 pkg_full: [FIX 2026-04-15] 严格要求文件中必须有对应的导入
                # 否则拒绝匹配（防止跨库误匹配）
                # 例如：Go 代码中没有导入 OpenSSL，就不应该用 C 规则匹配
                if have_imports:
                    for ri in r_imports:
                        if any(_endswith_or_eq(have, ri) for have in have_imports):
                            imp_ok = True
                            break
                # 如果规则要求导入但文件中没有，则 imp_ok 保持 False（严格拒绝）
            
        if not imp_ok:
            continue

        # symbol 条件：严格精确匹配
        sym_ok = True
        if r_symbols:
            n_candidates = {_norm_mod(c) for c in candidates if c}
            n_rule_syms = {_norm_mod(rs) for rs in r_symbols if rs}
            sym_ok = any(
                _precise_symbol_match(candidate_symbol, rule_symbol)
                for candidate_symbol in n_candidates
                for rule_symbol in n_rule_syms
            )
        else:
            # 规则没有指定symbols：只有当调用有明确的包前缀时才匹配
            # 这避免了make、new等通用符号误匹配
            if not pkg_alias:
                sym_ok = False
        
        if not sym_ok:
            continue
        
        # [NEW] 库API白名单验证：如果library_apis被提供，检查symbol是否在库API中
        # 这比黑名单方案更加可维护，避免漏报
        if sym_ok and library_apis:
            # library_apis格式：{library_name: {api_names}}
            # 如果文件导入了特定库，symbol必须精确出现在该库的API列表中
            api_in_libraries = False
            
            # 获取当前符号要检查的候选
            candidates_to_check = {_norm_mod(s) for s in r_symbols} if r_symbols else set()
            
            for lib_name, apis in library_apis.items():
                if not apis:
                    continue
                # 检查任一候选是否在该库的API中
                n_apis = {_norm_mod(api) for api in apis if api}
                if candidates_to_check and any(candidate in n_apis for candidate in candidates_to_check):
                    api_in_libraries = True
                    break
                
            # 如果symbol不在任何导入库的API中，拒绝此规则
            if not api_in_libraries:
                sym_ok = False

        if not sym_ok:
            continue

        # literals 条件（OR 语义）：如果规则指定了 literals，必须匹配
        lit_ok = True
        if r_literals:
            lit_ok = False
            # 从代码片段或字面量列表中检查
            all_lits = literals or []
            if code_snippet:
                # 从代码片段中提取字符串字面量
                import re as regex
                # 简单的方法：查找字符串内容
                for lit in r_literals:
                    if lit.replace('"', '').replace("'", '') in code_snippet:
                        lit_ok = True
                        break
            # 直接检查提供的字面量列表
            if not lit_ok and literals:
                for lit in r_literals:
                    for have_lit in literals:
                        # 规范化后比较：精确匹配优先，然后才是包含匹配
                        have_normalized = have_lit.replace('"', '').replace("'", '').strip()
                        lit_normalized = lit.replace('"', '').replace("'", '').strip()
                        # 精确相等
                        if have_normalized == lit_normalized:
                            lit_ok = True
                            break
                        # 只有当规则literal是单个关键字（如"AES"）时，才允许包含匹配
                        # 避免 "AES" 匹配 "AES/CBC/PKCS5Padding"
                        elif '/' not in lit_normalized and lit_normalized in have_normalized:
                            # 检查是否是单独的单词，而不是前缀
                            # 例如："AES" 匹配 "AES/CBC" 中的 "AES" 部分（用/分隔）
                            parts = have_normalized.split('/')
                            if lit_normalized in parts:
                                lit_ok = True
                                break
                    if lit_ok:
                        break
        if not lit_ok:
            continue

        out.append(rule)

    return out


# ------------------------------
# legacy symbol+imports matcher (file-level)
# ------------------------------
def match_library_call(symbol: str, imports: List[str], merged_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    根据符号与 import 匹配对应算法规则（宽松 OR 语义），兼容 'match' 或 'api'
    """
    matches = []
    n_imports = [_norm_mod(i) for i in (imports or [])]
    sym_n = _norm_mod(symbol or "")
    for rule in merged_rules or []:
        rd = _rule_def(rule)
        syms = rd.get("symbols", []) or []
        imps = rd.get("imports", []) or []

        sym_ok = (not syms) or any(_any_match([sym_n], s) for s in syms)
        imp_ok = (not imps) or any(any(_endswith_or_eq(h, i) for h in n_imports) for i in imps)
        if sym_ok and imp_ok:
            matches.append(rule)
    return matches


# ------------------------------
# wrappers
# ------------------------------
def match_wrapper_for_function(func_name: str, wrapper_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    nlow = (func_name or "").lower()
    for r in wrapper_rules or []:
        m = r.get("match", {})
        ncs = [x.lower() for x in m.get("naming_contains", [])]
        if any(k in nlow for k in ncs):
            out.append(r)
    if not out:
        out = [r for r in (wrapper_rules or []) if r.get("id") == "WRAP.Generic"] or out
    return out


# ------------------------------
# policy merge
# ------------------------------
def apply_policy_on_rule(rule: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    根据 policy 白名单 / enforce_params 覆盖规则
    """
    org = (policy or {}).get("org_policy", {}) or {}

    # 过渡白名单
    wl = org.get("transitional_whitelist", {}) or {}
    algs = wl.get("algorithms", []) or []
    rid = rule.get("id") or rule.get("rule_id")
    if rid in algs:
        rule = dict(rule)
        rule["policy_whitelisted"] = True

    # enforce 参数（按 id 优先，其次按 family）
    enforce_table = org.get("enforce_params", {}) or {}
    enforce = enforce_table.get(rid) or enforce_table.get(rule.get("algorithm_family"))
    if enforce:
        p = dict(rule.get("params", {}) or {})
        p.update(enforce)
        rule = dict(rule)
        rule["params"] = p
    return rule
