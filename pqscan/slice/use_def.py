import re
from typing import List, Dict, Set, Tuple, Any

# ---- 正则与关键词 ----
ASSIGN_RE = re.compile(
    r'(?P<lhs>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?P<op>:?=)\s*(?P<rhs>.+)$'
)
CONST_RE = re.compile(
    r'^\s*const\s+(?P<lhs>[A-Za-z_]\w*)\s*(?:[:\w\[\]*.()]+)?\s*=\s*(?P<rhs>.+)$'
)
VAR_RE = re.compile(
    r'^\s*var\s+(?P<lhs>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)'  # var a[, b]
    r'(?:\s*[:\w\[\]*.()]+)?'                                   # 可选类型
    r'(?:\s*=\s*(?P<rhs>.+))?$'                                 # 可选 = rhs
)

WORD_RE = re.compile(r'\b([A-Za-z_]\w*)\b')
NUM_RE = re.compile(r'\b(\d{1,6})\b')

GO_KEYWORDS = {
    "break","default","func","interface","select","case","defer","go","map","struct",
    "chan","else","goto","package","switch","const","fallthrough","if","range","type",
    "continue","for","import","return","var","true","false","nil"
}
COMMON_KEYWORDS = GO_KEYWORDS | {
    # Python/Java/C 等常见关键字，用于过滤词法提取的“变量名”噪声
    "class","def","return","if","elif","else","for","while","switch","case","default",
    "try","except","finally","with","as","from","import","public","private","protected",
    "static","final","void","int","float","double","char","bool","boolean","struct",
    "union","enum","goto","do","continue","break","new","delete","sizeof","this",
    "true","false","null","nullptr"
}

def _split_lhs(lhs_text: str) -> List[str]:
    return [x.strip() for x in lhs_text.split(",") if x.strip()]

def _vars_in_text(text: str) -> Set[str]:
    # 去除关键字与数字
    cand = set(WORD_RE.findall(text))
    return {w for w in cand if w not in COMMON_KEYWORDS and not w.isdigit()}

def _nums_in_text(text: str) -> Set[int]:
    out = set()
    for m in NUM_RE.findall(text or ""):
        try:
            out.add(int(m))
        except Exception:
            pass
    return out

# ---- 索引结构 ----
# defs_by_line[line] = [{lhs:set, rhs_vars:set, rhs_nums:set}]
# defs_by_var[var]   = [(line, entry_dict)]
# uses_by_var[var]   = set(lines)
def build_use_def_indices(code_lines: List[str]) -> Tuple[Dict[int, List[Dict[str,Any]]], Dict[str, List[Tuple[int, Dict[str,Any]]]], Dict[str, Set[int]]]:
    defs_by_line: Dict[int, List[Dict[str,Any]]] = {}
    defs_by_var: Dict[str, List[Tuple[int, Dict[str,Any]]]] = {}
    uses_by_var: Dict[str, Set[int]] = {}

    for i, line in enumerate(code_lines, start=1):
        stripped = line.strip()
        entry_list: List[Dict[str,Any]] = []

        # const 定义
        m = CONST_RE.match(stripped)
        if m:
            lhs_vars = {m.group("lhs")}
            rhs = m.group("rhs")
            entry_list.append({
                "lhs": lhs_vars,
                "rhs_vars": _vars_in_text(rhs),
                "rhs_nums": _nums_in_text(rhs),
                "kind": "const",
            })

        # var 定义
        m = VAR_RE.match(stripped)
        if m:
            lhs_vars = set(_split_lhs(m.group("lhs")))
            rhs = m.group("rhs") or ""
            entry_list.append({
                "lhs": lhs_vars,
                "rhs_vars": _vars_in_text(rhs),
                "rhs_nums": _nums_in_text(rhs),
                "kind": "var",
            })

        # 普通赋值/短变量声明（:= 或 =）
        m = ASSIGN_RE.search(stripped)
        if m:
            lhs_vars = set(_split_lhs(m.group("lhs")))
            rhs = m.group("rhs")
            entry_list.append({
                "lhs": lhs_vars,
                "rhs_vars": _vars_in_text(rhs),
                "rhs_nums": _nums_in_text(rhs),
                "kind": "assign" if m.group("op") == "=" else "short_assign",
            })

        if entry_list:
            defs_by_line[i] = entry_list
            for e in entry_list:
                for v in e["lhs"]:
                    defs_by_var.setdefault(v, []).append((i, e))

        # 使用点统计（粗粒度）：非定义行也可能使用变量
        # 简单策略：任何出现的标识符都算“使用”，定义行也统计 RHS 的使用
        use_vars = _vars_in_text(stripped)
        for v in use_vars:
            uses_by_var.setdefault(v, set()).add(i)

    # 保证按行递增，便于向上寻找最近定义
    for v, lst in defs_by_var.items():
        lst.sort(key=lambda x: x[0])

    return defs_by_line, defs_by_var, uses_by_var

# ---- 逆向切片（use-def） ----
def backward_slice(code_lines: List[str], start_line: int, var_names: List[str], hops: int = 12) -> List[int]:
    """
    从使用点（start_line）出发，逆向追踪 var_names 的定义链。
    返回相关行号（升序）。hops 限制迭代步数，避免极端循环。
    """
    if start_line < 1:
        start_line = 1
    if start_line > len(code_lines):
        start_line = len(code_lines)

    defs_by_line, defs_by_var, _ = build_use_def_indices(code_lines)

    needed: Set[str] = set(var_names or [])
    result: Set[int] = {start_line}
    visited_defs: Set[Tuple[int, str]] = set()  # (line, var)

    # 如果没有给变量名，尝试从该行提取
    if not needed:
        needed |= _vars_in_text(code_lines[start_line-1])

    # 逐步向上寻找最近定义
    steps = 0
    scan_start = start_line
    while needed and steps < hops:
        steps += 1
        found_any = False

        # 对每个待求变量，找 <= scan_start 的最近定义行
        new_needed: Set[str] = set()
        for var in sorted(list(needed)):
            defs = defs_by_var.get(var, [])
            # 找到最接近 scan_start 的定义（最后一个 <= scan_start）
            target = None
            for ln, e in reversed(defs):
                if ln <= scan_start:
                    target = (ln, e)
                    break
            if target is None:
                # 没有定义，可能来自形参/外部，保留在 needed，但不阻塞
                continue

            ln, e = target
            if (ln, var) in visited_defs:
                continue

            visited_defs.add((ln, var))
            result.add(ln)
            found_any = True

            # 新的需求变量 = 该定义的 RHS 上游
            new_needed |= set(e["rhs_vars"])

            # 简单常量折叠：若 RHS 只有数字/常量，无上游变量，则不再扩展
            # 但我们仍然保留行号作为证据
        needed = new_needed

        # 下一轮从更早的行再搜
        scan_start = min(result) - 1 if result else scan_start - 1
        if scan_start < 1:
            break
        if not found_any:
            break

    return sorted(result)

# ---- 从调用参数文本里粗提变量名，当未做 AST 实参定位时可用 ----
def infer_vars_from_arglist(arg_text: str) -> List[str]:
    """
    输入形如: "ctx, keyBits, myMode, 2048"
    输出: ["ctx","keyBits","myMode"]
    """
    vs = [w for w in WORD_RE.findall(arg_text or "") if w not in COMMON_KEYWORDS and not w.isdigit()]
    # 去重且保持顺序
    seen, out = set(), []
    for v in vs:
        if v not in seen:
            seen.add(v); out.append(v)
    return out
