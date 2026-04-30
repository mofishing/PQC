#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   def_use.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/10/20 14:58   1.0        use-def
"""

import re
from typing import List, Set

_WORD = re.compile(r'\b([A-Za-z_]\w*)\b')

def forward_uses(code_lines: List[str], def_line: int, var_name: str, max_search: int = 200) -> List[int]:
    """
    从定义行 def_line 向后寻找 var_name 的使用行
    返回出现该变量名的行号列表
    """
    uses: Set[int] = set()
    start = max(def_line + 1, 1)
    end = min(len(code_lines), def_line + max_search)
    for i in range(start, end + 1):
        line = code_lines[i-1]
        if re.search(rf'\b{re.escape(var_name)}\b', line):
            uses.add(i)
    return sorted(uses)

def extract_params_from_signature(func_src: str) -> List[str]:
    """
    极简 Go 形参名抽取：从 `func Name(param type, p2 type)` 抓标识符
    此实现是启发式，复杂类型时替换为 AST 参数节点抽取
    """
    m = re.search(r'func\s+\w+\s*\((.*?)\)', func_src, re.S)
    if not m:
        return []
    inside = m.group(1)
    parts = [p.strip() for p in inside.split(",") if p.strip()]
    names = []
    for p in parts:
        # 取最后一个“看起来像标识符”的词当作变量名
        tokens = _WORD.findall(p)
        if tokens:
            names.append(tokens[-1])
    # 去重
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n); out.append(n)
    return out
