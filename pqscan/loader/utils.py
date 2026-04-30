#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Shared loader utilities (normalization, matching helpers, JSON comment stripping)
"""

from __future__ import annotations

import re
from typing import Optional


def _norm_mod(x: Optional[str]) -> str:
    # 统一分隔符为点，去掉多余空白
    return (x or "").replace("/", ".").strip()


def _last_seg(x: Optional[str]) -> str:
    x = _norm_mod(x or "")
    return x.split(".")[-1] if x else x


def _last2_segs(x: Optional[str]) -> str:
    x = _norm_mod(x or "")
    parts = x.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else x


def _endswith_or_eq(have: Optional[str], need: Optional[str]) -> bool:
    if not have or not need:
        return False
    h = _norm_mod(have)
    n = _norm_mod(need)
    # 精确或后缀匹配（模块/符号常用层级）
    return h == n or h.endswith("." + n) or n.endswith("." + h)


def strip_json_comments(text: str) -> str:
    """移除 JSON 风格注释（// 与 /* */）"""
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return text

