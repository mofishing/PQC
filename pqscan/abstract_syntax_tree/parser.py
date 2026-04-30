#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   parser.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/18 16:49   1.0         get_parser(lang)
"""

# pqscan/abstract_syntax_tree/parser.py
from __future__ import annotations

from tree_sitter_language_pack import get_parser as _get_parser

SUPPORTED_LANGS = {
    "go": "go",
    "python": "python",
    "java": "java",
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cxx": "cpp",
}

def get_parser(lang: str):
    """
    返回 tree-sitter parser 实例
    若语言未注册，抛出错误
    """
    if lang not in SUPPORTED_LANGS:
        raise ValueError("Unsupported language: {lang}")
    try:
        return _get_parser(SUPPORTED_LANGS[lang])
    except Exception as e:
        raise RuntimeError(
            "Failed to load parser for '{lang}' via tree_sitter_language_pack."
            " 请确认已安装并与当前 tree-sitter 版本兼容"
        )


def _make_go_parser():
    """
    兼容旧工具：返回 Go parser，失败则返回 None。
    """
    try:
        return get_parser("go")
    except Exception:
        return None
