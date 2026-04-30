from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

# KB 目录：与本文件同级
_KB_DIR = Path(__file__).parent


def load_kb(lang: str = "all") -> Dict[str, Any]:
    """
    加载知识库，返回供 scan_candidates() 使用的 KB 字典。

    Args:
        lang: 目标语言；"all" 表示合并所有语言（go/python/java/c）。
              传入具体语言时，只加载该语言的映射。

    Returns:
        KB 字典，包含：
          api_mappings   — API 映射列表
          common_profiles — 通用算法配置文件
          merged_rules   — 合并后的规则列表
          version        — "2.0"
          language       — 请求的语言

    Example::

        from pqscan.kb import load_kb
        from pqscan.abstract_syntax_tree.scanner import scan_candidates

        kb = load_kb()                                      # 全语言
        candidates = scan_candidates(code, "go", kb)
    """
    from pqscan.loader.loader_v2 import (
        load_api_mappings,
        build_merged_rules_v2,
        load_common_profiles,
        load_kb_v2,
    )

    if lang != "all":
        # 单语言模式：直接调用 loader_v2
        return load_kb_v2(_KB_DIR, lang)

    # 全语言模式：合并所有支持的语言
    all_mappings: list = []
    for _lang in ("go", "python", "java", "c"):
        try:
            mappings = load_api_mappings(_KB_DIR, _lang)
            for m in mappings:
                # 过滤掉 meta 数据块（algid_tables 等）
                if isinstance(m, dict) and "_meta_algid_tables" not in m:
                    all_mappings.append(m)
        except Exception:
            pass  # 该语言映射不存在时静默跳过

    common_profiles = load_common_profiles(_KB_DIR)
    merged_rules = build_merged_rules_v2(all_mappings, common_profiles)

    return {
        "api_mappings": all_mappings,
        "common_profiles": common_profiles,
        "merged_rules": merged_rules,
        "version": "2.0",
        "language": lang,
    }
