#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   schema.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/23 16:45    1.0         json schema calibration
"""
# pqscan/llm/schema.py
from typing import Dict, Any, Tuple

EXPECTED_KEYS = {
    "algorithm_family": str, "variant": (str, type(None)),
    "category": str, "confidence": (int, float),
    "indicators": list, "key_bits": (int, type(None)),
    "block_size": (int, type(None)), "rounds": (int, type(None)),
    "rationale": str
}

def validate_classification(obj: Dict[str,Any]) -> Tuple[bool, str]:
    if not isinstance(obj, dict):
        return False, "not a json object"
    for k, t in EXPECTED_KEYS.items():
        if k not in obj:
            return False, f"missing key: {k}"
        if not isinstance(obj[k], t):
            return False, f"type mismatch on {k}"
    return True, ""
