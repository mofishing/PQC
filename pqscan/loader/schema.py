# pqscan/knowledge/schema.py
from typing import Dict, Any

def ensure_rule_schema(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    确保规则字段完整、格式统一
    """
    rule.setdefault("algorithm_family", "UNKNOWN")
    rule.setdefault("category", "unknown")
    rule.setdefault("quantum_secure", "unknown")
    # rule.setdefault("params", {})
    # params = rule["params"]
    rule.setdefault("params", {})
    params = rule["params"] or {}

    # 确保常用参数字段存在
    for p in ["key_bits", "mode", "padding"]:
        params.setdefault(p, {})

    # 参数格式规范化
    # for k, v in params.items():
    #     if not isinstance(v, dict):
    #         params[k] = {"allow": [v]}
    #     v.setdefault("allow", [])
    #     v.setdefault("disallow", [])
    #     v.setdefault("default", None)
    #     if "allow" in v and "disallow" not in v:
    #         v["disallow"] = []
    #     elif "disallow" in v and "allow" not in v:
    #         v["allow"] = []
    #     if "severity_if_not_allow" not in v:
    #         v["severity_if_not_allow"] = "medium"
    #     if "severity_if_disallow" not in v:
    #         v["severity_if_disallow"] = "medium"

    for k, v in list(params.items()):
        # 标量 → 规范化为 dict
        if not isinstance(v, dict):
            v = {"allow": [v]}
        # 补全缺省字段
        v.setdefault("allow", [])
        v.setdefault("disallow", [])
        v.setdefault("default", None)
        v.setdefault("severity_if_not_allow", "medium")
        v.setdefault("severity_if_disallow", "medium")
        # 如果只给了 allow 或只给了 disallow，补另一侧为空列表
        if "allow" in v and "disallow" not in v:
            v["disallow"] = []
        if "disallow" in v and "allow" not in v:
            v["allow"] = []
        params[k] = v

    rule["params"] = params
    rule.setdefault("reason", "")
    rule.setdefault("recommendation", "")
    return rule
