import json
import glob
import os
from collections import defaultdict

KB_DIR = "pqscan/kb"  # 改成你的路径
API_DIR = os.path.join(KB_DIR, "apis")
PARAM_RULE_FILE = os.path.join(KB_DIR, "param_extraction_rules.json")

# 这些 key 表示“语义字段绑定到程序来源”的指令
BIND_KEYS = {"from_param", "param", "from_receiver", "from_return", "param_index"}

def count_bind_directives(obj) -> int:
    """口径B：统计 semantic 中绑定指令总数（递归）"""
    if isinstance(obj, dict):
        cnt = sum(1 for k in obj.keys() if k in BIND_KEYS)
        for v in obj.values():
            cnt += count_bind_directives(v)
        return cnt
    if isinstance(obj, list):
        return sum(count_bind_directives(x) for x in obj)
    return 0

def flatten_mappings(mappings):
    """
    mappings 可能是 list（常见），也可能是 dict（少数库用表驱动结构）。
    我们只对“包含 semantic 的 API mapping”计数；表驱动的常量表可单独统计。
    """
    if isinstance(mappings, list):
        return mappings
    if isinstance(mappings, dict):
        # 若 dict 的 value 里是 API mapping 列表，就展开；否则返回空（表示这不是 API 级映射）
        out = []
        for v in mappings.values():
            if isinstance(v, list):
                out.extend(v)
        return out
    return []

# 统计结果：每个“库文件/库名”分别给出
stats = defaultdict(lambda: {"mappings": 0, "mappings_with_bind": 0, "bind_directives": 0})

for path in sorted(glob.glob(os.path.join(API_DIR, "*.json"))):
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    lang = doc.get("language", os.path.basename(path))
    lib = doc.get("library") or doc.get("libraries") or doc.get("librarys") or os.path.basename(path)
    if isinstance(lib, list):
        lib = ", ".join(lib)

    mappings = flatten_mappings(doc.get("mappings", []))

    mappings_with_bind = 0
    bind_directives = 0

    for m in mappings:
        sem = m.get("semantic", {})
        d = count_bind_directives(sem)
        if d > 0:
            mappings_with_bind += 1
            bind_directives += d

    key = f"{lang}:{lib}"
    stats[key]["mappings"] += len(mappings)
    stats[key]["mappings_with_bind"] += mappings_with_bind
    stats[key]["bind_directives"] += bind_directives

# 独立 param_extraction_rules 的条数
param_rule_count = 0
if os.path.exists(PARAM_RULE_FILE):
    with open(PARAM_RULE_FILE, "r", encoding="utf-8") as f:
        param_rule_count = len(json.load(f).get("rules", []))

print("=== 参数语义规则统计（建议口径A + 口径B）===")
print(f"独立 param_extraction_rules 条数: {param_rule_count}")
print()
print(f"{'库':45s}  {'API映射':>7s}  {'含绑定条目(A)':>12s}  {'绑定指令数(B)':>12s}")
for k, v in stats.items():
    print(f"{k[:45]:45s}  {v['mappings']:7d}  {v['mappings_with_bind']:12d}  {v['bind_directives']:12d}")
