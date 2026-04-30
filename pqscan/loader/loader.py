# pqscan/knowledge/loader.py
import json
import pathlib
import re
from typing import Dict, Any, List, Union

import yaml

from .schema import ensure_rule_schema

def _as_path(p: Union[str, pathlib.Path]) -> pathlib.Path:
    return p if isinstance(p, pathlib.Path) else pathlib.Path(p)

def _load_json_or_yaml(path: pathlib.Path) -> Dict[str, Any]:
    if path.suffix in (".yml", ".yaml"):
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        return json.loads(path.read_text(encoding="utf-8"))

def load_all_kb(kb_dir: pathlib.Path, language: str = None) -> Dict[str, Any]:
    """
    加载 common.json + go.json + policy.yaml，并合并为统一规则集：
    {
      "common": {...},
      "language": {...},
      "policy": {...},
      "merged_rules": [ ... ]
    }
    """

    kb_dir = _as_path(kb_dir)

    common_file = kb_dir / "rules.common.json"
    policy_file = kb_dir / "policy.org.yaml"
    lang_files = kb_dir.glob("rules.*.json")
    
    common = _load_json_or_yaml(common_file)
    policy = _load_json_or_yaml(policy_file)

    # 根据输入代码的 language 选择加载对应规则文件
    code_lang = language or "go"  # 默认 go
    lang_file = kb_dir / f"rules.{code_lang}.json"
    if not lang_file.exists():
        lang_file = kb_dir / "rules.go.json" # 兼容,默认用 go 的规则

    language = _load_json_or_yaml(lang_file)

    # 将 common 的规则转成 {id:rule} 便于快速索引
    common_rules = {r["id"]: ensure_rule_schema(r) for r in common.get("rules", [])}
    mappings = language.get("mappings", [])

    # merge：用 go.json 的 rule_id 对应到 common.json 的 rule 定义
    merged_rules = []
    for m in mappings:
        rid = m["rule_id"]
        if rid not in common_rules:
            continue
        rule = dict(common_rules[rid])
        rule["match"] = m["api"]
        rule["layer"] = ["library"]  # 语言绑定即库调用层
        merged_rules.append(rule)

    # wrapper_rules 直接取自 common 中 layer 包含 "wrapper" 的规则
    wrapper_rules = [ensure_rule_schema(r) for r in common.get("rules", [])
                        if "wrapper" in (r.get("layer") or [])]

    # 加载 llm kb
    llm_bundle = load_llm_kb(kb_dir)

    return {
        "common": common_rules,
        "language": mappings,
        "policy": policy,
        "merged_rules": merged_rules,
        "wrapper_rules": wrapper_rules,
        "llm": llm_bundle,
    }

def _compile_regex(pat: str, flags: List[str]) -> re.Pattern:
    f = 0
    for flg in (flags or []):
        fl = flg.lower()
        if fl == "i": f |= re.IGNORECASE
        if fl == "m": f |= re.MULTILINE
        if fl == "s": f |= re.DOTALL
    return re.compile(pat, f)

def load_llm_kb(kb_dir: pathlib.Path) -> Dict[str, Any]:
    """
    读取 kb/llm 下的：
      - heuristics.json    启发式规则（算法→正则/权重/理由）
      - prompts.json       提示词（system/user 模板，带占位符）
      - labels.json        算法族→类别/默认元信息
      - model.json         LLM provider/model/temperature
      - fewshot.json       少样本示例（可选）
      - extract_prompts.json 参数抽取提示词（可选）
    并预编译 heuristics 为 compiled_heuristics。
    """
    llm_root = kb_dir / "llm"
    out: Dict[str, Any] = {
        "heuristics": {},
        "compiled_heuristics": {},
        "prompts": {},
        "labels": {},
        "model": {},
        "fewshot": {},
        "extract_prompts": {}
    }

    def _load_if_exists(p: pathlib.Path) -> Dict[str, Any]:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                # JSON 解析失败时返回空，必要时可在此处打日志
                return {}
        return {}

    heur = _load_if_exists(llm_root / "heuristics.json")
    prompts = _load_if_exists(llm_root / "prompts.json")
    labels = _load_if_exists(llm_root / "labels.json")
    model = _load_if_exists(llm_root / "model.json")
    fewshot = _load_if_exists(llm_root / "fewshot.json")
    extract_prompts = _load_if_exists(llm_root / "extract_prompts.json")

    # 预编译 heuristics（支持可选 lang 过滤）
    compiled: Dict[str, Any] = {}
    for family, rules in (heur.get("algorithms") or {}).items():
        bucket = []
        for rule in rules:
            pat = rule.get("pattern", "")
            flags = rule.get("flags", [])
            weight = float(rule.get("weight", 1.0))
            reason = rule.get("reason", "")
            langs = {s.lower() for s in rule.get("lang", ["*"])}
            try:
                rx = _compile_regex(pat, flags)
            except re.error:
                # 跳过非法正则
                continue
            bucket.append({"rx": rx, "weight": weight, "reason": reason, "langs": langs})
        compiled[family] = bucket

    out["heuristics"] = heur
    out["compiled_heuristics"] = compiled
    out["prompts"] = prompts
    out["labels"] = labels
    out["model"] = model
    out["fewshot"] = fewshot
    out["extract_prompts"] = extract_prompts
    return out