#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   base   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/19 10:49    1.0         AnalyzerBase
"""

# pqscan/analysis/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from ..reporting.model import Finding
from ..reporting.severity import evaluate_severity


def infer_profile_reason(
    evidence: Optional[Dict[str, Any]],
    profile_id: Optional[str],
) -> Optional[str]:
    """Infer why a finding is still unknown when profile_id is missing.

    Returns None when the profile is resolved. Otherwise returns a short
    machine-readable reason token such as:
    - no_evidence
    - upstream_policy
    - analysis_unresolved
    - semantic_no_match
    - policy_suppressed
    - unknown
    """
    if profile_id:
        return None

    if not evidence:
        return "no_evidence"

    if evidence.get("suppressed") or evidence.get("suppressed_by_policy"):
        return "policy_suppressed"

    source = evidence.get("source")
    if source == "ast_only":
        return "upstream_policy"
    if source == "symbolic_execution":
        return "analysis_unresolved"

    sem = evidence.get("semantic")
    if isinstance(sem, dict):
        sem_pid = sem.get("profile_id") or sem.get("profile")
        if sem_pid in (None, "", "UNKNOWN"):
            return "semantic_no_match"

    return "unknown"

class AnalyzerBase(ABC):
    """
    所有分析器的抽象基类。
    - 统一接入知识库 bundle（含 common/go 映射与 policy）
    - 提供 make_finding()：按 reporting.Finding 产出结果，并用 reporting.severity 计算严重性
    """
    def __init__(self, kb_bundle: Dict[str, Any]):
        self.kb = kb_bundle

    @abstractmethod
    def analyze(self, code_path: str, code: str, features: Dict[str, Any], context: Optional[Dict[str, Any]] = None,) -> List[Finding]:
        ...

    def make_finding(
        self,
        *,
        file: str,
        line: int,
        symbol: str,
        rule: Dict[str, Any],
        layer: str,
        category: str,
        evidence: Dict[str, Any],
        literals: List[str] = None
    ) -> Finding:
        sev = evaluate_severity(rule, evidence)
        # 如果 evidence 中包含 semantic.profile_id 或 semantic.profile，优先填充 profile_id
        profile_id = None
        sem = (evidence or {}).get("semantic")
        if isinstance(sem, dict):
            profile_id = sem.get("profile_id") or sem.get("profile")

        return Finding(
            file=file,
            line=line,
            symbol=symbol,
            rule_id=rule["id"],
            profile_id=profile_id,
            layer=layer,
            category=category,
            quantum_secure=rule.get("quantum_secure"),
            severity=sev,
            reason=rule.get("reason", ""),
            recommendation=rule.get("recommendation", ""),
            evidence=evidence or {},
            literals=literals or [],
            profile_reason=infer_profile_reason(evidence, profile_id),
        )
