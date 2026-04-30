#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   model   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/19 10:54   1.0         None
"""

# pqscan/reporting/model.py
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any
import json

@dataclass
class Finding:
    file: str
    line: int
    symbol: str
    rule_id: str
    layer: str
    category: str
    quantum_secure: Any
    severity: str
    reason: str
    recommendation: str
    # 可选的语义profile（由分析器填充，如 semantic.profile/profile_id）
    profile_id: str = None
    key_bits: int = None  # 密钥位数（由符号分析填充）
    evidence: Dict[str, Any] = field(default_factory=dict)
    literals: List[str] = field(default_factory=list)
    # Task 15: 封装传播链路
    # 从叶节点（敏感 API）到入口调用点的完整调用链
    # 示例: ["RSA.generate", "setup_rsa_key", "init_rsa", "create_crypto_context"]
    # 直接调用时为单元素: ["RSA.generate"]
    wrapper_chain: List[str] = field(default_factory=list)
    # profile_id 为空时，说明该 finding 为什么仍处于 unknown
    profile_reason: str = None
    # key_bits 无法从当前位置识别时的说明
    key_bits_reason: str = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # 去掉空链路（减小输出体积）；单元素链路保留以表明是直接调用
        if not d.get('wrapper_chain'):
            d.pop('wrapper_chain', None)
        return d


@dataclass
class Report:
    file: str
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def compute_summary(self):
        total = len(self.findings)
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        self.summary = {
            "total": total,
            "severity_breakdown": by_severity
        }

    def to_dict(self):
        self.compute_summary()
        return {
            "file": self.file,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings]
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
