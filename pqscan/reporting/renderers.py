#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Report renderers (JSON / Markdown)
"""

from __future__ import annotations

from typing import List

from .model import Report, Finding


def generate_json_report(file_path: str, findings: List[Finding]) -> str:
    report = Report(file=file_path)
    for f in findings:
        report.add_finding(f)
    report.compute_summary()
    return report.to_json()


def generate_markdown_report(file_path: str, findings: List[Finding]) -> str:
    report = Report(file=file_path)
    for f in findings:
        report.add_finding(f)
    report.compute_summary()

    lines = [
        "# 抗量子计算脆弱性检测报告",
        f"**文件：** `{file_path}`",
        "",
        "## 概要",
        f"- 总计发现：{report.summary['total']} 项",
        "- 严重性分布：",
    ]
    for sev, cnt in report.summary["severity_breakdown"].items():
        lines.append(f"  - {sev}: {cnt}")

    lines.append("\n## 详细结果\n")
    for f in findings:
        lines.append(f"### {f.symbol} @ line {f.line}")
        lines.append(f"- **规则ID：** {f.rule_id}")
        lines.append(f"- **层级：** {f.layer}")
        lines.append(f"- **类别：** {f.category}")
        lines.append(f"- **抗量子安全性：** {f.quantum_secure}")
        lines.append(f"- **严重性：** {f.severity}")
        lines.append(f"- **原因：** {f.reason}")
        if getattr(f, "profile_reason", None):
            lines.append(f"- **profile原因：** {f.profile_reason}")
        lines.append(f"- **建议：** {f.recommendation}")
        if f.evidence:
            lines.append(f"- **证据：** `{f.evidence}`")
        # [Task 15.3.2] 展示封装传播链路
        _wc = getattr(f, 'wrapper_chain', None) or []
        if _wc:
            chain_str = " → ".join(_wc)
            lines.append(f"- **传播链：** `{chain_str}`")
        lines.append("")

    return "\n".join(lines)


def save_json_report(file_path: str, findings: List[Finding], out_path: str) -> None:
    """
    保存为 JSON 文件
    """
    json_data = generate_json_report(file_path, findings)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json_data)


def save_markdown_report(file_path: str, findings: List[Finding], out_path: str) -> None:
    """
    保存为 Markdown 文件
    """
    md = generate_markdown_report(file_path, findings)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)


__all__ = [
    "generate_json_report",
    "generate_markdown_report",
    "save_json_report",
    "save_markdown_report",
]
