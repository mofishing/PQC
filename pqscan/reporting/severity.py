#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   severity   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/19 10:54   1.0         None
"""

# pqscan/reporting/severity.py
from typing import Dict, Any, Optional

SEVERITY_ORDER = ["info", "low", "medium", "high"]

def compare_severity(a: str, b: str) -> str:
    return max(a, b, key=lambda x: SEVERITY_ORDER.index(x))

def evaluate_severity(rule: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    综合量子安全性、参数、策略，计算严重性。
    """
    base = "info"
    if rule.get("policy_whitelisted"):
        base = "low"
    elif rule.get("quantum_secure"):
        base = "info"
    elif rule.get("quantum_secure") == "weak":
        base = "medium"
    else:
        base = "high"

    # 参数安全性修正
    if evidence.get("violation"):
        base = compare_severity(base, "high")
    elif "details" in evidence and evidence["details"]:
        if any(str(v).startswith("disallowed") for v in evidence["details"].values()):
            base = compare_severity(base, "high")

    return base


def assess_severity(algorithm: Optional[str] = None,
                   key_bits: Optional[int] = None,
                   kb = None) -> str:
    """
    基于算法的量子威胁评估严重性（抗量子脆弱性检测视角）
    
    **抗量子视角**：优先评估量子威胁，传统约束仅作为次要参考

    策略（优先级从高到低）：
    1. **quantum_constraints.key_bits.severity**（量子威胁严重性）- 最高优先级
    2. **classic_constraints.key_bits.severity_map**（传统安全性）- 仅在没有量子约束时使用
    3. **quantum_secure + q_security_bits**（通用量子安全性判断）

    Args:
        algorithm: 算法标识符（如 ALG.RSA.PKE, ALG.AES 等）
        key_bits: 密钥长度（bits）
        kb: 知识库（包含 common_profiles 数据）

    Returns:
        严重性级别: "info", "low", "medium", "high", "critical"
        
    Examples:
        RSA 1024 → high (量子威胁 critical)
        RSA 4096 → high (量子威胁 critical，尽管传统安全)
        AES-128 → medium (量子威胁 weak)
        Kyber-512 → low (抗量子)
    """
    # 处理 algorithm 可能是非字符串类型的情况
    if algorithm and not isinstance(algorithm, str):
        # 如果是字典，尝试提取字符串值
        if isinstance(algorithm, dict):
            algorithm = algorithm.get('name') or algorithm.get('id') or str(algorithm)
        else:
            algorithm = str(algorithm)
    
    # 默认为 medium
    if not algorithm:
        return "medium"
    
    # 如果没有提供 KB，尝试加载
    if not kb or "common_profiles" not in kb:
        try:
            from pathlib import Path
            import json
            profile_path = Path(__file__).parent.parent / "kb" / "common" / "common_profiles.json"
            with open(profile_path, 'r', encoding='utf-8') as f:
                profiles_data = json.load(f)
        except Exception:
            # 如果加载失败，使用默认逻辑
            return "medium"
    else:
        profiles_data = kb.get("common_profiles", {})
    
    # 获取 profile
    profiles = {}
    for rule in profiles_data.get("rules", []):
        profiles[rule["id"]] = rule
    
    # 处理别名
    aliases = profiles_data.get("id_aliases", {})
    actual_id = aliases.get(algorithm, algorithm)
    profile = profiles.get(actual_id)
    
    # 如果找不到 profile，尝试模糊匹配（支持简化名）
    if not profile:
        # 尝试查找包含该算法名的 profile_id
        # 例如：algorithm="RSA" → 查找 "ALG.RSA.PKE"
        for profile_id, prof in profiles.items():
            if algorithm and algorithm.upper() in profile_id.upper():
                # 找到匹配，使用第一个
                profile = prof
                actual_id = profile_id
                break
    
    if not profile:
        return "medium"
    
    # 策略1: **优先**使用 quantum_constraints.key_bits.severity（量子威胁评估）
    # 这是抗量子检测工具，所以量子威胁是最高优先级
    quantum_constraints = profile.get("quantum_constraints", {})
    if quantum_constraints:
        key_bits_constraint = quantum_constraints.get("key_bits", {})
        if key_bits_constraint and "severity" in key_bits_constraint:
            # 量子约束中的 severity 表示量子威胁的严重性
            severity = key_bits_constraint["severity"]
            # 将 severity 映射到标准级别
            severity_mapping = {
                "critical": "high",   # 量子威胁严重（如 RSA、ECC）
                "error": "high",
                "warning": "medium",
                "info": "low",
                "none": "info"
            }
            base_severity = severity_mapping.get(severity, "medium")
            
            # 如果有密钥长度信息，检查是否极度弱（低于传统最小值）
            # 极度弱的密钥可能需要提升严重性
            if key_bits and base_severity != "high":  # 已经是 high 就不需要再提升
                classic_constraints = profile.get("classic_constraints", {})
                if classic_constraints:
                    key_bits_constraint_classic = classic_constraints.get("key_bits", {})
                    min_bits = key_bits_constraint_classic.get("min")
                    if min_bits and key_bits < min_bits:
                        # 密钥极度弱，提升到 high
                        return "high"
            
            return base_severity
    
    # 策略2: 如果没有量子约束，使用 classic_constraints.key_bits.severity_map
    # 这适用于没有明确量子威胁的算法（如某些对称算法）
    if key_bits:
        classic_constraints = profile.get("classic_constraints", {})
        if classic_constraints:
            key_bits_constraint = classic_constraints.get("key_bits", {})
            if key_bits_constraint and "severity_map" in key_bits_constraint:
                severity_map = key_bits_constraint["severity_map"]
                
                # 查找匹配的范围
                for range_str, severity in severity_map.items():
                    if _match_range(key_bits, range_str):
                        # 映射到标准级别
                        severity_mapping = {
                            "critical": "high",
                            "error": "high",
                            "warning": "medium",
                            "info": "low",
                            "none": "info"
                        }
                        return severity_mapping.get(severity, "medium")
    
    # 策略3: 基于 quantum_secure 和 q_security_bits 判断（通用回退）
    quantum_secure = profile.get("quantum_secure", False)
    q_security_bits = profile.get("q_security_bits", 0)
    
    if quantum_secure == True or quantum_secure == "strong":
        return "info"  # 抗量子算法
    elif quantum_secure == "weak":
        return "medium"  # 弱抗量子
    elif quantum_secure == "broken":
        return "high"  # 已破解
    elif q_security_bits == 0:
        return "high"  # 完全不抗量子
    elif q_security_bits < 64:
        return "high"  # 量子安全位数很低
    elif q_security_bits < 128:
        return "medium"  # 量子安全位数中等
    else:
        return "low"  # 量子安全位数较高
    
    return "medium"


def _match_range(value: int, range_str: str) -> bool:
    """
    匹配范围字符串，如 "< 2048", "2048", ">= 4096"
    
    Args:
        value: 要匹配的值
        range_str: 范围字符串
    
    Returns:
        是否匹配
    """
    range_str = range_str.strip()
    
    # 精确匹配
    if range_str.isdigit():
        return value == int(range_str)
    
    # 范围匹配
    if range_str.startswith(">="):
        threshold = int(range_str[2:].strip())
        return value >= threshold
    elif range_str.startswith(">"):
        threshold = int(range_str[1:].strip())
        return value > threshold
    elif range_str.startswith("<="):
        threshold = int(range_str[2:].strip())
        return value <= threshold
    elif range_str.startswith("<"):
        threshold = int(range_str[1:].strip())
        return value < threshold
    
    return False
