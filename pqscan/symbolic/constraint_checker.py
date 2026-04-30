"""
约束检查器：双模式约束验证（量子 + 传统）

支持：
1. quantum_constraints: 量子计算威胁（Shor/Grover 攻击）
2. classic_constraints: 传统密码学问题（ECB 模式、弱填充等）
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum


class ConstraintMode(Enum):
    """约束模式"""
    QUANTUM = "quantum"
    CLASSIC = "classic"


class Severity(Enum):
    """严重性级别"""
    CRITICAL = "critical"  # 严重（例如：DES、MD5）
    ERROR = "error"        # 错误（例如：ECB 模式）
    WARNING = "warning"    # 警告（例如：AES-128 量子不安全）
    INFO = "info"          # 信息（例如：建议使用更安全的算法）
    NONE = "none"          # 无问题
    
    def __lt__(self, other):
        """定义严重性级别排序"""
        order = {
            Severity.NONE: 0,
            Severity.INFO: 1,
            Severity.WARNING: 2,
            Severity.ERROR: 3,
            Severity.CRITICAL: 4,
        }
        return order[self] < order[other]


@dataclass
class ConstraintViolation:
    """约束违规"""
    mode: ConstraintMode           # 违规模式（quantum/classic）
    severity: Severity             # 严重性
    parameter: str                 # 违规参数（如 "key_bits", "mode"）
    value: Any                     # 参数值
    reason: str                    # 违规原因
    migrate_to: List[str] = None   # 推荐迁移到的算法
    
    def __post_init__(self):
        if self.migrate_to is None:
            self.migrate_to = []


class ConstraintChecker:
    """
    约束检查器
    
    使用示例：
        checker = ConstraintChecker()
        violations = checker.check_constraints(
            profile=aes_profile,
            params={"key_bits": 128, "mode": "ECB"},
            pq_mode=True,
            classic_mode=True
        )
    """
    
    def __init__(self):
        pass
    
    def check_constraints(
        self,
        profile: Dict[str, Any],
        params: Dict[str, Any],
        pq_mode: bool = True,
        classic_mode: bool = False
    ) -> List[ConstraintViolation]:
        """
        检查约束违规
        
        Args:
            profile: 从 get_profile() 获取的配置
            params: 提取的参数（如 {"key_bits": 128, "mode": "ECB"}）
            pq_mode: 是否启用量子检测
            classic_mode: 是否启用传统检测
        
        Returns:
            违规列表
        """
        violations = []
        
        # 量子约束检查
        if pq_mode and "quantum_constraints" in profile:
            qc_violations = self._check_quantum_constraints(
                profile["quantum_constraints"],
                params
            )
            violations.extend(qc_violations)
        
        # 传统约束检查
        if classic_mode and "classic_constraints" in profile:
            cc_violations = self._check_classic_constraints(
                profile["classic_constraints"],
                params
            )
            violations.extend(cc_violations)
        
        return violations
    
    def _check_quantum_constraints(
        self,
        constraints: Dict[str, Any],
        params: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查量子约束"""
        violations = []
        
        # 遍历所有约束参数
        for param_name, constraint in constraints.items():
            if not isinstance(constraint, dict):
                continue
            
            # 检查该参数是否在提供的参数中
            if param_name in params:
                param_value = params[param_name]
                
                # 特殊处理不同类型的参数
                if param_name in ["key_bits", "digest_bits", "block_bits", "output_bits"]:
                    # 数值类型参数
                    violations.extend(self._check_numeric_param_quantum(
                        param_name, constraint, param_value
                    ))
                elif param_name == "mode":
                    # 模式参数
                    violations.extend(self._check_mode_quantum(constraint, param_value))
                elif param_name == "algorithm":
                    # 算法级别约束
                    violations.extend(self._check_algorithm_constraint_quantum(constraint))
            else:
                # 参数不在提供的列表中，检查是否有算法级别的约束
                if param_name == "key_bits" and constraint.get("min_pq_resistant") is None:
                    # 算法本身不抗量子
                    if "severity" in constraint:
                        severity_str = constraint.get("severity", "warning")
                        severity = self._parse_severity(severity_str)
                        reason = constraint.get("reason", "Not quantum-resistant")
                        migrate_to = constraint.get("migrate_to", [])
                        
                        violations.append(ConstraintViolation(
                            mode=ConstraintMode.QUANTUM,
                            severity=severity,
                            parameter="algorithm",
                            value=None,
                            reason=reason,
                            migrate_to=migrate_to
                        ))
                elif param_name == "algorithm":
                    # 算法级别约束（不依赖参数值）
                    violations.extend(self._check_algorithm_constraint_quantum(constraint))
                elif param_name in ["digest_bits", "block_bits"] and "severity" in constraint:
                    # 固定值约束（如 MD5 的 digest_bits）
                    violations.extend(self._check_fixed_value_constraint_quantum(
                        param_name, constraint
                    ))
        
        return violations
    
    def _check_numeric_param_quantum(
        self,
        param_name: str,
        constraint: Dict[str, Any],
        param_value: int
    ) -> List[ConstraintViolation]:
        """检查数值类型参数的量子约束（key_bits, digest_bits 等）"""
        violations = []
        
        # 1. 检查 min_pq_resistant
        min_pq = constraint.get("min_pq_resistant")
        if min_pq is None:
            # null 表示算法本身不抗量子
            severity_str = constraint.get("severity", "warning")
            severity = self._parse_severity(severity_str)
            reason = constraint.get("reason", "Not quantum-resistant")
            migrate_to = constraint.get("migrate_to", [])
            
            violations.append(ConstraintViolation(
                mode=ConstraintMode.QUANTUM,
                severity=severity,
                parameter=param_name,
                value=param_value,
                reason=reason,
                migrate_to=migrate_to
            ))
            return violations
        
        # 2. severity_map
        severity_map = constraint.get("severity_map", {})
        reason = constraint.get("reason", "")
        
        param_str = str(param_value)
        if param_str in severity_map:
            severity_str = severity_map[param_str]
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.QUANTUM,
                    severity=severity,
                    parameter=param_name,
                    value=param_value,
                    reason=reason
                ))
        
        # 3. 检查是否低于最小阈值
        if min_pq and param_value < min_pq:
            violations.append(ConstraintViolation(
                mode=ConstraintMode.QUANTUM,
                severity=Severity.WARNING,
                parameter=param_name,
                value=param_value,
                reason=f"{param_name.replace('_', ' ').title()} {param_value} bits is below quantum-safe threshold {min_pq} bits"
            ))
        
        return violations
    
    def _check_fixed_value_constraint_quantum(
        self,
        param_name: str,
        constraint: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查固定值约束（如 MD5 的 digest_bits: 128）"""
        violations = []
        
        if "severity" in constraint:
            severity_str = constraint.get("severity", "info")
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                value = constraint.get("value")
                reason = constraint.get("reason", "")
                migrate_to = constraint.get("migrate_to", [])
                
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.QUANTUM,
                    severity=severity,
                    parameter=param_name,
                    value=value,
                    reason=reason,
                    migrate_to=migrate_to
                ))
        
        return violations
    
    def _check_algorithm_constraint_quantum(
        self,
        constraint: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查算法级别的量子约束"""
        violations = []
        
        if "severity" in constraint:
            severity_str = constraint.get("severity", "warning")
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                reason = constraint.get("reason", "Algorithm not quantum-resistant")
                migrate_to = constraint.get("migrate_to", [])
                
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.QUANTUM,
                    severity=severity,
                    parameter="algorithm",
                    value=None,
                    reason=reason,
                    migrate_to=migrate_to
                ))
        
        return violations
    
    def _check_classic_constraints(
        self,
        constraints: Dict[str, Any],
        params: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查传统约束"""
        violations = []
        
        # 遍历所有约束参数
        for param_name, constraint in constraints.items():
            if not isinstance(constraint, dict):
                continue
            
            # 检查该参数是否在提供的参数中
            if param_name in params:
                param_value = params[param_name]
                
                # 特殊处理不同类型的参数
                if param_name in ["key_bits", "digest_bits", "block_bits", "output_bits"]:
                    # 数值类型参数
                    violations.extend(self._check_numeric_param_classic(
                        param_name, constraint, param_value
                    ))
                elif param_name == "mode":
                    # 模式参数
                    violations.extend(self._check_mode_classic(constraint, param_value))
                elif param_name == "algorithm":
                    # 算法级别约束
                    violations.extend(self._check_algorithm_constraint_classic(constraint))
            else:
                # 参数不在提供的列表中，检查是否有算法级别的约束
                if param_name == "algorithm":
                    violations.extend(self._check_algorithm_constraint_classic(constraint))
                elif param_name in ["digest_bits", "block_bits"] and "severity" in constraint:
                    # 固定值约束
                    violations.extend(self._check_fixed_value_constraint_classic(
                        param_name, constraint
                    ))
        
        return violations
    
    def _check_numeric_param_classic(
        self,
        param_name: str,
        constraint: Dict[str, Any],
        param_value: int
    ) -> List[ConstraintViolation]:
        """检查数值类型参数的传统约束"""
        violations = []
        
        # 1. 检查 forbidden 列表
        forbidden = constraint.get("forbidden", [])
        if param_value in forbidden:
            severity_str = constraint.get("severity", "error")
            severity = self._parse_severity(severity_str)
            reason = constraint.get("reason", f"{param_name.replace('_', ' ').title()} {param_value} is forbidden")
            
            violations.append(ConstraintViolation(
                mode=ConstraintMode.CLASSIC,
                severity=severity,
                parameter=param_name,
                value=param_value,
                reason=reason
            ))
            return violations
        
        # 2. severity_map
        severity_map = constraint.get("severity_map", {})
        reason = constraint.get("reason", "")
        
        param_str = str(param_value)
        if param_str in severity_map:
            severity_str = severity_map[param_str]
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.CLASSIC,
                    severity=severity,
                    parameter=param_name,
                    value=param_value,
                    reason=reason
                ))
        
        return violations
    
    def _check_fixed_value_constraint_classic(
        self,
        param_name: str,
        constraint: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查固定值约束（传统模式）"""
        violations = []
        
        if "severity" in constraint:
            severity_str = constraint.get("severity", "info")
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                value = constraint.get("value")
                reason = constraint.get("reason", "")
                
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.CLASSIC,
                    severity=severity,
                    parameter=param_name,
                    value=value,
                    reason=reason
                ))
        
        return violations
    
    def _check_algorithm_constraint_classic(
        self,
        constraint: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查算法级别的传统约束"""
        violations = []
        
        if "severity" in constraint:
            severity_str = constraint.get("severity", "warning")
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                reason = constraint.get("reason", "Algorithm has security concerns")
                
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.CLASSIC,
                    severity=severity,
                    parameter="algorithm",
                    value=None,
                    reason=reason
                ))
        
        return violations
    
    def _check_key_bits_quantum(
        self,
        constraint: Dict[str, Any],
        key_bits: int
    ) -> List[ConstraintViolation]:
        """检查量子模式下的密钥长度"""
        violations = []
        
        # 1. 检查 min_pq_resistant
        min_pq = constraint.get("min_pq_resistant")
        if min_pq is None:
            # null 表示算法本身不抗量子（如 DES、RSA）
            severity_str = constraint.get("severity", "warning")
            severity = self._parse_severity(severity_str)
            reason = constraint.get("reason", "Not quantum-resistant")
            migrate_to = constraint.get("migrate_to", [])
            
            violations.append(ConstraintViolation(
                mode=ConstraintMode.QUANTUM,
                severity=severity,
                parameter="key_bits",
                value=key_bits,
                reason=reason,
                migrate_to=migrate_to
            ))
            return violations  # 如果算法本身不抗量子，不需要继续检查其他约束
        
        # 2. severity_map: {"128": "warning", "192": "info", "256": "none"}
        severity_map = constraint.get("severity_map", {})
        reason = constraint.get("reason", "")
        
        key_str = str(key_bits)
        if key_str in severity_map:
            severity_str = severity_map[key_str]
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.QUANTUM,
                    severity=severity,
                    parameter="key_bits",
                    value=key_bits,
                    reason=reason
                ))
        
        # 3. 检查是否低于最小抗量子阈值
        if min_pq and key_bits < min_pq:
            violations.append(ConstraintViolation(
                mode=ConstraintMode.QUANTUM,
                severity=Severity.WARNING,
                parameter="key_bits",
                value=key_bits,
                reason=f"Key length {key_bits} bits is below quantum-safe threshold {min_pq} bits"
            ))
        
        return violations
    
    def _check_key_bits_classic(
        self,
        constraint: Dict[str, Any],
        key_bits: int
    ) -> List[ConstraintViolation]:
        """检查传统模式下的密钥长度"""
        violations = []
        
        # severity_map: {"56": "critical", "112": "error", "128": "info"}
        severity_map = constraint.get("severity_map", {})
        reason = constraint.get("reason", "")
        
        key_str = str(key_bits)
        if key_str in severity_map:
            severity_str = severity_map[key_str]
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.CLASSIC,
                    severity=severity,
                    parameter="key_bits",
                    value=key_bits,
                    reason=reason
                ))
        
        return violations
    
    def _check_mode_quantum(
        self,
        constraint: Dict[str, Any],
        mode: str
    ) -> List[ConstraintViolation]:
        """检查量子模式下的加密模式"""
        violations = []
        
        # recommended: 推荐的模式
        recommended = constraint.get("recommended", [])
        severity_str = constraint.get("severity", "info")
        severity = self._parse_severity(severity_str)
        
        if recommended and mode not in recommended:
            violations.append(ConstraintViolation(
                mode=ConstraintMode.QUANTUM,
                severity=severity,
                parameter="mode",
                value=mode,
                reason=f"Recommended modes: {', '.join(recommended)}"
            ))
        
        return violations
    
    def _check_mode_classic(
        self,
        constraint: Dict[str, Any],
        mode: str
    ) -> List[ConstraintViolation]:
        """检查传统模式下的加密模式"""
        violations = []
        
        # forbidden: 禁止的模式（如 ECB）
        forbidden = constraint.get("forbidden", [])
        severity_map = constraint.get("severity_map", {})
        
        if mode in forbidden:
            severity_str = severity_map.get(mode, "error")
            severity = self._parse_severity(severity_str)
            
            violations.append(ConstraintViolation(
                mode=ConstraintMode.CLASSIC,
                severity=severity,
                parameter="mode",
                value=mode,
                reason=f"Mode '{mode}' is forbidden (insecure)"
            ))
        elif mode in severity_map:
            # 检查 severity_map 中的其他模式
            severity_str = severity_map[mode]
            severity = self._parse_severity(severity_str)
            
            if severity != Severity.NONE:
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.CLASSIC,
                    severity=severity,
                    parameter="mode",
                    value=mode,
                    reason=f"Mode '{mode}' has security concerns"
                ))
        
        return violations
    
    def _check_forbidden(
        self,
        forbidden: List[str],
        params: Dict[str, Any]
    ) -> List[ConstraintViolation]:
        """检查禁止项"""
        violations = []
        
        # 检查所有参数是否在禁止列表中
        for param_name, param_value in params.items():
            if str(param_value) in forbidden:
                violations.append(ConstraintViolation(
                    mode=ConstraintMode.CLASSIC,
                    severity=Severity.ERROR,
                    parameter=param_name,
                    value=param_value,
                    reason=f"Value '{param_value}' is forbidden"
                ))
        
        return violations
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """解析严重性字符串"""
        severity_map = {
            "critical": Severity.CRITICAL,
            "error": Severity.ERROR,
            "warning": Severity.WARNING,
            "info": Severity.INFO,
            "none": Severity.NONE,
        }
        return severity_map.get(severity_str.lower(), Severity.INFO)
