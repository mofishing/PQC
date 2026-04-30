#!/usr/bin/env python3
"""
约束求解器（Constraint Solver）

混合求解策略：
1. Fast Path: 自建线性求解器（无依赖）
2. Slow Path: Z3 SMT 求解器（可选依赖）

使用场景：
- 简单线性约束 → 自建求解器（快速）
- 复杂非线性约束 → Z3（强大）
"""

from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

from pqscan.analysis.wrapper_summary import (
    Expr, ExprType, Contract, ParamConstraint, Predicate
)


# ============================================================================
# 求解器类型
# ============================================================================

class SolverType(Enum):
    """求解器类型"""
    BUILTIN = "builtin"  # 自建求解器
    Z3 = "z3"            # Z3 SMT 求解器


class SolverResult(Enum):
    """求解结果"""
    SAT = "sat"          # 可满足
    UNSAT = "unsat"      # 不可满足
    UNKNOWN = "unknown"  # 未知


# ============================================================================
# 自建线性求解器（Fast Path）
# ============================================================================

class BuiltinSolver:
    """
    自建线性求解器
    
    支持：
    - 线性不等式：ax + b >= c
    - 简单的常量折叠
    
    不支持：
    - 非线性约束
    - 位运算
    - 数组操作
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def check_sat(
        self,
        constraints: List[ParamConstraint],
        param_values: Dict[str, Any]
    ) -> SolverResult:
        """
        检查约束是否可满足
        
        Args:
            constraints: 约束列表
            param_values: 参数值
            
        Returns:
            SAT/UNSAT/UNKNOWN
        """
        for constraint in constraints:
            value = param_values.get(constraint.param)
            
            if value is None:
                # 参数值未知
                return SolverResult.UNKNOWN
            
            # 检查约束
            if constraint.predicate == Predicate.GEQ:
                if value < constraint.value:
                    return SolverResult.UNSAT
            elif constraint.predicate == Predicate.LEQ:
                if value > constraint.value:
                    return SolverResult.UNSAT
            elif constraint.predicate == Predicate.EQ:
                if value != constraint.value:
                    return SolverResult.UNSAT
            elif constraint.predicate == Predicate.NEQ:
                if value == constraint.value:
                    return SolverResult.UNSAT
        
        return SolverResult.SAT
    
    def solve_for_param(
        self,
        expr: Expr,
        param_name: str,
        predicate: Predicate,
        threshold: Any
    ) -> Optional[Tuple[Predicate, Any]]:
        """
        求解单个参数的约束
        
        例如：
            expr = param * 8
            predicate = >=
            threshold = 256
            
            求解: param * 8 >= 256 → param >= 32
        
        Args:
            expr: 表达式
            param_name: 参数名
            predicate: 谓词
            threshold: 阈值
            
        Returns:
            (新谓词, 新阈值) 或 None
        """
        # Case 1: 直接是参数
        if expr.type == ExprType.PARAM and expr.param == param_name:
            return (predicate, threshold)
        
        # Case 2: 乘法 - param * const
        if expr.type == ExprType.MUL:
            left, right = expr.left, expr.right
            
            # param * const
            if left.type == ExprType.PARAM and left.param == param_name:
                if right.type == ExprType.CONST and right.value > 0:
                    if predicate == Predicate.GEQ:
                        # param * c >= t → param >= ceil(t / c)
                        new_threshold = -(-threshold // right.value)
                        return (Predicate.GEQ, new_threshold)
            
            # const * param
            if right.type == ExprType.PARAM and right.param == param_name:
                if left.type == ExprType.CONST and left.value > 0:
                    if predicate == Predicate.GEQ:
                        new_threshold = -(-threshold // left.value)
                        return (Predicate.GEQ, new_threshold)
        
        # Case 3: 加法 - param + const
        if expr.type == ExprType.ADD:
            left, right = expr.left, expr.right
            
            # param + const
            if left.type == ExprType.PARAM and left.param == param_name:
                if right.type == ExprType.CONST:
                    if predicate == Predicate.GEQ:
                        # param + c >= t → param >= t - c
                        new_threshold = threshold - right.value
                        return (Predicate.GEQ, new_threshold)
            
            # const + param
            if right.type == ExprType.PARAM and right.param == param_name:
                if left.type == ExprType.CONST:
                    if predicate == Predicate.GEQ:
                        new_threshold = threshold - left.value
                        return (Predicate.GEQ, new_threshold)
        
        return None


# ============================================================================
# Z3 求解器（Slow Path）
# ============================================================================

class Z3Solver:
    """
    Z3 SMT 求解器（可选依赖）
    
    支持：
    - 线性/非线性约束
    - 位向量
    - 数组
    - 函数
    
    需要安装：pip install z3-solver
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.available = self._check_z3_available()
        
        if not self.available:
            if self.verbose:
                print("[警告] Z3 求解器不可用，请安装: pip install z3-solver")
    
    def _check_z3_available(self) -> bool:
        """检查 Z3 是否可用"""
        try:
            import z3
            return True
        except ImportError:
            return False
    
    def check_sat(
        self,
        constraints: List[ParamConstraint],
        param_values: Dict[str, Any]
    ) -> SolverResult:
        """
        使用 Z3 检查约束可满足性
        
        Args:
            constraints: 约束列表
            param_values: 参数值
            
        Returns:
            SAT/UNSAT/UNKNOWN
        """
        if not self.available:
            return SolverResult.UNKNOWN
        
        import z3
        
        # 创建求解器
        solver = z3.Solver()
        
        # 创建符号变量
        z3_vars = {}
        for constraint in constraints:
            if constraint.param not in z3_vars:
                z3_vars[constraint.param] = z3.Int(constraint.param)
        
        # 添加约束
        for constraint in constraints:
            var = z3_vars[constraint.param]
            value = constraint.value
            
            if constraint.predicate == Predicate.GEQ:
                solver.add(var >= value)
            elif constraint.predicate == Predicate.LEQ:
                solver.add(var <= value)
            elif constraint.predicate == Predicate.EQ:
                solver.add(var == value)
            elif constraint.predicate == Predicate.NEQ:
                solver.add(var != value)
        
        # 添加参数值约束
        for param, value in param_values.items():
            if param in z3_vars:
                solver.add(z3_vars[param] == value)
        
        # 求解
        result = solver.check()
        
        if result == z3.sat:
            return SolverResult.SAT
        elif result == z3.unsat:
            return SolverResult.UNSAT
        else:
            return SolverResult.UNKNOWN

    def solve_with_model(
        self,
        constraints: List[ParamConstraint],
        param_values: Dict[str, Any]
    ) -> Tuple[SolverResult, Optional[Dict[str, Any]]]:
        """
        使用 Z3 求解并提取满足模型（SAT 时）或确认不可满足（UNSAT）

        Args:
            constraints: 参数约束列表
            param_values: 已知参数值（作为附加等值约束）

        Returns:
            (SolverResult, model_dict)
            - SAT:    model_dict 为满足所有约束的示例赋值 {param: value}
            - UNSAT:  model_dict 为 None（无反例）
            - UNKNOWN: model_dict 为 None
        """
        if not self.available:
            return SolverResult.UNKNOWN, None

        import z3

        solver = z3.Solver()
        z3_vars: Dict[str, Any] = {}

        for constraint in constraints:
            if constraint.param not in z3_vars:
                z3_vars[constraint.param] = z3.Int(constraint.param)

        for constraint in constraints:
            var = z3_vars[constraint.param]
            value = constraint.value
            if constraint.predicate == Predicate.GEQ:
                solver.add(var >= value)
            elif constraint.predicate == Predicate.LEQ:
                solver.add(var <= value)
            elif constraint.predicate == Predicate.EQ:
                solver.add(var == value)
            elif constraint.predicate == Predicate.NEQ:
                solver.add(var != value)

        for param, value in param_values.items():
            if param in z3_vars:
                solver.add(z3_vars[param] == value)

        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            model_dict: Dict[str, Any] = {}
            for param, z3_var in z3_vars.items():
                z3_val = model.eval(z3_var)
                try:
                    model_dict[param] = z3_val.as_long()
                except Exception:
                    model_dict[param] = str(z3_val)
            return SolverResult.SAT, model_dict
        elif result == z3.unsat:
            return SolverResult.UNSAT, None
        else:
            return SolverResult.UNKNOWN, None

    def solve_for_param(
        self,
        expr: Expr,
        param_name: str,
        predicate: Predicate,
        threshold: Any
    ) -> Optional[Tuple[Predicate, Any]]:
        """
        使用 Z3 求解参数约束
        
        Args:
            expr: 表达式
            param_name: 参数名
            predicate: 谓词
            threshold: 阈值
            
        Returns:
            (新谓词, 新阈值) 或 None
        """
        if not self.available:
            return None
        
        import z3
        
        # 创建符号变量
        param = z3.Int(param_name)
        
        # 将 Expr 转换为 Z3 表达式
        z3_expr = self._expr_to_z3(expr, {param_name: param})
        if z3_expr is None:
            return None
        
        # 创建约束
        if predicate == Predicate.GEQ:
            constraint = z3_expr >= threshold
        elif predicate == Predicate.LEQ:
            constraint = z3_expr <= threshold
        elif predicate == Predicate.EQ:
            constraint = z3_expr == threshold
        else:
            return None
        
        # 简化约束
        simplified = z3.simplify(constraint)
        
        # TODO: 从简化结果中提取新的约束
        # 这需要解析 Z3 的输出
        
        return None
    
    def _expr_to_z3(self, expr: Expr, z3_vars: Dict[str, Any]) -> Optional[Any]:
        """将 Expr 转换为 Z3 表达式"""
        import z3
        
        if expr.type == ExprType.CONST:
            return expr.value
        
        elif expr.type == ExprType.PARAM:
            return z3_vars.get(expr.param)
        
        elif expr.type == ExprType.MUL:
            left = self._expr_to_z3(expr.left, z3_vars)
            right = self._expr_to_z3(expr.right, z3_vars)
            if left is not None and right is not None:
                return left * right
        
        elif expr.type == ExprType.ADD:
            left = self._expr_to_z3(expr.left, z3_vars)
            right = self._expr_to_z3(expr.right, z3_vars)
            if left is not None and right is not None:
                return left + right
        
        return None


# ============================================================================
# 混合求解器（Hybrid Solver）
# ============================================================================

class ConstraintSolver:
    """
    混合约束求解器
    
    自动选择最合适的求解器：
    1. 简单线性约束 → BuiltinSolver（快速）
    2. 复杂约束 → Z3Solver（如果可用）
    """
    
    def __init__(self, prefer_z3: bool = False, verbose: bool = False):
        """
        初始化求解器
        
        Args:
            prefer_z3: 是否优先使用 Z3（即使是简单约束）
            verbose: 是否输出详细信息
        """
        self.builtin = BuiltinSolver(verbose=verbose)
        self.z3 = Z3Solver(verbose=verbose)
        self.prefer_z3 = prefer_z3
        self.verbose = verbose
    
    def check_sat(
        self,
        constraints: List[ParamConstraint],
        param_values: Dict[str, Any]
    ) -> SolverResult:
        """
        检查约束可满足性
        
        Args:
            constraints: 约束列表
            param_values: 参数值
            
        Returns:
            SAT/UNSAT/UNKNOWN
        """
        # 检查所有约束中的参数是否都有值
        required_params = {c.param for c in constraints}
        missing_params = required_params - set(param_values.keys())
        
        if missing_params:
            # 有参数未知，返回 UNKNOWN
            return SolverResult.UNKNOWN
        
        # 优先使用 Z3（如果可用且用户偏好）
        if self.prefer_z3 and self.z3.available:
            if self.verbose:
                print("[求解器] 使用 Z3")
            return self.z3.check_sat(constraints, param_values)
        
        # 尝试使用自建求解器
        if self.verbose:
            print("[求解器] 使用自建求解器")
        result = self.builtin.check_sat(constraints, param_values)
        
        # 如果自建求解器返回 UNKNOWN（且不是因为参数缺失），且 Z3 可用，则使用 Z3
        if result == SolverResult.UNKNOWN and not missing_params and self.z3.available:
            if self.verbose:
                print("[求解器] 回退到 Z3")
            return self.z3.check_sat(constraints, param_values)
        
        return result
    
    def solve_for_param(
        self,
        expr: Expr,
        param_name: str,
        predicate: Predicate,
        threshold: Any
    ) -> Optional[Tuple[Predicate, Any]]:
        """
        求解单个参数的约束
        
        Args:
            expr: 表达式
            param_name: 参数名
            predicate: 谓词
            threshold: 阈值
            
        Returns:
            (新谓词, 新阈值) 或 None
        """
        # 判断是否是简单约束
        is_simple = self._is_simple_constraint(expr)
        
        if is_simple or not self.z3.available:
            # 使用自建求解器
            return self.builtin.solve_for_param(expr, param_name, predicate, threshold)
        else:
            # 使用 Z3
            return self.z3.solve_for_param(expr, param_name, predicate, threshold)
    
    def _is_simple_constraint(self, expr: Expr) -> bool:
        """判断是否是简单线性约束"""
        # CONST, PARAM 是简单的
        if expr.type in (ExprType.CONST, ExprType.PARAM):
            return True
        
        # MUL, ADD 如果操作数都是简单的，则也是简单的
        if expr.type in (ExprType.MUL, ExprType.ADD):
            left_simple = self._is_simple_constraint(expr.left)
            right_simple = self._is_simple_constraint(expr.right)
            return left_simple and right_simple
        
        # 其他类型是复杂的
        return False

    # ============================================================================
    # 6.2 路径约束求解
    # ============================================================================

    def solve_path_constraints(
        self,
        constraints: List[ParamConstraint]
    ) -> Tuple[SolverResult, Optional[Dict[str, Any]]]:
        """
        求解路径约束集合（6.2）

        判断沿某条执行路径收集的所有约束是否同时可满足，
        并在可满足时返回一组满足赋值（模型）。

        Args:
            constraints: 路径上积累的约束列表（每个约束均为 ParamConstraint）

        Returns:
            (SolverResult, model_dict)
            - SAT:    (SAT, {param: value, ...})     — 路径可达，含示例赋值
            - UNSAT:  (UNSAT, None)                  — 路径不可达（约束矛盾）
            - UNKNOWN:(UNKNOWN, None)                — 无法判断
        """
        if not constraints:
            return SolverResult.SAT, {}

        # 先尝试内置求解器快速路径
        all_params = {c.param for c in constraints}
        # 没有具体值时使用 Z3 符号求解
        if self.z3.available:
            return self.z3.solve_with_model(constraints, {})

        # Z3 不可用时，利用自建的纯值检查（用于单参数简单约束）
        # 对每个参数尝试构造候选值
        for param in all_params:
            param_constraints = [c for c in constraints if c.param == param]
            result = self.builtin.check_sat(param_constraints, {})
            if result == SolverResult.UNSAT:
                return SolverResult.UNSAT, None
        return SolverResult.UNKNOWN, None

    # ============================================================================
    # 6.3 约束简化与冲突检测
    # ============================================================================

    def simplify_constraints(
        self,
        constraints: List[ParamConstraint]
    ) -> List[ParamConstraint]:
        """
        约束简化（6.3 合并优化）

        合并同一参数上的冗余约束：
        - GEQ: 保留最大下界（最严格）
        - LEQ: 保留最小上界（最严格）
        - EQ:  重复相同值仅保留一条
        - NEQ: 全部保留（无法合并）

        Args:
            constraints: 原始约束列表

        Returns:
            简化后的约束列表
        """
        # 按 (param, predicate) 分组
        geq_bounds: Dict[str, Any] = {}    # param -> max lower bound
        leq_bounds: Dict[str, Any] = {}    # param -> min upper bound
        eq_values: Dict[str, Any] = {}     # param -> known eq value
        neq_list: List[ParamConstraint] = []

        for c in constraints:
            if c.predicate == Predicate.GEQ:
                if c.param not in geq_bounds or c.value > geq_bounds[c.param]:
                    geq_bounds[c.param] = c.value
            elif c.predicate == Predicate.LEQ:
                if c.param not in leq_bounds or c.value < leq_bounds[c.param]:
                    leq_bounds[c.param] = c.value
            elif c.predicate == Predicate.EQ:
                eq_values[c.param] = c.value  # 最后一条为准（冲突由 detect_conflicts 处理）
            elif c.predicate == Predicate.NEQ:
                neq_list.append(c)

        simplified: List[ParamConstraint] = []
        for param, bound in geq_bounds.items():
            simplified.append(ParamConstraint(param=param, predicate=Predicate.GEQ, value=bound))
        for param, bound in leq_bounds.items():
            simplified.append(ParamConstraint(param=param, predicate=Predicate.LEQ, value=bound))
        for param, val in eq_values.items():
            simplified.append(ParamConstraint(param=param, predicate=Predicate.EQ, value=val))
        simplified.extend(neq_list)

        return simplified

    def detect_conflicts(
        self,
        constraints: List[ParamConstraint]
    ) -> List[Tuple[ParamConstraint, ParamConstraint]]:
        """
        约束冲突检测（6.3 冲突检测）

        找出约束集中互相矛盾的约束对，例如：
        - x >= 2048 AND x <= 512  （下界 > 上界）
        - x == 128  AND x == 256  （两个不同等值）
        - x == 128  AND x != 128  （等值与不等冲突）
        - x >= 128  AND x == 64   （等值不满足下界）

        Args:
            constraints: 约束列表

        Returns:
            冲突对列表 [(c1, c2), ...]，若无冲突则为空列表
        """
        conflicts: List[Tuple[ParamConstraint, ParamConstraint]] = []

        for i, c1 in enumerate(constraints):
            for j, c2 in enumerate(constraints):
                if j <= i:
                    continue
                if c1.param != c2.param:
                    continue
                # 同一参数，检查矛盾
                if self._are_conflicting(c1, c2):
                    conflicts.append((c1, c2))

        return conflicts

    def _are_conflicting(
        self,
        c1: ParamConstraint,
        c2: ParamConstraint
    ) -> bool:
        """判断两条约束是否矛盾（假设作用于同一参数）"""
        p1, v1 = c1.predicate, c1.value
        p2, v2 = c2.predicate, c2.value

        # GEQ 与 LEQ 互斥：x >= v1 AND x <= v2，若 v1 > v2 则矛盾
        if p1 == Predicate.GEQ and p2 == Predicate.LEQ:
            return v1 > v2
        if p1 == Predicate.LEQ and p2 == Predicate.GEQ:
            return v2 > v1

        # 两个 EQ 值不同
        if p1 == Predicate.EQ and p2 == Predicate.EQ:
            return v1 != v2

        # EQ 与 NEQ 相同值
        if p1 == Predicate.EQ and p2 == Predicate.NEQ:
            return v1 == v2
        if p1 == Predicate.NEQ and p2 == Predicate.EQ:
            return v1 == v2

        # EQ 与 GEQ：x == v1 AND x >= v2，若 v1 < v2 则矛盾
        if p1 == Predicate.EQ and p2 == Predicate.GEQ:
            return v1 < v2
        if p1 == Predicate.GEQ and p2 == Predicate.EQ:
            return v2 < v1

        # EQ 与 LEQ：x == v1 AND x <= v2，若 v1 > v2 则矛盾
        if p1 == Predicate.EQ and p2 == Predicate.LEQ:
            return v1 > v2
        if p1 == Predicate.LEQ and p2 == Predicate.EQ:
            return v2 > v1

        return False
