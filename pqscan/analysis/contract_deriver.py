#!/usr/bin/env python3
"""
约束派生器（Contract Deriver）

从敏感点的约束派生封装函数的约束，支持线性变换。

核心功能：
1. 约束反向传播：从敏感点（Sink）向调用者传播
2. 线性变换求解：bytes * 8 >= 256 → bytes >= 32
3. 表达式替换：将 callee 的约束映射到 caller 的参数空间

示例：
  敏感点：RSA_generate_key(bits)
  约束：bits >= 2048
  
  封装函数：generate_rsa_key(bytes)
  调用：RSA_generate_key(bytes * 8)
  
  派生约束：bytes * 8 >= 2048 → bytes >= 256
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from pqscan.analysis.wrapper_summary import (
    Expr, ExprType, Effect, Contract, 
    ParamConstraint, StateConstraint, Predicate
)


class ContractDeriver:
    """
    约束派生器
    
    从敏感点的约束派生封装函数的约束
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def derive_contract(
        self,
        effect: Effect,
        sink_constraints: List[Dict[str, Any]],
        caller_params: List[str]
    ) -> Optional[Contract]:
        """
        从 Effect 和 sink 约束派生封装函数的约束
        
        Args:
            effect: 关键输入归因结果
            sink_constraints: 敏感点的约束列表（从 profile 获取）
            caller_params: 调用者函数的参数列表
            
        Returns:
            Contract 对象，如果无法派生则返回 None
        
        示例：
            effect.key_inputs = {
                'key_bits': Expr(type=MUL, left=Expr(PARAM, 'keylen'), right=Expr(CONST, 8))
            }
            sink_constraints = [
                {'field': 'key_bits', 'min': 256, 'pq_min': 3072}
            ]
            
            派生结果：
            Contract(param_constraints=[
                ParamConstraint(param='keylen', predicate='>=', value=32)  # 256/8
            ])
        """
        if not sink_constraints:
            return None
        
        param_constraints = []
        state_constraints = []
        
        # 遍历每个约束
        for constraint_spec in sink_constraints:
            field = constraint_spec.get('field')
            if not field:
                continue
            
            # 获取该字段的表达式
            expr = effect.key_inputs.get(field)
            if not expr:
                continue
            
            # 提取约束阈值（优先 pq_min，其次 min）
            threshold = constraint_spec.get('pq_min') or constraint_spec.get('min')
            if threshold is None:
                continue
            
            # 派生约束
            derived = self._derive_constraint_from_expr(
                expr=expr,
                predicate=Predicate.GEQ,
                threshold=threshold,
                caller_params=caller_params
            )
            
            if derived:
                param_constraints.extend(derived['param_constraints'])
                state_constraints.extend(derived['state_constraints'])
        
        if not param_constraints and not state_constraints:
            return None

        # 约束简化（Task 13.3.5 / 5.2）
        # 合并等价约束，减少重复与冗余，提升后续判定与传播效率。
        raw_param_count = len(param_constraints)
        raw_state_count = len(state_constraints)

        param_constraints = self._simplify_param_constraints(param_constraints)
        state_constraints = self._simplify_state_constraints(state_constraints)

        if self.verbose and (
            len(param_constraints) != raw_param_count
            or len(state_constraints) != raw_state_count
        ):
            print(
                f"    [约束简化] 参数约束 {raw_param_count} -> {len(param_constraints)}, "
                f"状态约束 {raw_state_count} -> {len(state_constraints)}"
            )
        
        return Contract(
            param_constraints=param_constraints,
            state_constraints=state_constraints
        )

    def _simplify_param_constraints(
        self,
        constraints: List[ParamConstraint]
    ) -> List[ParamConstraint]:
        """
        合并等价参数约束。

        规则：
        - 同参数 GEQ：保留最大阈值（更严格）
        - 同参数 LEQ：保留最小阈值（更严格）
        - 同参数 EQ/NEQ：去重
        - 其余保持原语义并去重
        """
        if not constraints:
            return []

        grouped: Dict[str, List[ParamConstraint]] = {}
        for item in constraints:
            grouped.setdefault(item.param, []).append(item)

        simplified: List[ParamConstraint] = []

        for param, items in grouped.items():
            geq_values: List[Any] = []
            leq_values: List[Any] = []
            eq_values: List[Any] = []
            neq_values: List[Any] = []
            passthrough: List[ParamConstraint] = []

            for item in items:
                if item.predicate == Predicate.GEQ:
                    geq_values.append(item.value)
                elif item.predicate == Predicate.LEQ:
                    leq_values.append(item.value)
                elif item.predicate == Predicate.EQ:
                    eq_values.append(item.value)
                elif item.predicate == Predicate.NEQ:
                    neq_values.append(item.value)
                else:
                    passthrough.append(item)

            # GEQ: 保留最大值
            numeric_geq = [v for v in geq_values if isinstance(v, (int, float))]
            if numeric_geq:
                simplified.append(ParamConstraint(
                    param=param,
                    predicate=Predicate.GEQ,
                    value=max(numeric_geq)
                ))

            # LEQ: 保留最小值
            numeric_leq = [v for v in leq_values if isinstance(v, (int, float))]
            if numeric_leq:
                simplified.append(ParamConstraint(
                    param=param,
                    predicate=Predicate.LEQ,
                    value=min(numeric_leq)
                ))

            # EQ/NEQ: 去重保留
            for eqv in sorted(set(eq_values), key=lambda x: str(x)):
                simplified.append(ParamConstraint(
                    param=param,
                    predicate=Predicate.EQ,
                    value=eqv
                ))

            for neqv in sorted(set(neq_values), key=lambda x: str(x)):
                simplified.append(ParamConstraint(
                    param=param,
                    predicate=Predicate.NEQ,
                    value=neqv
                ))

            # 其他谓词去重
            seen = set()
            for item in passthrough:
                key = (item.param, item.predicate, item.value)
                if key in seen:
                    continue
                seen.add(key)
                simplified.append(item)

        return simplified

    def _simplify_state_constraints(
        self,
        constraints: List[StateConstraint]
    ) -> List[StateConstraint]:
        """
        合并等价状态约束。

        规则与参数约束一致，但分组键为 (obj, field)。
        """
        if not constraints:
            return []

        grouped: Dict[str, List[StateConstraint]] = {}
        for item in constraints:
            key = f"{item.obj}.{item.field}"
            grouped.setdefault(key, []).append(item)

        simplified: List[StateConstraint] = []

        for key, items in grouped.items():
            obj = items[0].obj
            field = items[0].field

            geq_values: List[Any] = []
            leq_values: List[Any] = []
            eq_values: List[Any] = []
            neq_values: List[Any] = []
            passthrough: List[StateConstraint] = []

            for item in items:
                if item.predicate == Predicate.GEQ:
                    geq_values.append(item.value)
                elif item.predicate == Predicate.LEQ:
                    leq_values.append(item.value)
                elif item.predicate == Predicate.EQ:
                    eq_values.append(item.value)
                elif item.predicate == Predicate.NEQ:
                    neq_values.append(item.value)
                else:
                    passthrough.append(item)

            numeric_geq = [v for v in geq_values if isinstance(v, (int, float))]
            if numeric_geq:
                simplified.append(StateConstraint(
                    obj=obj,
                    field=field,
                    predicate=Predicate.GEQ,
                    value=max(numeric_geq)
                ))

            numeric_leq = [v for v in leq_values if isinstance(v, (int, float))]
            if numeric_leq:
                simplified.append(StateConstraint(
                    obj=obj,
                    field=field,
                    predicate=Predicate.LEQ,
                    value=min(numeric_leq)
                ))

            for eqv in sorted(set(eq_values), key=lambda x: str(x)):
                simplified.append(StateConstraint(
                    obj=obj,
                    field=field,
                    predicate=Predicate.EQ,
                    value=eqv
                ))

            for neqv in sorted(set(neq_values), key=lambda x: str(x)):
                simplified.append(StateConstraint(
                    obj=obj,
                    field=field,
                    predicate=Predicate.NEQ,
                    value=neqv
                ))

            seen = set()
            for item in passthrough:
                uniq = (item.obj, item.field, item.predicate, item.value)
                if uniq in seen:
                    continue
                seen.add(uniq)
                simplified.append(item)

        return simplified
    
    def _derive_constraint_from_expr(
        self,
        expr: Expr,
        predicate: Predicate,
        threshold: Any,
        caller_params: List[str]
    ) -> Optional[Dict[str, List]]:
        """
        从表达式派生约束
        
        支持的变换：
        - CONST: 常量检查
        - PARAM: 直接映射
        - MUL: 线性变换（除法）
        - ADD: 线性变换（减法）
        - STATE: 状态约束
        - UNION: 候选约束（OR）
        
        Args:
            expr: 表达式
            predicate: 原始谓词（>=）
            threshold: 原始阈值
            caller_params: 调用者参数列表
            
        Returns:
            {'param_constraints': [...], 'state_constraints': [...]}
        """
        param_constraints = []
        state_constraints = []
        
        # 1. 常量表达式：直接检查
        if expr.type == ExprType.CONST:
            # 常量检查（静态验证）
            if predicate == Predicate.GEQ:
                if expr.value < threshold:
                    # UNSAT：常量不满足约束
                    if self.verbose:
                        print(f"    [约束冲突] 常量 {expr.value} < {threshold}")
            return None  # 常量不需要派生约束
        
        # 2. 参数表达式：直接映射
        if expr.type == ExprType.PARAM:
            if expr.param in caller_params:
                param_constraints.append(ParamConstraint(
                    param=expr.param,
                    predicate=predicate,
                    value=threshold
                ))
                if self.verbose:
                    print(f"    [派生] {expr.param} {predicate.value} {threshold}")
        
        # 3. 乘法表达式：反向求解
        elif expr.type == ExprType.MUL:
            # bytes * 8 >= 256 → bytes >= 32
            derived = self._solve_mul_constraint(
                expr, predicate, threshold, caller_params
            )
            if derived:
                param_constraints.extend(derived)
        
        # 4. 加法表达式：反向求解
        elif expr.type == ExprType.ADD:
            # (param + c) >= threshold → param >= (threshold - c)
            derived = self._solve_add_constraint(
                expr, predicate, threshold, caller_params
            )
            if derived:
                param_constraints.extend(derived)
        
        # 5. 状态表达式：派生状态约束
        elif expr.type == ExprType.STATE:
            state_constraints.append(StateConstraint(
                obj=expr.obj,
                field=expr.field,
                predicate=predicate,
                value=threshold
            ))
            if self.verbose:
                print(f"    [派生状态] {expr.obj}.{expr.field} {predicate.value} {threshold}")
        
        # 6. UNION 表达式：候选约束（OR）
        elif expr.type == ExprType.UNION:
            # 对每个候选派生约束
            for candidate in expr.candidates:
                derived = self._derive_constraint_from_expr(
                    candidate, predicate, threshold, caller_params
                )
                if derived:
                    param_constraints.extend(derived['param_constraints'])
                    state_constraints.extend(derived['state_constraints'])
        
        return {
            'param_constraints': param_constraints,
            'state_constraints': state_constraints
        }
    
    def _solve_mul_constraint(
        self,
        expr: Expr,
        predicate: Predicate,
        threshold: Any,
        caller_params: List[str]
    ) -> List[ParamConstraint]:
        """
        求解乘法约束
        
        支持模式：
        - param * const >= threshold → param >= threshold / const
        - const * param >= threshold → param >= threshold / const
        
        Args:
            expr: MUL 表达式
            predicate: 谓词（>=）
            threshold: 阈值
            caller_params: 参数列表
            
        Returns:
            派生的参数约束列表
        """
        constraints = []
        
        # 检查 left * right
        left, right = expr.left, expr.right
        
        # Case 1: param * const
        if left.type == ExprType.PARAM and right.type == ExprType.CONST:
            param_name = left.param
            multiplier = right.value
            
            if param_name in caller_params and multiplier > 0:
                if predicate == Predicate.GEQ:
                    # param * multiplier >= threshold
                    # → param >= ceil(threshold / multiplier)
                    derived_threshold = -(-threshold // multiplier)  # 向上取整
                    constraints.append(ParamConstraint(
                        param=param_name,
                        predicate=Predicate.GEQ,
                        value=derived_threshold
                    ))
                    if self.verbose:
                        print(f"    [乘法求解] {param_name} * {multiplier} >= {threshold}")
                        print(f"              → {param_name} >= {derived_threshold}")
        
        # Case 2: const * param
        elif left.type == ExprType.CONST and right.type == ExprType.PARAM:
            param_name = right.param
            multiplier = left.value
            
            if param_name in caller_params and multiplier > 0:
                if predicate == Predicate.GEQ:
                    derived_threshold = -(-threshold // multiplier)
                    constraints.append(ParamConstraint(
                        param=param_name,
                        predicate=Predicate.GEQ,
                        value=derived_threshold
                    ))
        
        return constraints
    
    def _solve_add_constraint(
        self,
        expr: Expr,
        predicate: Predicate,
        threshold: Any,
        caller_params: List[str]
    ) -> List[ParamConstraint]:
        """
        求解加法约束
        
        支持模式：
        - param + const >= threshold → param >= threshold - const
        - const + param >= threshold → param >= threshold - const
        
        Args:
            expr: ADD 表达式
            predicate: 谓词（>=）
            threshold: 阈值
            caller_params: 参数列表
            
        Returns:
            派生的参数约束列表
        """
        constraints = []
        
        left, right = expr.left, expr.right
        
        # Case 1: param + const
        if left.type == ExprType.PARAM and right.type == ExprType.CONST:
            param_name = left.param
            addend = right.value
            
            if param_name in caller_params:
                if predicate == Predicate.GEQ:
                    # param + addend >= threshold
                    # → param >= threshold - addend
                    derived_threshold = threshold - addend
                    constraints.append(ParamConstraint(
                        param=param_name,
                        predicate=Predicate.GEQ,
                        value=derived_threshold
                    ))
                    if self.verbose:
                        print(f"    [加法求解] {param_name} + {addend} >= {threshold}")
                        print(f"              → {param_name} >= {derived_threshold}")
        
        # Case 2: const + param
        elif left.type == ExprType.CONST and right.type == ExprType.PARAM:
            param_name = right.param
            addend = left.value
            
            if param_name in caller_params:
                if predicate == Predicate.GEQ:
                    derived_threshold = threshold - addend
                    constraints.append(ParamConstraint(
                        param=param_name,
                        predicate=Predicate.GEQ,
                        value=derived_threshold
                    ))
        
        return constraints
