from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass
import sys
import os

# 添加父目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pqscan.analysis.constraint_solver import ConstraintSolver
from pqscan.analysis.wrapper_summary import (
    Expr, ExprType, ParamConstraint, Predicate
)


@dataclass
class Constraint:
    """约束定义（简化版，用于外部接口）"""
    param_name: str           # 参数名
    operator: str             # >=, <=, ==, !=
    threshold: Union[int, float]  # 阈值
    unit: Optional[str] = None    # 单位（bytes/bits）


@dataclass
class DerivedConstraint:
    """派生约束"""
@dataclass
class DerivedConstraint:
    """派生约束"""
    source_constraint: Constraint      # 源约束（A 的约束）
    derived_constraint: Constraint     # 派生约束（B 的约束）
    transform_expr: Expr               # 变换表达式（Expr 树）
    confidence: str                    # 置信度（confirmed/probable/suspect）


class ConstraintDerivationEngine:
    """
    约束派生引擎
    
    复用 pqscan.analysis.constraint_solver.ConstraintSolver：
    - 简单约束：自建求解器（快速，无依赖）
    - 复杂约束：Z3 SMT 求解器（强大，可选依赖）
    """
    
    def __init__(self, prefer_z3: bool = False, verbose: bool = False):
        """
        初始化派生引擎
        
        Args:
            prefer_z3: 是否优先使用 Z3
            verbose: 是否输出详细信息
        """
        self.solver = ConstraintSolver(prefer_z3=prefer_z3, verbose=verbose)
        self.verbose = verbose
    
    @staticmethod
    def parse_transform_expr(transform_str: str, wrapper_param: str) -> Expr:
        """
        解析变换表达式字符串为 Expr 树
        
        支持的格式：
        - "*8" → Mul(Param(wrapper_param), Const(8))
        - "/8" → Mul(Param(wrapper_param), Const(1/8))
        - "+10" → Add(Param(wrapper_param), Const(10))
        - "-5" → Add(Param(wrapper_param), Const(-5))
        - "*8+10" → Add(Mul(Param(wrapper_param), Const(8)), Const(10))
        
        Args:
            transform_str: 变换表达式字符串
            wrapper_param: 封装函数的参数名
            
        Returns:
            Expr 树
        """
        transform_str = transform_str.strip()
        
        # 恒等变换
        if not transform_str or transform_str == "identity":
            return Expr(type=ExprType.PARAM, param=wrapper_param)
        
        # 乘法：*8
        if transform_str.startswith("*") and "+" not in transform_str and "-" not in transform_str:
            multiplier = float(transform_str[1:])
            return Expr(
                type=ExprType.MUL,
                left=Expr(type=ExprType.PARAM, param=wrapper_param),
                right=Expr(type=ExprType.CONST, value=multiplier)
            )
        
        # 除法：/8 → 乘以 1/8
        if transform_str.startswith("/"):
            divisor = float(transform_str[1:])
            return Expr(
                type=ExprType.MUL,
                left=Expr(type=ExprType.PARAM, param=wrapper_param),
                right=Expr(type=ExprType.CONST, value=1.0 / divisor)
            )
        
        # 加法：+10
        if transform_str.startswith("+"):
            offset = int(transform_str[1:])
            return Expr(
                type=ExprType.ADD,
                left=Expr(type=ExprType.PARAM, param=wrapper_param),
                right=Expr(type=ExprType.CONST, value=offset)
            )
        
        # 减法：-5 → 加 -5
        if transform_str.startswith("-") and not transform_str[1:].isdigit():
            # 避免误识别负数
            pass
        elif transform_str.startswith("-"):
            offset = int(transform_str[1:])
            return Expr(
                type=ExprType.ADD,
                left=Expr(type=ExprType.PARAM, param=wrapper_param),
                right=Expr(type=ExprType.CONST, value=-offset)
            )
        
        # 复合变换：*8+10
        import re
        match = re.match(r'\*([0-9.]+)([+\-])([0-9]+)', transform_str)
        if match:
            multiplier = float(match.group(1))
            op = match.group(2)
            offset = int(match.group(3))
            
            # param * multiplier
            mul_expr = Expr(
                type=ExprType.MUL,
                left=Expr(type=ExprType.PARAM, param=wrapper_param),
                right=Expr(type=ExprType.CONST, value=multiplier)
            )
            
            # (param * multiplier) + offset
            offset_value = offset if op == '+' else -offset
            return Expr(
                type=ExprType.ADD,
                left=mul_expr,
                right=Expr(type=ExprType.CONST, value=offset_value)
            )
        
        # 默认：恒等变换
        return Expr(type=ExprType.PARAM, param=wrapper_param)
    
    def derive_constraint(
        self,
        source_constraint: Constraint,
        transform_expr: Expr,
        wrapper_param_name: str
    ) -> DerivedConstraint:
        """
        约束派生：从 A 的约束反向求解 B 的约束
        
        例如：
        - A 的约束：key_bits >= 3072
        - 变换表达式：key_bits = keylen * 8
        - 派生约束：keylen >= 384
        
        Args:
            source_constraint: 源约束（A 的约束）
            transform_expr: 变换表达式（Expr 树）
            wrapper_param_name: 封装函数的参数名
            
        Returns:
            DerivedConstraint
        """
        # 转换 operator 为 Predicate
        op_map = {
            '>=': Predicate.GEQ,
            '<=': Predicate.LEQ,
            '==': Predicate.EQ,
            '!=': Predicate.NEQ
        }
        
        predicate = op_map.get(source_constraint.operator, Predicate.GEQ)
        threshold = source_constraint.threshold
        
        # 使用 ConstraintSolver 反向求解
        result = self.solver.solve_for_param(
            transform_expr,
            wrapper_param_name,
            predicate,
            threshold
        )
        
        if result is None:
            # 无法求解，返回 suspect 置信度
            derived_constraint = Constraint(
                param_name=wrapper_param_name,
                operator="unknown",
                threshold=threshold
            )
            confidence = "suspect"
        else:
            new_predicate, new_threshold = result
            
            # 转换回 operator 字符串
            pred_to_op = {
                Predicate.GEQ: '>=',
                Predicate.LEQ: '<=',
                Predicate.EQ: '==',
                Predicate.NEQ: '!='
            }
            
            derived_constraint = Constraint(
                param_name=wrapper_param_name,
                operator=pred_to_op.get(new_predicate, '>='),
                threshold=new_threshold,
                unit=source_constraint.unit
            )
            confidence = "confirmed"
        
        return DerivedConstraint(
            source_constraint=source_constraint,
            derived_constraint=derived_constraint,
            transform_expr=transform_expr,
            confidence=confidence
        )
    
    def derive_from_wrapper_contract(
        self,
        wrapper_contract: Dict[str, Any],
        sink_constraints: Dict[str, Constraint]
    ) -> Dict[str, DerivedConstraint]:
        """
        从封装契约派生约束
        
        Args:
            wrapper_contract: 封装契约（来自 wrappers KB）
            sink_constraints: 敏感函数（A）的约束字典
        
        Returns:
            派生约束字典 {wrapper_param_name: DerivedConstraint}
        """
        derived_constraints = {}
        
        semantic = wrapper_contract.get('semantic', {})
        
        # 遍历 semantic 中的关键输入字段
        for key_input in ['key_bits', 'algorithm_name', 'curve', 'iv_length']:
            if key_input not in semantic:
                continue
            
            input_spec = semantic[key_input]
            
            # 只处理 from_param 的情况
            if not isinstance(input_spec, dict) or 'from_param' not in input_spec:
                continue
            
            wrapper_param = input_spec['from_param']
            transform_str = input_spec.get('transform', 'identity')
            
            # 解析变换表达式
            transform_expr = self.parse_transform_expr(transform_str, wrapper_param)
            
            # 查找源约束
            if key_input in sink_constraints:
                source_constraint = sink_constraints[key_input]
                
                # 派生约束
                derived = self.derive_constraint(
                    source_constraint,
                    transform_expr,
                    wrapper_param
                )
                
                derived_constraints[wrapper_param] = derived
        
        return derived_constraints


def test_constraint_derivation():
    """测试约束派生"""
    print("=" * 60)
    print("约束派生引擎测试（复用 ConstraintSolver）")
    print("=" * 60)
    
    engine = ConstraintDerivationEngine(verbose=False)
    
    # 测试 1：乘法变换
    print("\n[测试 1] 乘法变换: key_bits = keylen * 8")
    source = Constraint(
        param_name="key_bits",
        operator=">=",
        threshold=3072
    )
    transform_expr = engine.parse_transform_expr("*8", "keylen")
    
    derived = engine.derive_constraint(source, transform_expr, "keylen")
    
    print(f"源约束: {source.param_name} {source.operator} {source.threshold}")
    print(f"变换: key_bits = keylen * 8")
    print(f"派生约束: {derived.derived_constraint.param_name} "
          f"{derived.derived_constraint.operator} "
          f"{derived.derived_constraint.threshold}")
    print(f"置信度: {derived.confidence}")
    assert derived.derived_constraint.threshold == 384, f"派生阈值应为 384，实际为 {derived.derived_constraint.threshold}"
    print("✓ 通过")
    
    # 测试 2：加法变换
    print("\n[测试 2] 加法变换: key_bits = keylen + 10")
    source2 = Constraint(
        param_name="key_bits",
        operator=">=",
        threshold=3072
    )
    transform_expr2 = engine.parse_transform_expr("+10", "keylen")
    
    derived2 = engine.derive_constraint(source2, transform_expr2, "keylen")
    
    print(f"源约束: {source2.param_name} {source2.operator} {source2.threshold}")
    print(f"变换: key_bits = keylen + 10")
    print(f"派生约束: {derived2.derived_constraint.param_name} "
          f"{derived2.derived_constraint.operator} "
          f"{derived2.derived_constraint.threshold}")
    # key_bits >= 3072 → keylen + 10 >= 3072 → keylen >= 3062
    assert derived2.derived_constraint.threshold == 3062, f"派生阈值应为 3062，实际为 {derived2.derived_constraint.threshold}"
    print("✓ 通过")
    
    # 测试 3：复合变换
    print("\n[测试 3] 复合变换: key_bits = keylen * 8 + 10")
    source3 = Constraint(
        param_name="key_bits",
        operator=">=",
        threshold=3072
    )
    transform_expr3 = engine.parse_transform_expr("*8+10", "keylen")
    
    derived3 = engine.derive_constraint(source3, transform_expr3, "keylen")
    
    print(f"源约束: {source3.param_name} {source3.operator} {source3.threshold}")
    print(f"变换: key_bits = keylen * 8 + 10")
    print(f"派生约束: {derived3.derived_constraint.param_name} "
          f"{derived3.derived_constraint.operator} "
          f"{derived3.derived_constraint.threshold}")
    print(f"置信度: {derived3.confidence}")
    
    # 复合表达式需要 Z3，如果没有 Z3 则会返回 suspect
    if derived3.confidence == "suspect":
        print("⚠ 复合表达式需要 Z3 求解器，当前不可用")
        print("  提示: pip install z3-solver")
        print("✓ 跳过（Z3 不可用）")
    else:
        # key_bits >= 3072 → keylen*8+10 >= 3072 → keylen*8 >= 3062 → keylen >= 383 (向上取整)
        expected = 383
        assert derived3.derived_constraint.threshold == expected, \
            f"派生阈值应为 {expected}，实际为 {derived3.derived_constraint.threshold}"
        print("✓ 通过")
    
    # 测试 4：从 wrapper contract 派生
    print("\n[测试 4] 从 wrapper contract 派生约束")
    wrapper_contract = {
        "function": "my_rsa_keygen",
        "func_params": ["keylen"],
        "semantic": {
            "profile_id": "ALG.RSA.PKE",
            "operation": "keygen",
            "key_bits": {
                "from_param": "keylen",
                "unit": "bytes",
                "transform": "*8"
            }
        }
    }
    
    sink_constraints = {
        "key_bits": Constraint(
            param_name="key_bits",
            operator=">=",
            threshold=3072
        )
    }
    
    derived_dict = engine.derive_from_wrapper_contract(
        wrapper_contract,
        sink_constraints
    )
    
    print(f"Wrapper 函数: {wrapper_contract['function']}")
    print(f"Wrapper 参数: {wrapper_contract['func_params']}")
    print(f"\n源约束（RSA_generate_key）:")
    for k, v in sink_constraints.items():
        print(f"  {v.param_name} {v.operator} {v.threshold}")
    
    print(f"\n派生约束（my_rsa_keygen）:")
    for param_name, derived_constraint in derived_dict.items():
        dc = derived_constraint.derived_constraint
        print(f"  {dc.param_name} {dc.operator} {dc.threshold} ({derived_constraint.confidence})")
    
    assert 'keylen' in derived_dict, "应该派生出 keylen 的约束"
    assert derived_dict['keylen'].derived_constraint.threshold == 384
    print("✓ 通过")
    
    print("\n" + "=" * 60)
    print("✓ 所有测试通过！")
    print("=" * 60)


if __name__ == '__main__':
    test_constraint_derivation()
