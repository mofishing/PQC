#!/usr/bin/env python3
"""
Task 13.3: Wrapper 约束传播实现

基于已有的 wrapper_summary 和 propagation_graph，实现封装约束传播。
不直接跨函数追溯变量，而是：
1. 为每个wrapper函数生成Contract（约束）
2. 将Contract传播到调用链
3. 在检测时应用Contract判断是否违反约束

设计思路：
- 为wrapper生成Effect（关键输入归因）+ Contract（派生约束）
- 使用CallersIndex构建调用链
- 传播约束时累积参数变换
"""

from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from pqscan.analysis.wrapper_summary import (
    Effect, Contract, CallSite, CallersIndex,
    ParamConstraint, Predicate, InputSource, Expr, ExprType
)
from pqscan.abstract_syntax_tree import extract_features


@dataclass
class WrapperContract:
    """Wrapper函数的约束"""
    function_name: str
    effect: Effect  # 关键输入归因
    contract: Contract  # 派生约束
    param_mapping: Dict[str, str]  # 参数映射 {"arg0": "bits", "arg1": "..."}


class WrapperContractGenerator:
    """为wrapper函数生成约束"""
    
    def __init__(self, features: Dict[str, Any]):
        """
        Args:
            features: extract_features() 返回的特征
        """
        self.features = features
        self.functions = features.get('functions', [])
        self.calls = features.get('calls', [])
        self.var_assignments = features.get('var_assignments', [])
    
    def generate_contract_for_wrapper(
        self,
        wrapper_name: str,
        sensitive_api: str,
        sensitive_profile: str
    ) -> Optional[WrapperContract]:
        """
        为wrapper函数生成contract
        
        Args:
            wrapper_name: wrapper函数名 (如 "generate_key")
            sensitive_api: 敏感API (如 "RSA.generate")
            sensitive_profile: 敏感点profile (如 "ALG.RSA")
        
        Returns:
            WrapperContract 或 None
        """
        # 1. 查找wrapper函数定义
        wrapper_func = None
        for func in self.functions:
            if func.get('name') == wrapper_name:
                wrapper_func = func
                break
        
        if not wrapper_func:
            return None
        
        # 2. 查找wrapper内部对敏感API的调用
        sensitive_call = None
        wrapper_start = wrapper_func.get('start_line')
        wrapper_end = wrapper_func.get('end_line')
        
        for call in self.calls:
            call_line = call.get('line')
            if (wrapper_start <= call_line <= wrapper_end and
                sensitive_api in call.get('symbol', '')):
                sensitive_call = call
                break
        
        if not sensitive_call:
            return None
        
        # 3. 提取关键输入（敏感API的参数）
        call_args = sensitive_call.get('args', [])
        key_inputs = {}
        param_mapping = {}
        
        # 提取wrapper的参数列表
        wrapper_params = wrapper_func.get('params', [])
        
        # 分析敏感API调用的参数
        for i, arg in enumerate(call_args):
            arg_value = arg.get('value')
            if isinstance(arg_value, str):
                # 检查是否是wrapper的参数
                if arg_value in wrapper_params:
                    # 参数直接传递
                    key_inputs[f'arg{i}'] = Expr(
                        type=ExprType.PARAM,
                        value=arg_value,
                        repr=arg_value
                    )
                    param_mapping[f'arg{i}'] = arg_value
                else:
                    # 可能是表达式（如 arg_value * 8）
                    # 这里简化处理，标记为参数依赖
                    key_inputs[f'arg{i}'] = Expr(
                        type=ExprType.PARAM,
                        value=arg_value,
                        repr=arg_value
                    )
            elif isinstance(arg_value, int):
                # 常量
                key_inputs[f'arg{i}'] = Expr(
                    type=ExprType.CONST,
                    value=arg_value,
                    repr=str(arg_value)
                )
        
        # 4. 生成Effect
        effect = Effect(
            sink_profile_id=sensitive_profile,
            key_inputs=key_inputs,
            input_sources={
                k: InputSource.PARAM_DEP for k in key_inputs.keys()
            }
        )
        
        # 5. 生成Contract（派生约束）
        # 假设RSA密钥长度需要 >= 2048
        param_constraints = []
        for param_name in param_mapping.values():
            param_constraints.append(
                ParamConstraint(
                    param=param_name,
                    predicate=Predicate.GEQ,
                    value=2048
                )
            )
        
        contract = Contract(param_constraints=param_constraints)
        
        return WrapperContract(
            function_name=wrapper_name,
            effect=effect,
            contract=contract,
            param_mapping=param_mapping
        )
    
    def analyze_call_chain(
        self,
        entry_call: Dict[str, Any]
    ) -> List[WrapperContract]:
        """
        分析调用链，收集所有wrapper contracts
        
        Args:
            entry_call: 入口调用点（如对wrapper的调用）
        
        Returns:
            调用链上的所有wrapper contracts
        """
        contracts = []
        
        # TODO: 递归分析调用链
        # 1. 如果entry_call是wrapper，生成contract
        # 2. 查找wrapper内部的调用
        # 3. 递归分析
        
        return contracts


class WrapperContractEvaluator:
    """应用wrapper约束进行检测"""
    
    def __init__(self, contracts: List[WrapperContract]):
        self.contracts = {c.function_name: c for c in contracts}
    
    def check_call(
        self,
        function_name: str,
        arg_values: List[Any]
    ) -> Optional[Dict[str, Any]]:
        """
        检查函数调用是否违反约束
        
        Args:
            function_name: 被调函数名
            arg_values: 实参值列表
        
        Returns:
            检测结果或None
        """
        contract = self.contracts.get(function_name)
        if not contract:
            return None
        
        # 构建参数字典
        param_values = {}
        for arg_idx, param_name in contract.param_mapping.items():
            idx = int(arg_idx.replace('arg', ''))
            if idx < len(arg_values):
                param_values[param_name] = arg_values[idx]
        
        # 判断约束是否满足
        is_sat = contract.contract.is_sat(param_values, {})
        
        if is_sat is False:  # UNSAT - 违反约束
            # 找出违反的约束
            violations = []
            for constraint in contract.contract.param_constraints:
                value = param_values.get(constraint.param)
                if value is not None:
                    if constraint.predicate == Predicate.GEQ and value < constraint.value:
                        violations.append({
                            'param': constraint.param,
                            'expected': f'>= {constraint.value}',
                            'actual': value
                        })
            
            return {
                'violated': True,
                'violations': violations,
                'profile_id': contract.effect.sink_profile_id
            }
        
        return None


# ==============================================================================
# 使用示例
# ==============================================================================

def example_usage():
    """示例：如何使用wrapper contract"""
    code = '''
def generate_key(bits):
    return RSA.generate(bits)

key = generate_key(1024)  # WEAK
'''
    
    # 1. 提取特征
    features = extract_features(code, 'python')
    
    # 2. 生成wrapper contract
    generator = WrapperContractGenerator(features)
    contract = generator.generate_contract_for_wrapper(
        wrapper_name='generate_key',
        sensitive_api='RSA.generate',
        sensitive_profile='ALG.RSA'
    )
    
    if contract:
        print(f"Generated contract for {contract.function_name}")
        print(f"  Effect: {contract.effect}")
        print(f"  Contract: {contract.contract}")
        
        # 3. 应用contract检查调用
        evaluator = WrapperContractEvaluator([contract])
        result = evaluator.check_call('generate_key', [1024])
        
        if result and result['violated']:
            print(f"  VIOLATION DETECTED!")
            print(f"    Violations: {result['violations']}")
    else:
        print("Failed to generate contract")


if __name__ == '__main__':
    example_usage()
