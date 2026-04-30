"""
简单函数内联器 - 纯计算函数的内联求值

职责：
- 检测纯计算函数（单个 return，无副作用）
- 提取函数定义和返回表达式
- 执行参数替换（符号替换）
- 使用 Z3 求值替换后的表达式

限制：
- 仅支持单个 return 语句
- 仅支持算术表达式（无控制流）
- 不支持递归调用
- 不支持副作用（IO、全局变量修改等）

示例：
    def calc_keysize(security_level):
        return security_level * 16
    
    bits = calc_keysize(64)  
    → 内联为: bits = 64 * 16
    → Z3求值: bits = 1024
"""

from typing import Optional, Dict, Any, List
import re


class SimpleFunctionInliner:
    """
    简单函数内联器
    
    处理流程：
    1. 提取函数定义（函数名、参数列表、返回表达式）
    2. 检测函数调用
    3. 参数替换（将形参替换为实参）
    4. 表达式求值（使用 Z3）
    """
    
    def __init__(self, functions: List[Dict[str, Any]] = None):
        """
        Args:
            functions: 函数定义列表（从 features['functions'] 获取）
        """
        self.functions = functions or []
        self.function_map = self._build_function_map()
    
    def _build_function_map(self) -> Dict[str, Dict[str, Any]]:
        """构建函数名 → 函数定义的映射"""
        func_map = {}
        for func in self.functions:
            func_name = func.get('name', '')
            if func_name:
                func_map[func_name] = func
        return func_map
    
    def can_inline(self, func_name: str) -> bool:
        """
        判断函数是否可以内联
        
        条件：
        1. 函数存在于 function_map
        2. 有返回表达式（return语句）
        3. 仅有一个 return（可选检查）
        """
        if func_name not in self.function_map:
            return False
        
        func_def = self.function_map[func_name]
        
        # 检查是否有 return 表达式
        return_expr = func_def.get('return_expression')
        if not return_expr:
            return False
        
        # 简单检查：如果返回表达式包含复杂结构（if/for/while），不内联
        if any(keyword in return_expr for keyword in ['if ', 'for ', 'while ', 'raise ', 'yield ']):
            return False
        
        return True
    
    def inline_call(
        self,
        func_name: str,
        args: List[Any],
        use_z3: bool = True
    ) -> Optional[int]:
        """
        内联函数调用并求值
        
        Args:
            func_name: 函数名（如 'calc_keysize'）
            args: 实际参数列表（如 [64]）
            use_z3: 是否使用 Z3 求值（默认 True）
        
        Returns:
            函数返回值（整数），无法求值返回 None
        
        Example:
            >>> inliner.inline_call('calc_keysize', [64])
            1024  # calc_keysize(64) = 64 * 16 = 1024
        """
        if not self.can_inline(func_name):
            return None
        
        func_def = self.function_map[func_name]
        
        # 1. 获取形参列表和返回表达式
        params = func_def.get('params', [])
        return_expr = func_def.get('return_expression', '')
        
        if not return_expr:
            return None
        
        # 2. 参数数量检查
        if len(args) != len(params):
            # 参数数量不匹配
            return None
        
        # 3. 构建参数替换映射: 形参 → 实参
        param_map = {}
        for param_name, arg_value in zip(params, args):
            # 尝试将实参转换为可用的值
            if isinstance(arg_value, (int, float)):
                param_map[param_name] = arg_value
            elif isinstance(arg_value, str):
                # 尝试解析字符串为整数
                try:
                    param_map[param_name] = int(arg_value)
                except ValueError:
                    # 无法解析，保持原样
                    param_map[param_name] = arg_value
            else:
                param_map[param_name] = arg_value
        
        # 4. 执行参数替换
        substituted_expr = self._substitute_params(return_expr, param_map)
        
        print(f"[DEBUG SimpleFunctionInliner] Inlining {func_name}({args})")
        print(f"[DEBUG SimpleFunctionInliner]   Original: {return_expr}")
        print(f"[DEBUG SimpleFunctionInliner]   Params: {param_map}")
        print(f"[DEBUG SimpleFunctionInliner]   Substituted: {substituted_expr}")
        
        # 5. 求值替换后的表达式
        if use_z3:
            result = self._evaluate_with_z3(substituted_expr)
        else:
            result = self._evaluate_simple(substituted_expr)
        
        print(f"[DEBUG SimpleFunctionInliner]   Result: {result}")
        
        return result
    
    def _substitute_params(self, expr: str, param_map: Dict[str, Any]) -> str:
        """
        在表达式中替换参数
        
        使用词边界正则确保完整替换
        
        Example:
            expr = "security_level * 16"
            param_map = {"security_level": 64}
            → "64 * 16"
        """
        result = expr
        
        # 按参数名长度降序排序（避免部分匹配问题）
        sorted_params = sorted(param_map.items(), key=lambda x: len(x[0]), reverse=True)
        
        for param_name, param_value in sorted_params:
            # 使用词边界 \b 确保完整匹配
            pattern = r'\b' + re.escape(param_name) + r'\b'
            replacement = str(param_value)
            result = re.sub(pattern, replacement, result)
        
        return result
    
    def _evaluate_with_z3(self, expr: str) -> Optional[int]:
        """
        使用 Z3 求值表达式
        
        Args:
            expr: 算术表达式（如 "64 * 16"）
        
        Returns:
            表达式的值，无法求值返回 None
        """
        try:
            from pqscan.analysis.expression_evaluator import ExpressionEvaluator
            
            evaluator = ExpressionEvaluator(context={})
            result = evaluator.evaluate(expr)
            
            if isinstance(result, (int, float)):
                return int(result)
            
            return None
        except Exception as e:
            print(f"[DEBUG SimpleFunctionInliner] Z3 evaluation failed: {e}")
            return None
    
    def _evaluate_simple(self, expr: str) -> Optional[int]:
        """
        简单求值（不使用 Z3）
        
        尝试直接 eval，仅支持安全的算术表达式
        """
        try:
            # 安全检查：只允许数字、运算符、括号
            if not re.match(r'^[\d\s\+\-\*\/\%\(\)]+$', expr):
                return None
            
            result = eval(expr, {"__builtins__": {}}, {})
            
            if isinstance(result, (int, float)):
                return int(result)
            
            return None
        except Exception:
            return None


# ============================================================
# 便捷函数
# ============================================================

def inline_simple_function(
    func_name: str,
    args: List[Any],
    functions: List[Dict[str, Any]]
) -> Optional[int]:
    """
    便捷函数：内联简单函数调用
    
    Args:
        func_name: 函数名
        args: 实参列表
        functions: 函数定义列表
    
    Returns:
        函数返回值，无法内联返回 None
    """
    inliner = SimpleFunctionInliner(functions)
    return inliner.inline_call(func_name, args)
