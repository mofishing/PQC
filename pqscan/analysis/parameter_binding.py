#!/usr/bin/env python3
"""
参数绑定提取器 v2（无正则版本）

使用简单的字符串分析代替正则表达式，更清晰、更易维护。

支持的表达式：
- 常量：256, 1024
- 变量：x, keylen
- 乘法：x*8, 8*x
- 加法：x+10
- 减法：x-10

不支持复杂嵌套，但足够处理 90% 的实际情况。
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ParamBinding:
    """参数绑定"""
    target_param: str                  # 目标参数（如 param_0）
    source_param: Optional[str] = None # 源参数（如 keylen）
    transform: Optional[str] = None    # 变换（如 *8）
    is_constant: bool = False
    constant_value: Optional[Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"target_param": self.target_param}
        if self.is_constant:
            result["constant"] = self.constant_value
        else:
            if self.source_param:
                result["source_param"] = self.source_param
            if self.transform:
                result["transform"] = self.transform
        return result


class SimpleExpressionParser:
    """简单表达式解析器（不使用正则）"""
    
    @staticmethod
    def parse(expr: str) -> Dict[str, Any]:
        """
        解析表达式
        
        Args:
            expr: 表达式字符串（如 "keylen*8"）
        
        Returns:
            {
                "type": "constant" | "variable" | "binary_op",
                "value": ...,
                "left": ...,
                "op": ...,
                "right": ...
            }
        """
        expr = expr.strip()
        
        # 1. 常量（十进制和十六进制）
        if expr.isdigit():
            return {"type": "constant", "value": int(expr)}
        
        if expr.startswith(("0x", "0X")):
            try:
                return {"type": "constant", "value": int(expr, 16)}
            except ValueError:
                pass
        
        # 2. 查找运算符（从右到左，处理优先级）
        # 先找加减（低优先级）
        for i in range(len(expr) - 1, -1, -1):
            if expr[i] in ('+', '-'):
                left = expr[:i].strip()
                right = expr[i+1:].strip()
                if left and right:  # 确保不是一元运算符
                    return {
                        "type": "binary_op",
                        "op": expr[i],
                        "left": SimpleExpressionParser.parse(left),
                        "right": SimpleExpressionParser.parse(right)
                    }
        
        # 再找乘除（高优先级）
        for i in range(len(expr) - 1, -1, -1):
            if expr[i] in ('*', '/'):
                left = expr[:i].strip()
                right = expr[i+1:].strip()
                if left and right:
                    return {
                        "type": "binary_op",
                        "op": expr[i],
                        "left": SimpleExpressionParser.parse(left),
                        "right": SimpleExpressionParser.parse(right)
                    }
        
        # 3. 括号（简化处理：只处理最外层括号）
        if expr.startswith('(') and expr.endswith(')'):
            return SimpleExpressionParser.parse(expr[1:-1])
        
        # 4. 变量
        if expr.isidentifier():
            return {"type": "variable", "name": expr}
        
        # 5. 无法解析
        return {"type": "unknown", "expr": expr}


class ParameterBindingExtractor:
    """参数绑定提取器（简化版）"""
    
    def __init__(self, verbose: bool = False):
        """
        初始化提取器
        
        Args:
            verbose: 是否输出调试信息
        """
        self.parser = SimpleExpressionParser()
        self.verbose = verbose
    
    def extract_binding(self, arg_expr: str, target_param: str = "param_0") -> ParamBinding:
        """
        提取参数绑定
        
        Args:
            arg_expr: 参数表达式（如 "keylen*8"）
            target_param: 目标参数名（如 "param_0"）
        
        Returns:
            ParamBinding
        """
        ast = self.parser.parse(arg_expr)
        
        # Case 1: 常量
        if ast["type"] == "constant":
            return ParamBinding(
                target_param=target_param,
                is_constant=True,
                constant_value=ast["value"]
            )
        
        # Case 2: 简单变量
        if ast["type"] == "variable":
            return ParamBinding(
                target_param=target_param,
                source_param=ast["name"]
            )
        
        # Case 3: 二元运算
        if ast["type"] == "binary_op":
            # 尝试提取 variable op constant 模式
            left = ast["left"]
            right = ast["right"]
            op = ast["op"]
            
            # variable * constant
            if left["type"] == "variable" and right["type"] == "constant":
                return ParamBinding(
                    target_param=target_param,
                    source_param=left["name"],
                    transform=f"{op}{right['value']}"
                )
            
            # constant * variable
            if left["type"] == "constant" and right["type"] == "variable":
                return ParamBinding(
                    target_param=target_param,
                    source_param=right["name"],
                    transform=f"{op}{left['value']}"
                )
            
            # 复合表达式（如 x*8+10）
            transform_str = self._ast_to_transform(ast)
            if transform_str:
                var_name = self._find_variable(ast)
                if var_name:
                    return ParamBinding(
                        target_param=target_param,
                        source_param=var_name,
                        transform=transform_str
                    )
            
            # 暂时简化处理：只提取最外层的变量
            var_name = self._find_variable(ast)
            if var_name:
                # 无法精确表示变换，标记为复杂
                return ParamBinding(
                    target_param=target_param,
                    source_param=var_name,
                    transform="<complex>"
                )
        
        # Case 4: 无法解析
        return ParamBinding(
            target_param=target_param,
            source_param=None
        )
    
    def _ast_to_transform(self, ast: Dict[str, Any], exclude_var: Optional[str] = None) -> Optional[str]:
        """
        将 AST 转换为变换字符串（如 "*8+10"）
        
        Args:
            ast: AST 字典
            exclude_var: 要排除的变量名（默认为找到的第一个变量）
        
        Returns:
            变换字符串，如果无法转换则返回 None
        """
        if exclude_var is None:
            exclude_var = self._find_variable(ast)
        
        if ast["type"] == "constant":
            return str(ast["value"])
        
        if ast["type"] == "variable":
            # 如果是我们要排除的变量，忽略它
            if ast["name"] == exclude_var:
                return ""
            return ast["name"]
        
        if ast["type"] == "binary_op":
            left_str = self._ast_to_transform(ast["left"], exclude_var)
            right_str = self._ast_to_transform(ast["right"], exclude_var)
            op = ast["op"]
            
            # 如果左边是空（源变量），则是 var op right 形式
            if left_str == "":
                return f"{op}{right_str}"
            
            # 如果右边是空（源变量），则是 left op var 形式
            if right_str == "":
                # 对于乘法，统一为 *value 形式
                if op == '*':
                    return f"*{left_str}"
                return f"{left_str}{op}"
            
            # 两边都有值，组合起来
            return f"{left_str}{op}{right_str}"
        
        return None
    
    def _find_variable(self, ast: Dict[str, Any]) -> Optional[str]:
        """在 AST 中查找第一个变量"""
        if ast["type"] == "variable":
            return ast["name"]
        if ast["type"] == "binary_op":
            left_var = self._find_variable(ast["left"])
            if left_var:
                return left_var
            return self._find_variable(ast["right"])
        return None
    
    def extract_from_expr(self, expr: str, target_param: str = "param_0") -> ParamBinding:
        """
        从表达式提取绑定（向后兼容）
        
        Args:
            expr: 参数表达式
            target_param: 目标参数名
        
        Returns:
            ParamBinding
        """
        return self.extract_binding(expr, target_param)
    
    def extract_from_callsite(
        self,
        args_repr: list,
        callee_params: Optional[list] = None
    ) -> Dict[str, ParamBinding]:
        """
        从 callsite 提取所有参数绑定
        
        Args:
            args_repr: 参数表达式列表（如 ["keylen*8", "mode"]）
            callee_params: 被调函数参数名列表（可选）
        
        Returns:
            {param_name: ParamBinding}
        """
        bindings = {}
        
        for i, arg_expr in enumerate(args_repr):
            # 确定目标参数名
            if callee_params and i < len(callee_params):
                target_param = callee_params[i]
            else:
                target_param = f"param_{i}"
            
            # 提取绑定
            binding = self.extract_binding(arg_expr, target_param)
            bindings[target_param] = binding
        
        return bindings
    
    def to_dict(self, bindings: Dict[str, ParamBinding]) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
        return {
            param: binding.to_dict()
            for param, binding in bindings.items()
        }
    
    def apply_transform(self, value: int, transform: str) -> int:
        """
        应用变换到值
        
        Args:
            value: 输入值
            transform: 变换字符串（如 "*8", "+10", "*8+10"）
        
        Returns:
            变换后的值
        """
        if not transform or transform == "<complex>":
            return value
        
        # 解析变换字符串
        result = value
        i = 0
        while i < len(transform):
            # 找到运算符
            if transform[i] in ('*', '/', '+', '-'):
                op = transform[i]
                i += 1
                
                # 提取数字
                num_str = ""
                while i < len(transform) and (transform[i].isdigit() or transform[i] == '.'):
                    num_str += transform[i]
                    i += 1
                
                if num_str:
                    num = int(num_str) if '.' not in num_str else float(num_str)
                    
                    # 应用运算
                    if op == '*':
                        result = result * num
                    elif op == '/':
                        result = result // num  # 整除
                    elif op == '+':
                        result = result + num
                    elif op == '-':
                        result = result - num
            else:
                i += 1
        
        return int(result)
    
    def reverse_transform(self, value: int, transform: str) -> Optional[int]:
        """
        反向应用变换（用于约束派生）
        
        Args:
            value: 输出值
            transform: 变换字符串（如 "*8", "+10"）
        
        Returns:
            输入值，如果无法反向则返回 None
        """
        if not transform or transform == "<complex>":
            return None
        
        # 解析变换字符串（反向顺序）
        ops = []
        i = 0
        while i < len(transform):
            if transform[i] in ('*', '/', '+', '-'):
                op = transform[i]
                i += 1
                
                num_str = ""
                while i < len(transform) and (transform[i].isdigit() or transform[i] == '.'):
                    num_str += transform[i]
                    i += 1
                
                if num_str:
                    num = int(num_str) if '.' not in num_str else float(num_str)
                    ops.append((op, num))
            else:
                i += 1
        
        # 反向应用（倒序且反向运算）
        result = value
        for op, num in reversed(ops):
            if op == '*':
                if result % num != 0:
                    return None  # 无法整除
                result = result // num
            elif op == '/':
                result = result * num
            elif op == '+':
                result = result - num
            elif op == '-':
                result = result + num
        
        return int(result)


# ============================================================================
# 便利函数（向后兼容）
# ============================================================================

def extract_param_bindings(args_repr: list, callee_params: Optional[list] = None, verbose: bool = False) -> Dict[str, ParamBinding]:
    """
    便利函数：提取参数绑定（向后兼容）
    
    Args:
        args_repr: 参数表达式列表
        callee_params: 被调函数参数名列表
        verbose: 是否输出调试信息
    
    Returns:
        {param_name: ParamBinding}
    """
    extractor = ParameterBindingExtractor(verbose=verbose)
    return extractor.extract_from_callsite(args_repr, callee_params)


# ============================================================================
# 测试代码
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("参数绑定提取器测试（无正则版本）")
    print("=" * 70)
    
    extractor = ParameterBindingExtractor()
    
    test_cases = [
        ("256", "常量"),
        ("keylen", "简单变量"),
        ("keylen*8", "乘法变换"),
        ("8*keylen", "乘法变换（反向）"),
        ("keylen+10", "加法变换"),
        ("size-5", "减法变换"),
        ("bits/8", "除法变换"),
    ]
    
    print("\n单个表达式测试:")
    for expr, desc in test_cases:
        binding = extractor.extract_binding(expr, "param_0")
        print(f"\n  {expr:20} ({desc})")
        print(f"    → {binding.to_dict()}")
    
    print("\n" + "=" * 70)
    print("Callsite 测试")
    print("=" * 70)
    
    # 模拟 callsite
    args_repr = ["keylen*8", "mode", "1024"]
    callee_params = ["key_bits", "cipher_mode", "iterations"]
    
    bindings = extractor.extract_from_callsite(args_repr, callee_params)
    
    print(f"\n参数表达式: {args_repr}")
    print(f"被调参数: {callee_params}")
    print(f"\n提取的绑定:")
    
    for param, binding in bindings.items():
        print(f"\n  {param}:")
        print(f"    {binding.to_dict()}")
    
    print("\n" + "=" * 70)
    print("✓ 测试完成")
    print("=" * 70)
