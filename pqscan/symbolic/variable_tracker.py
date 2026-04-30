#!/usr/bin/env python3
"""
Variable Tracker: AST-based variable value tracking

纯 AST 实现的变量追踪，替代正则表达式：
1. 常量追踪：#define KEY_SIZE 128, const int KEY_SIZE = 128
2. 变量追踪：int keySize = 128; AES_set_key(..., keySize, ...)
3. 跨函数追踪：通过 ValueGraph 的数据流分析
4. 表达式求值：keySize * 8, 16 << 3

设计原则：
- 纯 AST，无正则
- 语言无关（基于统一的 AST 结构）
- 与 ObjectStateTracker 配合（对象状态追踪）
"""

from typing import Dict, Any, List, Optional, Set


class VariableTracker:
    """
    AST-based variable value tracker
    
    追踪变量值的定义和传播，支持：
    1. 常量定义：#define, const, enum
    2. 变量赋值：int x = 128;
    3. 参数传递：func(x) where x = 128
    4. 表达式求值：x * 8, x << 3
    
    使用示例:
        tracker = VariableTracker()
        
        # 从 AST 提取的变量赋值信息构建
        var_assignments = [
            {'name': 'keySize', 'value': '128', 'line': 10},
            {'name': 'KEY_BITS', 'value': '256', 'line': 5},  # #define
        ]
        tracker.build_from_assignments(var_assignments)
        
        # 查询变量值
        value = tracker.get_value('keySize')  # → 128
        value = tracker.get_value('KEY_BITS')  # → 256
    """
    
    def __init__(self):
        # 变量值表: var_name → value
        self.variables: Dict[str, Any] = {}
        # 原始表达式表: var_name → raw expression/value text
        self.expressions: Dict[str, Any] = {}
        
        # 变量定义位置: var_name → line
        self.definitions: Dict[str, int] = {}
        
        # 表达式缓存: expr_str → evaluated_value
        self.expr_cache: Dict[str, Any] = {}
    
    def build_from_assignments(self, var_assignments: List[Dict[str, Any]]):
        """
        从 AST 提取的变量赋值列表构建追踪表
        
        Args:
            var_assignments: 变量赋值列表，格式：
                [{'name': 'keySize', 'value': '128', 'line': 10}, ...]
        """
        for assignment in var_assignments:
            var_name = assignment.get('name')
            value_str = assignment.get('value')
            line = assignment.get('line')
            
            if not var_name or value_str is None:
                continue

            self.expressions[var_name] = value_str
            
            # 如果 value 已经是整数或其他类型，直接使用
            if not isinstance(value_str, str):
                self.variables[var_name] = value_str
                self.definitions[var_name] = line
                continue
            
            # 尝试求值字符串表达式
            evaluated_value = self._evaluate_expression(value_str)
            
            if evaluated_value is not None:
                self.variables[var_name] = evaluated_value
                self.definitions[var_name] = line
    
    def get_value(self, var_name: str) -> Optional[Any]:
        """
        获取变量的值
        
        Args:
            var_name: 变量名
        
        Returns:
            变量值，未找到返回 None
        """
        return self.variables.get(var_name)

    def get_expression(self, var_name: str, max_hops: int = 8) -> Optional[Any]:
        """
        获取变量的原始表达式，并递归展开简单别名链。

        例如：
            x = key
            key = make([]byte, 32)
        调用 get_expression("x") 返回 "make([]byte, 32)"。
        """
        if not var_name:
            return None

        visited: Set[str] = set()
        current = var_name
        hops = max(1, int(max_hops))
        expr: Any = None

        while hops > 0:
            hops -= 1
            if current in visited:
                break
            visited.add(current)
            expr = self.expressions.get(current)
            if expr is None:
                break
            if not isinstance(expr, str):
                return expr
            text = expr.strip()
            if not text:
                return text
            if not text.isidentifier():
                return text
            if text in self.variables:
                return self.variables[text]
            current = text

        return expr
    
    def has_variable(self, var_name: str) -> bool:
        """检查变量是否存在"""
        return var_name in self.variables or var_name in self.expressions
    
    def get_definition_line(self, var_name: str) -> Optional[int]:
        """获取变量定义的行号"""
        return self.definitions.get(var_name)
    
    def _evaluate_expression(self, expr_str: str) -> Optional[Any]:
        """
        求值表达式（纯 AST，无 eval）
        
        支持的表达式：
        - 字面量：128, "AES", 0x80
        - 算术运算：16 * 8, 128 << 1
        - 变量引用：KEY_SIZE (递归查找)
        
        Args:
            expr_str: 表达式字符串
        
        Returns:
            求值结果，无法求值返回 None
        """
        # 缓存检查
        if expr_str in self.expr_cache:
            return self.expr_cache[expr_str]
        
        expr_str = expr_str.strip()
        
        # Case 1: 整数字面量
        if expr_str.isdigit():
            value = int(expr_str)
            self.expr_cache[expr_str] = value
            return value
        
        # Case 2: 十六进制字面量
        if expr_str.startswith('0x') or expr_str.startswith('0X'):
            try:
                value = int(expr_str, 16)
                self.expr_cache[expr_str] = value
                return value
            except ValueError:
                pass
        
        # Case 3: 字符串字面量
        if (expr_str.startswith('"') and expr_str.endswith('"')) or \
           (expr_str.startswith("'") and expr_str.endswith("'")):
            value = expr_str[1:-1]
            self.expr_cache[expr_str] = value
            return value
        
        # Case 4: 简单算术表达式 (a * b, a << b, a + b, etc.)
        value = self._evaluate_arithmetic(expr_str)
        if value is not None:
            self.expr_cache[expr_str] = value
            return value
        
        # Case 5: 变量引用（递归查找）
        if expr_str.isidentifier():
            value = self.get_value(expr_str)
            if value is not None:
                self.expr_cache[expr_str] = value
                return value
        
        # 无法求值
        return None
    
    def _evaluate_arithmetic(self, expr_str: str) -> Optional[int]:
        """
        求值简单算术表达式（无 eval，安全）
        
        支持：+, -, *, /, <<, >>
        """
        operators = [
            ('<<', lambda a, b: a << b),
            ('>>', lambda a, b: a >> b),
            ('*', lambda a, b: a * b),
            ('/', lambda a, b: a // b),
            ('+', lambda a, b: a + b),
            ('-', lambda a, b: a - b),
        ]
        
        for op_str, op_func in operators:
            if op_str in expr_str:
                parts = expr_str.split(op_str, 1)
                if len(parts) == 2:
                    left = self._evaluate_expression(parts[0].strip())
                    right = self._evaluate_expression(parts[1].strip())
                    
                    if isinstance(left, int) and isinstance(right, int):
                        try:
                            return op_func(left, right)
                        except (ZeroDivisionError, ValueError):
                            return None
        
        return None
    
    def resolve_argument(self, arg: Any, language: str) -> Optional[Any]:
        """
        解析参数值（字面量或变量引用）
        
        Args:
            arg: 参数值（可能是字面量、变量名或表达式）
            language: 语言类型
        
        Returns:
            解析后的值
        
        使用示例:
            # 字面量
            tracker.resolve_argument(128, 'c')  # → 128
            
            # 变量引用
            tracker.resolve_argument('keySize', 'c')  # → 128 (如果 keySize=128)
            
            # 表达式
            tracker.resolve_argument('16 * 8', 'c')  # → 128
        """
        # Case 1: 已经是数值类型
        if isinstance(arg, (int, float)):
            return arg
        
        # Case 2: 字符串类型 - 尝试求值
        if isinstance(arg, str):
            return self._evaluate_expression(arg)
        
        # Case 3: 字典类型（从 AST args 提取）
        if isinstance(arg, dict):
            # 如果有 'value' 字段，使用它
            if 'value' in arg:
                return self.resolve_argument(arg['value'], language)
            # 如果有 'name' 字段，可能是变量引用
            if 'name' in arg:
                return self.get_value(arg['name'])
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_variables': len(self.variables),
            'raw_expressions': len(self.expressions),
            'integer_variables': sum(1 for v in self.variables.values() if isinstance(v, int)),
            'string_variables': sum(1 for v in self.variables.values() if isinstance(v, str)),
            'cached_expressions': len(self.expr_cache)
        }


if __name__ == "__main__":
    # 测试
    tracker = VariableTracker()
    
    print("Variable Tracker Test")
    print("="*80)
    
    # 模拟 AST 提取的变量赋值
    var_assignments = [
        {'name': 'KEY_SIZE', 'value': '128', 'line': 5},
        {'name': 'KEY_BYTES', 'value': '16', 'line': 6},
        {'name': 'KEY_BITS', 'value': 'KEY_BYTES * 8', 'line': 7},  # 表达式
        {'name': 'SHIFTED', 'value': '16 << 3', 'line': 8},  # 位移
        {'name': 'ALGO_NAME', 'value': '"AES"', 'line': 9},
    ]
    
    tracker.build_from_assignments(var_assignments)
    
    print("\n变量表:")
    for var_name, value in tracker.variables.items():
        print(f"  {var_name} = {value} (line {tracker.get_definition_line(var_name)})")
    
    print("\n表达式求值测试:")
    test_cases = [
        ('KEY_SIZE', 128),
        ('KEY_BITS', 128),
        ('SHIFTED', 128),
        ('ALGO_NAME', 'AES'),
        ('256 >> 1', 128),
        ('0x80', 128),
    ]
    
    for expr, expected in test_cases:
        result = tracker._evaluate_expression(expr)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {expr} = {result} (expected {expected})")
    
    print("\n统计信息:")
    stats = tracker.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
