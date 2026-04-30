#!/usr/bin/env python3
"""
表达式求值器

统一处理表达式解析和求值，支持：
- 常量（整数、浮点数、字符串）
- 变量引用
- 算术表达式（+、-、*、/、%、**）
- 比较表达式（==、!=、<、>、<=、>=）
- 逻辑表达式（&&、||、!）
- 函数调用
- 数组/字段访问
"""

import re
from typing import Any, Dict, Optional, List, Tuple
from dataclasses import dataclass


@dataclass
class EvalContext:
    """求值上下文"""
    variables: Dict[str, Any]              # 变量值
    constants: Dict[str, Any]              # 常量定义
    functions: Dict[str, Any]              # 函数值（用于常量传播）
    
    def get(self, name: str) -> Optional[Any]:
        """获取变量/常量值"""
        if name in self.variables:
            return self.variables[name]
        if name in self.constants:
            return self.constants[name]
        return None


class ExpressionEvaluator:
    """表达式求值器"""
    
    # 运算符优先级
    OPERATOR_PRECEDENCE = {
        '**': 4,
        '*': 3, '/': 3, '%': 3,
        '+': 2, '-': 2,
        '<': 1, '>': 1, '<=': 1, '>=': 1, '==': 1, '!=': 1,
        '&&': 0, '||': 0,
    }
    
    def __init__(self, context: Optional[EvalContext] = None):
        self.context = context or EvalContext({}, {}, {})
        self._z3_available = self._check_z3_available()
    
    def _check_z3_available(self) -> bool:
        """检查 Z3 是否可用"""
        try:
            import z3
            return True
        except ImportError:
            return False
    
    def evaluate(self, expr: str) -> Optional[Any]:
        """
        求值表达式
        
        Args:
            expr: 表达式字符串
        
        Returns:
            求值结果，失败返回 None
        """
        expr = expr.strip()
        
        # 0. 优先尝试 Z3 求值（处理复杂表达式如括号）
        if self._z3_available and self._should_use_z3(expr):
            z3_result = self._evaluate_with_z3(expr)
            if z3_result is not None:
                return z3_result
        
        # 1. 常量
        value = self._try_parse_constant(expr)
        if value is not None:
            return value
        
        # 2. 变量引用
        if self._is_identifier(expr):
            return self.context.get(expr)
        
        # 3. 一元运算符
        if expr.startswith('-') or expr.startswith('!'):
            return self._evaluate_unary(expr)
        
        # 4. 括号表达式
        if expr.startswith('(') and expr.endswith(')'):
            return self.evaluate(expr[1:-1])
        
        # 5. 函数调用
        if '(' in expr and expr.endswith(')'):
            return self._evaluate_function_call(expr)
        
        # 6. 数组/字段访问
        if '[' in expr or '.' in expr:
            return self._evaluate_access(expr)
        
        # 7. 二元运算符
        return self._evaluate_binary(expr)
    
    def _try_parse_constant(self, expr: str) -> Optional[Any]:
        """尝试解析常量"""
        # 整数
        if expr.isdigit() or (expr.startswith('-') and expr[1:].isdigit()):
            return int(expr)
        
        # 十六进制
        if expr.startswith('0x') or expr.startswith('0X'):
            try:
                return int(expr, 16)
            except ValueError:
                pass
        
        # 浮点数
        try:
            if '.' in expr:
                return float(expr)
        except ValueError:
            pass
        
        # 字符串
        if (expr.startswith('"') and expr.endswith('"')) or \
           (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]
        
        # 布尔值
        if expr in ('true', 'True', 'TRUE'):
            return True
        if expr in ('false', 'False', 'FALSE'):
            return False
        
        return None
    
    def _is_identifier(self, expr: str) -> bool:
        """判断是否为标识符"""
        return re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', expr) is not None
    
    def _evaluate_unary(self, expr: str) -> Optional[Any]:
        """求值一元运算符"""
        if expr.startswith('-'):
            operand = self.evaluate(expr[1:].strip())
            if operand is not None and isinstance(operand, (int, float)):
                return -operand
        
        if expr.startswith('!'):
            operand = self.evaluate(expr[1:].strip())
            if operand is not None:
                return not operand
        
        return None
    
    def _evaluate_function_call(self, expr: str) -> Optional[Any]:
        """求值函数调用"""
        # 提取函数名和参数
        match = re.match(r'^(\w+)\((.*)\)$', expr)
        if not match:
            return None
        
        func_name = match.group(1)
        args_str = match.group(2)
        
        # 解析参数
        args = self._parse_arguments(args_str)
        
        # 内置函数
        if func_name == 'strlen':
            if args and isinstance(args[0], str):
                return len(args[0])
        
        if func_name == 'sizeof':
            # 简化处理：返回符号值
            return f"sizeof({args_str})"
        
        # 查找函数值（常量传播）
        func_value = self.context.functions.get(func_name)
        if func_value is not None:
            return func_value
        
        return None
    
    def _parse_arguments(self, args_str: str) -> List[Any]:
        """解析函数参数"""
        if not args_str.strip():
            return []
        
        args = []
        depth = 0
        current = []
        
        for char in args_str:
            if char in '([{':
                depth += 1
                current.append(char)
            elif char in ')]}':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                arg_str = ''.join(current).strip()
                if arg_str:
                    args.append(self.evaluate(arg_str))
                current = []
            else:
                current.append(char)
        
        # 最后一个参数
        arg_str = ''.join(current).strip()
        if arg_str:
            args.append(self.evaluate(arg_str))
        
        return args
    
    def _evaluate_access(self, expr: str) -> Optional[Any]:
        """求值数组/字段访问"""
        # 数组访问: arr[0]
        if '[' in expr:
            match = re.match(r'^(\w+)\[(.+)\]$', expr)
            if match:
                array_name = match.group(1)
                index_expr = match.group(2)
                
                array = self.context.get(array_name)
                index = self.evaluate(index_expr)
                
                if array is not None and index is not None:
                    try:
                        return array[index]
                    except (IndexError, KeyError, TypeError):
                        pass
        
        # 字段访问: obj.field
        if '.' in expr:
            parts = expr.split('.')
            value = self.context.get(parts[0])
            
            for part in parts[1:]:
                if value is None:
                    return None
                
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = getattr(value, part, None)
            
            return value
        
        return None
    
    def _evaluate_binary(self, expr: str) -> Optional[Any]:
        """求值二元运算符"""
        # 查找运算符（从低优先级到高优先级，同优先级长运算符优先）
        operators = sorted(
            self.OPERATOR_PRECEDENCE.keys(),
            key=lambda x: (self.OPERATOR_PRECEDENCE[x], -len(x))
        )
        
        for op in operators:
            
            # 跳过函数调用中的运算符
            pos = self._find_operator_outside_parens(expr, op)
            if pos == -1:
                continue
            
            left_expr = expr[:pos].strip()
            right_expr = expr[pos + len(op):].strip()
            
            left = self.evaluate(left_expr)
            right = self.evaluate(right_expr)
            
            # 符号执行：如果有一个操作数未知，返回符号表达式
            if left is None or right is None:
                return f"({left_expr} {op} {right_expr})"
            
            # 如果操作数是符号表达式（字符串），返回符号表达式
            if isinstance(left, str) or isinstance(right, str):
                return f"({left_expr} {op} {right_expr})"
            
            # 算术运算
            if op == '+':
                return left + right
            if op == '-':
                return left - right
            if op == '*':
                return left * right
            if op == '/':
                if right != 0:
                    return left / right
            if op == '%':
                if right != 0:
                    return left % right
            if op == '**':
                return left ** right
            
            # 比较运算
            if op == '==':
                return left == right
            if op == '!=':
                return left != right
            if op == '<':
                return left < right
            if op == '>':
                return left > right
            if op == '<=':
                return left <= right
            if op == '>=':
                return left >= right
            
            # 逻辑运算
            if op == '&&':
                return left and right
            if op == '||':
                return left or right
        
        return None
    
    def _find_operator_outside_parens(self, expr: str, op: str) -> int:
        """查找括号外的运算符位置"""
        depth = 0
        i = 0
        
        while i < len(expr):
            if expr[i] in '([{':
                depth += 1
            elif expr[i] in ')]}':
                depth -= 1
            elif depth == 0 and expr[i:i+len(op)] == op:
                # 避免部分匹配（例如 * 匹配 ** 的一部分）
                # 检查前后是否有运算符字符
                before_ok = (i == 0 or expr[i-1] not in '*/<>=!&|')
                after_ok = (i + len(op) >= len(expr) or 
                           expr[i + len(op)] not in '*/<>=!&|')
                
                if before_ok and after_ok:
                    return i
            i += 1
        
        return -1
    
    def _should_use_z3(self, expr: str) -> bool:
        """
        判断是否应该使用 Z3 求值
        
        对于包含算术运算符的表达式使用 Z3
        """
        # 如果包含括号和运算符，使用 Z3
        has_parens = '(' in expr and ')' in expr
        has_operators = any(op in expr for op in ['+', '-', '*', '/', '%'])
        
        # 但排除函数调用（如 "calculate(64)"）
        if has_parens and not has_operators:
            return False
        
        return has_operators
    
    def _evaluate_with_z3(self, expr: str) -> Optional[int]:
        """
        使用 Z3 求值算术表达式
        
        Args:
            expr: 表达式字符串，如 "(64 * 8) + (64 * 8)"
        
        Returns:
            整数结果，失败返回 None
        """
        try:
            import z3
            
            # 提取表达式中的所有标识符（变量名）
            identifiers = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', expr))
            
            # 创建 Z3 变量
            z3_vars = {}
            solver = z3.Solver()
            
            # 为每个标识符创建 Z3 整数变量
            for ident in identifiers:
                z3_vars[ident] = z3.Int(ident)
                
                # 如果在上下文中有该变量的值，添加约束
                value = self.context.get(ident)
                if value is not None and isinstance(value, int):
                    solver.add(z3_vars[ident] == value)
            
            # 创建结果变量
            result_var = z3.Int('__result__')
            
            # 将表达式转换为 Z3 表达式
            # 替换变量名为 Z3 变量
            z3_expr_str = expr
            for ident in identifiers:
                z3_expr_str = re.sub(r'\b' + ident + r'\b', f'z3_vars["{ident}"]', z3_expr_str)
            
            # 构建约束：result == expression
            try:
                z3_expr = eval(z3_expr_str, {"z3_vars": z3_vars, "z3": z3})
                solver.add(result_var == z3_expr)
            except Exception:
                return None
            
            # 求解
            if solver.check() == z3.sat:
                model = solver.model()
                result = model[result_var]
                if result is not None:
                    return result.as_long()
            
            return None
            
        except Exception:
            return None


def evaluate_expression(
    expr: str,
    variables: Optional[Dict[str, Any]] = None,
    constants: Optional[Dict[str, Any]] = None
) -> Optional[Any]:
    """
    便捷函数：求值表达式
    
    Args:
        expr: 表达式字符串
        variables: 变量值字典
        constants: 常量值字典
    
    Returns:
        求值结果
    """
    context = EvalContext(
        variables=variables or {},
        constants=constants or {},
        functions={}
    )
    evaluator = ExpressionEvaluator(context)
    return evaluator.evaluate(expr)


def extract_variables(expr: str) -> List[str]:
    """
    提取表达式中的变量
    
    Args:
        expr: 表达式字符串
    
    Returns:
        变量名列表
    """
    # 移除字符串字面量
    expr = re.sub(r'"[^"]*"', '', expr)
    expr = re.sub(r"'[^']*'", '', expr)
    
    # 提取标识符
    identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', expr)
    
    # 过滤关键字和内置函数
    keywords = {'true', 'false', 'null', 'sizeof', 'strlen'}
    variables = [v for v in identifiers if v not in keywords]
    
    return list(set(variables))


if __name__ == '__main__':
    # 测试
    print("测试表达式求值器:")
    
    # 常量
    assert evaluate_expression("42") == 42
    assert evaluate_expression("3.14") == 3.14
    assert evaluate_expression('"hello"') == "hello"
    
    # 算术表达式
    assert evaluate_expression("2 + 3") == 5
    assert evaluate_expression("10 - 4") == 6
    assert evaluate_expression("3 * 4") == 12
    assert evaluate_expression("15 / 3") == 5.0
    assert evaluate_expression("10 % 3") == 1
    assert evaluate_expression("2 ** 3") == 8
    
    # 复杂表达式
    assert evaluate_expression("2 + 3 * 4") == 14
    assert evaluate_expression("(2 + 3) * 4") == 20
    
    # 变量
    ctx = {"x": 10, "y": 5}
    assert evaluate_expression("x + y", ctx) == 15
    assert evaluate_expression("x * 2", ctx) == 20
    
    # 比较
    assert evaluate_expression("10 > 5") == True
    assert evaluate_expression("3 < 2") == False
    assert evaluate_expression("5 == 5") == True
    
    # 变量提取
    vars = extract_variables("x + y * 2")
    assert set(vars) == {"x", "y"}
    
    vars = extract_variables("strlen(name) + 10")
    assert set(vars) == {"name"}
    
    print("✓ 所有测试通过")
