"""
函数调用语义建模

为常见函数调用建立语义模型，使系统能够推导函数调用的返回值。

支持的函数:
- os.getenv(key, default) - 返回默认值
- int(value) - 转换为整数
- str(value) - 转换为字符串
- float(value) - 转换为浮点数
- dict.get(key, default) - 返回默认值
"""

import ast
from typing import Any, Optional, Dict, List


# 函数语义定义
FUNCTION_SEMANTICS = {
    # 环境变量获取
    'os.getenv': {
        'type': 'default_value_fallback',
        'default_param_index': 1,  # 第二个参数是默认值
        'description': 'Returns the second parameter if env var not found'
    },
    'os.environ.get': {
        'type': 'default_value_fallback',
        'default_param_index': 1,
        'description': 'Returns the second parameter if key not found'
    },
    
    # 类型转换
    'int': {
        'type': 'type_conversion',
        'target_type': int,
        'param_index': 0,
        'description': 'Converts first parameter to integer'
    },
    'str': {
        'type': 'type_conversion',
        'target_type': str,
        'param_index': 0,
        'description': 'Converts first parameter to string'
    },
    'float': {
        'type': 'type_conversion',
        'target_type': float,
        'param_index': 0,
        'description': 'Converts first parameter to float'
    },
    
    # 字典获取
    'dict.get': {
        'type': 'default_value_fallback',
        'default_param_index': 1,
        'description': 'Returns the second parameter if key not found'
    },
}


def get_function_name(call_node: ast.Call) -> Optional[str]:
    """
    提取函数调用的完整名称
    
    Examples:
        int(...) -> "int"
        os.getenv(...) -> "os.getenv"
        config.get(...) -> "dict.get" (泛化)
    """
    if isinstance(call_node.func, ast.Name):
        # 简单函数名: int, str, float
        return call_node.func.id
    
    elif isinstance(call_node.func, ast.Attribute):
        # 属性访问: os.getenv, dict.get
        if isinstance(call_node.func.value, ast.Name):
            obj_name = call_node.func.value.id
            attr_name = call_node.func.attr
            
            # 特殊处理: 任何 .get() 调用都视为 dict.get
            if attr_name == 'get' and obj_name not in ['os']:
                return 'dict.get'
            
            return f"{obj_name}.{attr_name}"
    
    return None


def extract_argument_value(arg_node: ast.AST) -> Optional[Any]:
    """
    提取参数的字面量值
    
    Supports:
    - Constants: 1024, "1024", 3.14
    - Strings: "default_value"
    - Numbers: 42, 3.14
    """
    if isinstance(arg_node, ast.Constant):
        return arg_node.value
    
    # Python 3.7 兼容
    if isinstance(arg_node, ast.Num):
        return arg_node.n
    if isinstance(arg_node, ast.Str):
        return arg_node.s
    
    return None


def evaluate_function_call(call_node: ast.Call) -> Optional[Any]:
    """
    求值函数调用的返回值
    
    处理两种模式:
    1. 默认值回退: os.getenv("KEY", "1024") -> "1024"
    2. 类型转换: int("1024") -> 1024
    
    Returns:
        函数调用的返回值，如果无法求值则返回 None
    
    Example:
        int(os.getenv("RSA_BITS", "1024"))
        -> os.getenv(...) returns "1024"
        -> int("1024") returns 1024
    """
    func_name = get_function_name(call_node)
    if not func_name or func_name not in FUNCTION_SEMANTICS:
        return None
    
    semantics = FUNCTION_SEMANTICS[func_name]
    
    # 模式 1: 默认值回退
    if semantics['type'] == 'default_value_fallback':
        default_idx = semantics['default_param_index']
        if len(call_node.args) > default_idx:
            return extract_argument_value(call_node.args[default_idx])
        return None
    
    # 模式 2: 类型转换
    elif semantics['type'] == 'type_conversion':
        param_idx = semantics['param_index']
        target_type = semantics['target_type']
        
        if len(call_node.args) > param_idx:
            arg_value = extract_argument_value(call_node.args[param_idx])
            
            # 如果参数本身是函数调用，递归求值
            if arg_value is None and isinstance(call_node.args[param_idx], ast.Call):
                arg_value = evaluate_function_call(call_node.args[param_idx])
            
            # 执行类型转换
            if arg_value is not None:
                try:
                    return target_type(arg_value)
                except (ValueError, TypeError):
                    return None
        
        return None
    
    return None


def extract_function_call_semantics(node: ast.AST) -> Optional[Dict[str, Any]]:
    """
    提取赋值语句右侧的函数调用语义
    
    Returns:
        {
            'type': 'function_call',
            'function': 'int',
            'value': 1024,
            'inner_calls': ['os.getenv']
        }
    
    Example:
        key_bits = int(os.getenv("RSA_BITS", "1024"))
        -> {
            'type': 'function_call',
            'function': 'int',
            'value': 1024,
            'inner_calls': ['os.getenv']
        }
    """
    if not isinstance(node, ast.Call):
        return None
    
    func_name = get_function_name(node)
    if not func_name:
        return None
    
    # 求值函数调用
    value = evaluate_function_call(node)
    if value is None:
        return None
    
    # 收集嵌套的函数调用
    inner_calls = []
    for arg in node.args:
        if isinstance(arg, ast.Call):
            inner_func = get_function_name(arg)
            if inner_func:
                inner_calls.append(inner_func)
    
    return {
        'type': 'function_call',
        'function': func_name,
        'value': value,
        'inner_calls': inner_calls
    }


# 快捷函数：直接从代码片段中提取
def extract_from_code(code: str) -> Optional[Any]:
    """
    从代码片段中提取函数调用的值
    
    Example:
        extract_from_code('int(os.getenv("RSA_BITS", "1024"))')
        -> 1024
    """
    try:
        tree = ast.parse(code, mode='eval')
        if isinstance(tree.body, ast.Call):
            return evaluate_function_call(tree.body)
    except SyntaxError:
        pass
    
    return None
