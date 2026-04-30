
from typing import Dict, Any, List, Optional
from .parser import get_parser
from .navigator import node_text, walk


def extract_return_expression(func_node, code: str, lang: str) -> Optional[str]:
    """
    从函数AST节点提取返回表达式
    
    Args:
        func_node: 函数定义的AST节点
        code: 源代码
        lang: 语言
    
    Returns:
        返回表达式的文本（如 "security_level * 16"），没有则None
    """
    if not func_node:
        return None
    
    # 查找return语句
    for node in walk(func_node):
        if node.type == "return_statement":
            # 找到return节点，提取表达式部分（跳过"return"关键字）
            for child in node.children:
                if child.type not in["return", ";"]:
                    # 这是返回表达式
                    expr_text = node_text(code, child).strip()
                    return expr_text
    
    return None


def extract_function_params(func_node, code: str, lang: str) -> List[str]:
    """
    从函数AST节点提取参数名列表
    
    Args:
        func_node: 函数定义的AST节点
        code: 源代码
        lang: 语言
    
    Returns:
        参数名列表，如 ["security_level"]
    """
    from .extractor import extract_function_params as extractor_params
    return extractor_params(func_node, code, lang)


def enhance_function_definitions(functions: List[Dict[str, Any]], code: str, lang: str) -> List[Dict[str, Any]]:
    """
    增强函数定义列表，添加params和return_expression字段
    
    Args:
        functions: extract_functions()返回的基本函数列表
        code: 源代码
        lang: 语言
    
    Returns:
        增强后的函数列表，每个包含：
        - name: 函数名
        - start_line/end_line: 行号范围
        - params: 参数名列表
        - return_expression: 返回表达式（纯计算函数）
        - _node: AST节点（可选）
    """
    enhanced = []
    
    for func in functions:
        func_node = func.get('_node')
        if not func_node:
            # 没有AST节点，无法增强
            enhanced.append(func)
            continue
        
        # 提取参数和返回表达式
        params = extract_function_params(func_node, code, lang)
        return_expr = extract_return_expression(func_node, code, lang)
        
        # 创建增强版本
        enhanced_func = {
            **func,
            'params': params,
            'return_expression': return_expr
        }
        
        enhanced.append(enhanced_func)
    
    return enhanced
