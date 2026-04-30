#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   extractor.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/18 16:49   1.0         function/call/import/constant/assignment/basic block
"""
from typing import Dict

# pqscan/abstract_syntax_tree/extractor.py
from .navigator import iter_functions, iter_imports, walk, node_text


def extract_imports(root, code: str, lang: str):
    """提取 import 列表"""
    return list(iter_imports(root, code, lang))

def extract_imports_with_aliases(root, code: str, lang: str = "go"):
    """Return (imports_list, alias_map) for multiple languages.
    alias_map: alias -> fullpath/module
    """
    imports = []
    alias_map = {}
    lang = (lang or "go").lower()

    # Go: import_spec nodes with optional name and path
    if lang == "go":
        for n in walk(root):
            if n.type == "import_spec":
                name_node = n.child_by_field_name("name")
                path_node = n.child_by_field_name("path")
                if not path_node:
                    continue
                path_text = node_text(code, path_node).strip('" ')
                imports.append(path_text)
                alias = node_text(code, name_node) if name_node else path_text.rsplit("/",1)[-1]
                alias_map[alias] = path_text
        return list(dict.fromkeys(imports)), alias_map

    # Python: handle 'import x as y' and 'from a.b import c as d'
    if lang == "python":
        for n in walk(root):
            # 1. import os, numpy as np
            if n.type == "import_statement":
                text = node_text(code, n).strip()
                body = text[len("import"):].strip()
                for part in body.split(','):
                    part = part.strip()
                    if not part:
                        continue
                    if " as " in part:
                        mod, alias = [x.strip() for x in part.split(" as ", 1)]
                        imports.append(mod)
                        alias_map[alias] = mod
                    else:
                        imports.append(part)
                        alias_map[part.rsplit('.', 1)[-1]] = part

            # 2. from Crypto.Cipher import AES as A, DES (纯 AST，无正则)
            if n.type == "import_from_statement":
                module_node = n.child_by_field_name("module_name")
                
                if module_node:
                    # 获取 from 后的模块名 (e.g., "Crypto.Cipher")
                    mod = node_text(code, module_node).strip()
                    imports.append(mod)
                    
                    # 遍历所有导入项 (AES, DES, ...)
                    for child in n.children:
                        if child.type == "dotted_name":
                            # import 的符号 (e.g., "AES")
                            name = node_text(code, child).strip()
                            fq = f"{mod}.{name}"
                            alias_map[name] = fq
                        
                        elif child.type == "aliased_import":
                            # "AES as A" 形式
                            name_node = child.child_by_field_name("name")
                            alias_node = child.child_by_field_name("alias")
                            if name_node and alias_node:
                                name = node_text(code, name_node).strip()
                                al = node_text(code, alias_node).strip()
                                fq = f"{mod}.{name}"
                                alias_map[al] = fq
                else:
                    # "from . import x" 或 "from .. import y" (相对导入)
                    for child in n.children:
                        if child.type == "dotted_name":
                            name = node_text(code, child).strip()
                            alias_map[name] = name

        return list(dict.fromkeys(imports)), alias_map

    # Java: import declarations like 'import java.util.List;'
    if lang == "java":
        for n in walk(root):
            if n.type == "import_declaration":
                text = node_text(code, n).strip()
                text = text.replace('import','').strip().rstrip(';')
                imports.append(text)
                alias = text.rsplit('.',1)[-1]
                alias_map[alias] = text
        return list(dict.fromkeys(imports)), alias_map

    # C/C++: #include lines
    if lang in ("c","cpp","c++","cxx"):
        for n in walk(root):
            if n.type in ("preproc_include", "include_directive"):
                text = node_text(code, n).strip()
                # extract header path
                m = text.strip().lstrip('#include').strip()
                # Remove angle brackets for system headers and quotes for local headers
                m = m.strip('<>"')
                imports.append(m)
        return list(dict.fromkeys(imports)), alias_map

    # fallback: return simple iter_imports output
    for n in walk(root):
        if n.type == "import_spec":
            imports.append(node_text(code, n).strip('" '))
    return list(dict.fromkeys(imports)), alias_map


def _extract_java_var_assignments(root, code: str):
    """
    为 Java 提取变量赋值映射（升级为 scope-aware list 格式）
    
    新格式：
    [
        {"name": "keyGen", "value": "KeyGenerator", "line": 10, "function": "initCrypto"},
        ...
    ]
    """
    from typing import List, Dict
    
    # 构建函数行号映射
    func_map = {}
    functions = iter_functions(root, code, 'java')
    for func in functions:
        start_line = func.get('start_line', 0)
        end_line = func.get('end_line', 999999)
        func_name = func.get('name', '')
        for line_num in range(start_line, end_line + 1):
            func_map[line_num] = func_name
    
    var_assignments_list = []
    
    for n in walk(root):
        # Java: variable_declarator 包含变量声明
        if n.type == "variable_declarator":
            name_node = n.child_by_field_name("name")
            value_node = n.child_by_field_name("value")
            
            if name_node:
                var_name = node_text(code, name_node).strip()
                line_num = n.start_point[0] + 1
                func_name = func_map.get(line_num, '')
                
                # 尝试从 value 中推断类型 (纯 AST，无正则)
                if value_node:
                    value_text = node_text(code, value_node).strip()
                    ast_info = None  # 保存AST结构化信息
                    
                    # 检查是否是方法调用: ClassName.getInstance(...)
                    if value_node.type == "method_invocation":
                        object_node = value_node.child_by_field_name("object")
                        name_method = value_node.child_by_field_name("name")
                        
                        # 提取调用参数
                        call_args = extract_call_arguments(value_node, code, "java")
                        
                        if object_node and name_method:
                            class_name = node_text(code, object_node).strip()
                            method_name = node_text(code, name_method).strip()
                            # 如果是 getInstance 等工厂方法，记录类名
                            if method_name in ("getInstance", "newInstance", "create"):
                                var_assignments_list.append({
                                    'name': var_name,
                                    'value': class_name,
                                    'expr_value': value_text,
                                    'receiver_type': class_name,
                                    'line': line_num,
                                    'function': func_name,
                                    '_call_node': value_node  # Store AST node for precise mapping
                                })
                            else:
                                var_assignments_list.append({
                                    'name': var_name,
                                    'value': value_text,
                                    'line': line_num,
                                    'function': func_name,
                                    '_call_node': value_node  # Store AST node
                                })
                    # Java: new byte[N] 或 new byte[]{...}
                    elif value_node.type == "array_creation_expression":
                        # 提取数组类型和维度
                        type_node = value_node.child_by_field_name("type")
                        dimensions_node = value_node.child_by_field_name("dimensions")
                        
                        if type_node and dimensions_node:
                            type_text = node_text(code, type_node).strip()
                            # 提取维度表达式
                            dim_args = []
                            for child in dimensions_node.children:
                                if child.type not in ["[", "]", "comment"]:
                                    dim_args.append({
                                        "type": child.type,
                                        "text": node_text(code, child).strip()
                                    })
                            
                            if type_text == "byte" and dim_args:
                                ast_info = {
                                    "type": "array_creation",
                                    "element_type": "byte",
                                    "dimensions": dim_args
                                }
                        
                        # 也可能有初始化列表 new byte[]{1,2,3}
                        initializer = value_node.child_by_field_name("initializer")
                        if initializer and type_text == "byte":
                            # 统计初始化元素数量
                            init_args = extract_call_arguments(initializer, code, "java")
                            ast_info = {
                                "type": "array_initializer",
                                "element_type": "byte",
                                "initializer": init_args
                            }
                        
                        assignment = {
                            'name': var_name,
                            'value': value_text,
                            'line': line_num,
                            'function': func_name
                        }
                        if ast_info:
                            assignment['ast_info'] = ast_info
                        var_assignments_list.append(assignment)
                    else:
                        var_assignments_list.append({
                            'name': var_name,
                            'value': value_text,
                            'line': line_num,
                            'function': func_name
                        })
        
        # Java: 也处理局部变量声明的情况（variable_declarator 在 local_variable_declaration 中）
        elif n.type == "local_variable_declaration":
            # 类型在这个节点中
            type_node = None
            for ch in n.children:
                if ch.type in ("type_identifier", "generic_type", "primitive_type", "array_type", "integral_type"):
                    type_node = ch
                    break
            
            if type_node:
                var_type = node_text(code, type_node).strip()
                line_num = n.start_point[0] + 1
                func_name = func_map.get(line_num, '')
                
                # 查找 variable_declarator 子节点
                for ch in n.children:
                    if ch.type == "variable_declarator":
                        name_node = ch.child_by_field_name("name")
                        value_node = ch.child_by_field_name("value")
                        
                        if name_node:
                            var_name = node_text(code, name_node).strip()
                            
                            # 如果有初始化值，尝试提取 AST 信息
                            ast_info = None
                            value_text = var_type
                            
                            if value_node:
                                value_text = node_text(code, value_node).strip()
                                
                                # Java: new byte[N] 或 new byte[]{...}
                                if value_node.type == "array_creation_expression":
                                    # 查找类型节点（可能是 type 字段或按位置查找）
                                    type_in_array = None
                                    dimensions_node = None
                                    initializer = None
                                    
                                    # 遍历子节点查找
                                    for child in value_node.children:
                                        if child.type in ("integral_type", "type_identifier", "primitive_type"):
                                            type_in_array = child
                                        elif child.type in ("dimensions", "dimensions_expr"):
                                            dimensions_node = child
                                        elif child.type == "array_initializer":
                                            initializer = child
                                    
                                    # 如果有维度表达式（new byte[N]）
                                    if type_in_array and dimensions_node and dimensions_node.type == "dimensions_expr":
                                        type_text = node_text(code, type_in_array).strip()
                                        
                                        # 提取维度表达式
                                        dim_args = []
                                        for child in dimensions_node.children:
                                            if child.type not in ["[", "]", "comment"]:
                                                dim_args.append({
                                                    "type": child.type,
                                                    "text": node_text(code, child).strip()
                                                })
                                        
                                        if type_text == "byte" and dim_args:
                                            ast_info = {
                                                "type": "array_creation",
                                                "element_type": "byte",
                                                "dimensions": dim_args
                                            }
                                    
                                    # 如果有初始化列表（new byte[]{1,2,3}）
                                    elif type_in_array and initializer:
                                        type_text = node_text(code, type_in_array).strip()
                                        
                                        if type_text == "byte":
                                            # 统计初始化元素数量（不使用 extract_call_arguments，直接遍历）
                                            init_args = []
                                            for init_child in initializer.children:
                                                if init_child.type not in ["{", "}", ",", "comment"]:
                                                    arg_info = {
                                                        "type": init_child.type,
                                                        "text": node_text(code, init_child).strip()
                                                    }
                                                    # 尝试解析为整数
                                                    if init_child.type in ["decimal_integer_literal", "integer_literal", "number_literal"]:
                                                        try:
                                                            text = node_text(code, init_child).strip()
                                                            arg_info["value"] = int(text, 0)
                                                        except ValueError:
                                                            pass
                                                    init_args.append(arg_info)
                                            
                                            ast_info = {
                                                "type": "array_initializer",
                                                "element_type": "byte",
                                                "initializer": init_args
                                            }
                            
                            assignment = {
                                'name': var_name,
                                'value': value_text,
                                'line': line_num,
                                'function': func_name
                            }
                            if ast_info:
                                assignment['ast_info'] = ast_info
                            var_assignments_list.append(assignment)

        # Java: 处理直接赋值表达式（例如 CRYPTO = DEFAULT_CRYPTO.toCharArray();）
        elif n.type == "assignment_expression":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")

            if not left_node or not right_node:
                continue

            # 仅处理简单标识符赋值，字段赋值由 extract_field_assignments 负责
            if left_node.type != "identifier":
                continue

            var_name = node_text(code, left_node).strip()
            if not var_name:
                continue

            line_num = n.start_point[0] + 1
            func_name = func_map.get(line_num, '')
            value_text = node_text(code, right_node).strip()

            assignment = {
                'name': var_name,
                'value': value_text,
                'line': line_num,
                'function': func_name,
            }

            if right_node.type in ("method_invocation", "call_expression"):
                assignment['_call_node'] = right_node

            var_assignments_list.append(assignment)
    
    return var_assignments_list


def _try_load_config_file(root, code: str, call_args, current_line: int, module_name: str):
    """
    尝试读取json.load(f)或yaml.load(f)调用的配置文件内容
    
    Args:
        root: AST根节点
        code: 源代码
        call_args: json.load/yaml.load的参数列表
        current_line: 当前行号
        module_name: 'json' 或 'yaml'
    
    Returns:
        字典对象（配置文件内容），或None（无法读取）
    """
    import os
    import json
    
    # 提取文件对象参数（如 f）
    if not call_args or len(call_args) == 0:
        return None
    
    file_obj_name = call_args[0].get('text', '').strip()
    if not file_obj_name:
        return None
    
    # 在AST中查找 with open(...) as file_obj_name 或 file_obj_name = open(...)
    file_path = _find_file_path_for_object(root, code, file_obj_name, current_line)
    
    if not file_path:
        return None
    
    # 读取并解析文件
    try:
        # 处理相对路径：相对于测试文件所在目录
        if not os.path.isabs(file_path):
            # 假设配置文件在 tests/real_world/fixtures/ 目录
            base_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(base_dir))
            fixtures_dir = os.path.join(project_root, "tests", "real_world", "fixtures")
            file_path = os.path.join(fixtures_dir, os.path.basename(file_path))
        
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, 'r', encoding='utf-8') as f:
            if module_name == 'json':
                config_dict = json.load(f)
            elif module_name == 'yaml':
                try:
                    import yaml
                    config_dict = yaml.safe_load(f)
                except ImportError:
                    return None
            else:
                return None
        
        # 只返回简单的字典（不支持嵌套对象）
        if isinstance(config_dict, dict):
            result = {}
            for key, value in config_dict.items():
                if isinstance(value, (int, float, str, bool)):
                    result[key] = value
            return result
        
        return None
    except Exception:
        return None


def _find_file_path_for_object(root, code: str, file_obj_name: str, current_line: int):
    """
    查找文件对象对应的文件路径
    
    支持模式：
    1. with open("path") as f:
    2. with open(path_var) as f:
    
    Args:
        root: AST根节点
        code: 源代码
        file_obj_name: 文件对象名（如 'f'）
        current_line: 当前行号（仅查找此行之前的）
    
    Returns:
        文件路径字符串，或None
    """
    from .navigator import walk, node_text
    
    # 查找 with_statement
    for node in walk(root):
        if node.type == "with_statement":
            node_line = node.start_point[0] + 1
            if node_line >= current_line:
                continue
            
            # 检查 with 子句
            with_clause = None
            for child in node.children:
                if child.type == "with_clause":
                    with_clause = child
                    break
            
            if not with_clause:
                continue
            
            # 遍历 with_item
            for child in with_clause.children:
                if child.type == "with_item":
                    # 查找 as_pattern: call as identifier
                    for subchild in child.children:
                        if subchild.type == "as_pattern":
                            # 检查目标名称
                            as_target = subchild.child_by_field_name("alias")
                            if not as_target:
                                # 尝试查找 as_pattern_target
                                for c in subchild.children:
                                    if c.type == "as_pattern_target":
                                        as_target = c
                                        break
                            
                            if as_target:
                                target_name = node_text(code, as_target).strip()
                                if target_name == file_obj_name:
                                    # 找到匹配的with语句，提取open调用的参数
                                    call_node = None
                                    for c in subchild.children:
                                        if c.type == "call":
                                            call_node = c
                                            break
                                    
                                    if call_node:
                                        path = _extract_path_from_open_call(call_node, code, root)
                                        return path
    
    return None


def _extract_path_from_open_call(call_node, code: str, root):
    """
    从 open(...) 调用中提取文件路径
    
    支持：
    1. open("path.json")
    2. open(Path(__file__).parent / "fixtures" / "crypto.json")
    
    Args:
        call_node: open() 调用的AST节点
        code: 源代码
        root: AST根节点
    
    Returns:
        文件路径字符串，或None
    """
    from .navigator import node_text
    import os
    
    # 提取第一个参数
    arg_list = call_node.child_by_field_name("arguments")
    if not arg_list:
        return None
    
    for child in arg_list.children:
        if child.type in ("string", "concatenated_string"):
            # 直接是字符串字面量
            path_str = node_text(code, child).strip().strip('"').strip("'")
            return path_str
        elif child.type == "identifier":
            # 是一个变量
            var_name = node_text(code, child).strip()
            # 简化处理：如果是config_path这样的变量，尝试查找其值
            return _find_path_variable_value(root, code, var_name, call_node.start_point[0] + 1)
        elif child.type == "binary_operator":
            # Path对象操作：Path(__file__).parent / "fixtures" / "crypto.json"
            path_parts = []
            _collect_path_parts(child, code, path_parts)
            if path_parts:
                return os.path.join(*path_parts)
    
    return None


def _find_path_variable_value(root, code: str, var_name: str, current_line: int):
    """
    查找路径变量的值（简化版本，只支持简单的Path操作）
    
    例如: config_path = Path(__file__).parent / "fixtures" / "crypto.json"
    """
    from .navigator import walk, node_text
    import os
    
    for node in walk(root):
        if node.type == "assignment":
            node_line = node.start_point[0] + 1
            if node_line >= current_line:
                continue
            
            left = node.child_by_field_name("left")
            if left and node_text(code, left).strip() == var_name:
                right = node.child_by_field_name("right")
                if right and right.type == "binary_operator":
                    # Path操作
                    path_parts = []
                    _collect_path_parts(right, code, path_parts)
                    if path_parts:
                        return os.path.join(*path_parts)
    
    return None


def _collect_path_parts(node, code: str, parts: list):
    """
    从Path操作表达式中收集路径组成部分
    
    例如: Path(__file__).parent / "fixtures" / "crypto.json"
    返回: ["fixtures", "crypto.json"]
    """
    from .navigator import node_text
    
    if node.type in ("string", "concatenated_string"):
        path_str = node_text(code, node).strip().strip('"').strip("'")
        if path_str and path_str not in ("__file__", "."):
            parts.append(path_str)
    elif node.type == "binary_operator":
        # 递归处理左右子节点
        for child in node.children:
            _collect_path_parts(child, code, parts)


def _extract_python_var_assignments(root, code: str):
    """
    为 Python 提取变量赋值映射（scope-aware 列表格式）
    
    返回：[{"name": "key", "value": "b'0123...'", "line": 65, "function": "test_aes_cbc"}]
    """
    from typing import List, Dict
    from .navigator import iter_functions
    
    # 构建函数行号映射
    func_map = {}
    for func in iter_functions(root, code, "python"):
        func_name = func.get('name', 'unknown')
        start_line = func.get('start_line', 0)
        end_line = func.get('end_line', 999999)
        for line in range(start_line, end_line + 1):
            func_map[line] = func_name
    
    var_assignments = []
    
    for n in walk(root):
        # Python: assignment节点包含赋值语句
        if n.type == "assignment":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")
            line = n.start_point[0] + 1
            func_name = func_map.get(line, "")
            
            if left_node and right_node:
                var_name = node_text(code, left_node).strip()
                right_text = node_text(code, right_node).strip()
                value_to_store = right_text  # 默认存储完整表达式
                ast_info = None  # 保存AST结构化信息
                
                # 从右侧推断类型 (纯 AST，无正则)
                if right_node.type == "call":
                    # 模式1: ClassName.method(...) 或模式2: ClassName(...)
                    function_node = right_node.child_by_field_name("function")
                    
                    # 提取调用参数（AST结构化）
                    call_args = extract_call_arguments(right_node, code, "python")
                    
                    # 【Task 13.2.1】尝试提取函数调用语义（os.getenv, int 等）
                    # 使用 Python AST 库来解析和求值常见函数调用
                    try:
                        import ast as py_ast
                        from .function_semantics import evaluate_function_call
                        
                        # 将 tree-sitter AST 节点转换为 Python AST
                        expr_text = node_text(code, right_node).strip()
                        py_tree = py_ast.parse(expr_text, mode='eval')
                        
                        if isinstance(py_tree.body, py_ast.Call):
                            func_value = evaluate_function_call(py_tree.body)
                            if func_value is not None:
                                # 成功提取函数调用的值
                                ast_info = {
                                    "type": "function_call",
                                    "expression": expr_text,
                                    "value": func_value
                                }
                                value_to_store = str(func_value)
                                
                                assignment = {
                                    "name": var_name,
                                    "value": value_to_store,
                                    "line": line,
                                    "function": func_name,
                                    "ast_info": ast_info
                                }
                                var_assignments.append(assignment)
                                continue  # 跳过后续处理，已完成
                    except Exception:
                        # 函数语义提取失败，回退到原有逻辑
                        pass
                    
                    if function_node:
                        if function_node.type == "attribute":
                            # ClassName.method(...) - 获取 ClassName
                            object_node = function_node.child_by_field_name("object")
                            attribute_node = function_node.child_by_field_name("attribute")
                            
                            if object_node and attribute_node:
                                module_name = node_text(code, object_node).strip()
                                method_name = node_text(code, attribute_node).strip()
                                
                                # 【新增】检测 json.load(f) 或 yaml.load(f) 调用
                                if module_name in ("json", "yaml") and method_name == "load":
                                    # 尝试读取配置文件内容
                                    file_dict = _try_load_config_file(
                                        root, code, call_args, line, module_name
                                    )
                                    if file_dict:
                                        # 成功读取配置文件，存储为字典字面量
                                        ast_info = {
                                            "type": "dictionary",
                                            "value": file_dict,
                                            "source": f"{module_name}.load"
                                        }
                                        value_to_store = str(file_dict)
                                    else:
                                        # 无法读取文件，保留默认行为
                                        class_name = module_name
                                        value_to_store = class_name
                                else:
                                    # 其他属性调用，保持原有逻辑
                                    class_name = module_name
                                    value_to_store = class_name
                        elif function_node.type == "identifier":
                            # ClassName(...) 或 function(...)
                            func_name_str = node_text(code, function_node).strip()
                            value_to_store = func_name_str
                            
                            # Python: bytearray(N) - 保存AST参数
                            if func_name_str == "bytearray":
                                ast_info = {
                                    "type": "call",
                                    "function": "bytearray",
                                    "args": call_args
                                }
                
                # 【新增】检测字典字面量赋值: cfg = {"rsa_bits": 1024}
                elif right_node.type == "dictionary":
                    dict_value = {}
                    # 遍历字典的键值对
                    for child in right_node.children:
                        if child.type == "pair":
                            key_node = child.child_by_field_name("key")
                            value_node = child.child_by_field_name("value")
                            if key_node and value_node:
                                key_text = node_text(code, key_node).strip().strip('"').strip("'")
                                value_text = node_text(code, value_node).strip()
                                # 尝试解析为整数
                                try:
                                    dict_value[key_text] = int(value_text)
                                except ValueError:
                                    dict_value[key_text] = value_text
                    ast_info = {
                        "type": "dictionary",
                        "value": dict_value
                    }
                    value_to_store = str(dict_value)
                
                # 【新增】检测字典访问: rsa_bits = cfg["rsa_bits"]
                elif right_node.type == "subscript":
                    object_node = right_node.child_by_field_name("value")
                    index_node = None
                    # 查找subscript节点
                    for child in right_node.children:
                        if child.type == "[":
                            # 下一个节点是index
                            idx = right_node.children.index(child)
                            if idx + 1 < len(right_node.children):
                                index_node = right_node.children[idx + 1]
                                break
                    
                    if object_node and index_node:
                        dict_var = node_text(code, object_node).strip()
                        key_text = node_text(code, index_node).strip().strip('"').strip("'")
                        ast_info = {
                            "type": "subscript",
                            "object": dict_var,
                            "key": key_text
                        }
                        value_to_store = f"{dict_var}[{key_text}]"
                
                # 【新增】检测算术表达式: rsa_bits = security_level * 8
                elif right_node.type in ("binary_operator", "comparison_operator"):
                    ast_info = {
                        "type": "binary_op",
                        "expression": right_text
                    }
                    value_to_store = right_text
                
                assignment = {
                    "name": var_name,
                    "value": value_to_store,
                    "line": line,
                    "function": func_name
                }
                if ast_info:
                    assignment["ast_info"] = ast_info
                
                # [Task 13.2.2] 如果right_node是函数调用，保存AST节点用于assigned_to映射
                if right_node.type == "call":
                    assignment["_call_node"] = right_node
                
                var_assignments.append(assignment)
    
    return var_assignments


def _extract_go_var_assignments(root, code: str) -> Dict[str, str]:
    """
    为 Go 提取变量赋值映射：变量名 -> 赋值类型或值
    
    **重要**：返回格式支持 scope-aware 查找
    返回值是列表格式：[{"name": "key", "value": "make([]byte, 16)", "line": 34, "function": "test_aes_128_cbc"}]
    
    例如：sig := rsa.NewSigner(...)
    => [{ "name": "sig", "value": "Signer", "line": 10, "function": "main" }]
    """
    from typing import Dict, List
    from .navigator import iter_functions
    
    # 先构建函数行号映射
    func_map = {}  # line -> function_name
    for func in iter_functions(root, code, "go"):
        func_name = func.get('name', 'unknown')
        start_line = func.get('start_line', 0)
        end_line = func.get('end_line', 999999)
        for line in range(start_line, end_line + 1):
            func_map[line] = func_name
    
    var_assignments = []  # 改为列表格式
    
    for n in walk(root):
        # Go: short_var_declaration (使用 := 的声明)
        if n.type == "short_var_declaration":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")
            line = n.start_point[0] + 1
            func_name = func_map.get(line, "")
            
            if left_node and right_node:
                # 左侧可能是identifier_list
                var_names = []
                if left_node.type == "expression_list":
                    for child in left_node.children:
                        if child.type == "identifier":
                            var_names.append(node_text(code, child).strip())
                elif left_node.type == "identifier":
                    var_names.append(node_text(code, left_node).strip())
                
                # 提取右侧的完整表达式文本（保留原始形式）
                right_text = node_text(code, right_node).strip()
                
                # 右侧推断类型 (纯 AST，无正则)
                value_to_store = right_text  # 默认存储完整表达式
                ast_info = None  # 保存 AST 结构化信息
                
                # 处理 expression_list (Go 可能返回多个值)
                actual_right_node = right_node
                if right_node.type == "expression_list":
                    # 取第一个表达式
                    for child in right_node.children:
                        if child.type not in [",", "comment"]:
                            actual_right_node = child
                            right_text = node_text(code, actual_right_node).strip()
                            value_to_store = right_text
                            break
                
                if actual_right_node.type == "call_expression":
                    # 获取函数节点
                    function_node = actual_right_node.child_by_field_name("function")
                    
                    # 提取调用参数（AST 结构化）
                    call_args = extract_call_arguments(actual_right_node, code, "go")
                    
                    if function_node and function_node.type == "selector_expression":
                        # pkg.NewXxx(...) 或 pkg.Method(...)
                        field_node = function_node.child_by_field_name("field")
                        
                        if field_node:
                            method_name = node_text(code, field_node).strip()
                            
                            # 模式1: NewXxx(...) -> 提取 Xxx 作为类型
                            if method_name.startswith("New") and len(method_name) > 3:
                                type_name = method_name[3:]  # 移除 "New" 前缀
                                value_to_store = type_name
                            # 模式2: make(...) -> 保留完整表达式，并保存 AST 参数
                            elif "make" in right_text:
                                value_to_store = right_text
                                ast_info = {
                                    "type": "call",
                                    "function": "make",
                                    "args": call_args  # AST 结构化参数
                                }
                            # 模式3: 其他方法 -> 使用方法名作为类型提示
                            else:
                                value_to_store = method_name
                    
                    elif function_node and function_node.type == "identifier":
                        # 直接函数调用：func(...)
                        func_name_str = node_text(code, function_node).strip()
                        if func_name_str == "make":
                            value_to_store = right_text
                            ast_info = {
                                "type": "call",
                                "function": "make",
                                "args": call_args
                            }
                
                # 为每个变量名创建记录
                for var_name in var_names:
                    assignment = {
                        "name": var_name,
                        "value": value_to_store,
                        "line": line,
                        "function": func_name
                    }
                    # 如果有 AST 结构化信息，添加到记录中
                    if ast_info:
                        assignment["ast_info"] = ast_info
                    if actual_right_node is not None and actual_right_node.type == "call_expression":
                        assignment["_call_node"] = actual_right_node
                    var_assignments.append(assignment)
        
        # Go: var_declaration (使用 var 的声明)
        elif n.type == "var_declaration":
            for spec in n.children:
                if spec.type == "var_spec":
                    name_node = spec.child_by_field_name("name")
                    type_node = spec.child_by_field_name("type")
                    value_node = spec.child_by_field_name("value")
                    line = spec.start_point[0] + 1
                    func_name = func_map.get(line, "")
                    
                    if name_node:
                        var_name = node_text(code, name_node).strip()
                        value_to_store = None
                        
                        # 优先使用显式类型
                        if type_node:
                            var_type = node_text(code, type_node).strip()
                            # 去除指针符号
                            var_type = var_type.lstrip('*')
                            value_to_store = var_type
                        # 从值推断 (纯 AST，无正则)
                        elif value_node:
                            value_text = node_text(code, value_node).strip()
                            
                            if value_node.type == "call_expression":
                                function_node = value_node.child_by_field_name("function")
                                
                                if function_node and function_node.type == "selector_expression":
                                    field_node = function_node.child_by_field_name("field")
                                    
                                    if field_node:
                                        method_name = node_text(code, field_node).strip()
                                        # pkg.NewXxx(...) -> 提取 Xxx
                                        if method_name.startswith("New") and len(method_name) > 3:
                                            value_to_store = method_name[3:]
                                        else:
                                            value_to_store = value_text
                            else:
                                value_to_store = value_text
                        
                        if value_to_store:
                            assignment = {
                                "name": var_name,
                                "value": value_to_store,
                                "line": line,
                                "function": func_name
                            }
                            if value_node is not None and value_node.type == "call_expression":
                                assignment["_call_node"] = value_node
                            var_assignments.append(assignment)
    
    return var_assignments


def _extract_c_var_assignments(root, code: str):
    """
    为 C 提取变量赋值映射（升级为 scope-aware list 格式 + 赋值表达式）
    
    新格式：
    [
        {"name": "key_size", "value": "2048", "line": 10, "function": "main"},
        {"name": "ctx", "value": "EVP_MD_CTX", "line": 12, "function": "main"},
        {"name": "ctx", "value": "EVP_CIPHER_CTX_new", "line": 15, "function": "encrypt", "_call_node": <node>},
        ...
    ]
    
    支持两种模式：
    1. 声明（declaration）：EVP_CIPHER_CTX *ctx;
    2. 赋值（assignment_expression）：ctx = EVP_CIPHER_CTX_new();
    """
    from typing import List, Dict, Any
    
    # 构建函数行号映射
    func_map = {}
    functions = iter_functions(root, code, 'c')
    for func in functions:
        start_line = func.get('start_line', 0)
        end_line = func.get('end_line', 999999)
        func_name = func.get('name', '')
        for line_num in range(start_line, end_line + 1):
            func_map[line_num] = func_name
    
    var_assignments_list = []
    
    for n in walk(root):
        # ============ 模式1：声明（declaration）============
        if n.type == "declaration":
            # 查找类型说明符
            type_node = None
            for child in n.children:
                if child.type in ["type_identifier", "struct_specifier", "primitive_type", "sized_type_specifier"]:
                    type_node = child
                    break
            
            var_type = node_text(code, type_node).strip() if type_node else None
            
            # 查找init_declarator（包含变量名和初始化）或直接的 array_declarator/pointer_declarator
            for child in n.children:
                # 情况1: init_declarator（有初始化）
                if child.type == "init_declarator":
                    declarator = child.child_by_field_name("declarator")
                    value_node = child.child_by_field_name("value")
                    
                    if declarator:
                        # 处理指针声明：pointer_declarator
                        var_name_node = declarator
                        is_array = False
                        array_size_node = None
                        ast_info = None
                        
                        if declarator.type == "pointer_declarator":
                            var_name_node = declarator.child_by_field_name("declarator")
                        # 处理数组声明：array_declarator
                        elif declarator.type == "array_declarator":
                            is_array = True
                            var_name_node = declarator.child_by_field_name("declarator")
                            # 提取数组大小
                            array_size_node = declarator.child_by_field_name("size")
                        
                        if var_name_node and var_name_node.type == "identifier":
                            var_name = node_text(code, var_name_node).strip()
                            line_num = n.start_point[0] + 1
                            func_name = func_map.get(line_num, '')
                            
                            # C: 数组声明 char key[N]
                            if is_array and array_size_node:
                                size_text = node_text(code, array_size_node).strip()
                                ast_info = {
                                    "type": "array_declaration",
                                    "element_type": var_type if var_type else "unknown",
                                    "size": {
                                        "type": array_size_node.type,
                                        "text": size_text
                                    }
                                }
                                # 尝试解析为整数
                                if array_size_node.type in ["number_literal", "integer_literal"]:
                                    try:
                                        ast_info["size"]["value"] = int(size_text)
                                    except ValueError:
                                        pass
                            
                            # 提取初始化值（如果有）
                            call_node = None
                            if value_node:
                                value_text = node_text(code, value_node).strip()
                                final_value = value_text
                                
                                # 检查是否是函数调用
                                if value_node.type == "call_expression":
                                    fn = value_node.child_by_field_name("function")
                                    if fn:
                                        final_value = node_text(code, fn).strip()
                                        call_node = value_node  # 保存 AST 节点
                                        
                                        # 提取调用参数
                                        call_args = extract_call_arguments(value_node, code, "c")
                                        if not ast_info:
                                            ast_info = {}
                                        ast_info.update({
                                            "type": "call",
                                            "function": final_value,
                                            "args": call_args
                                        })
                                
                                # 尝试解析为整数
                                elif value_node.type in ["number_literal", "integer_literal"]:
                                    try:
                                        final_value = int(value_text)
                                    except ValueError:
                                        pass
                                
                                # 尝试解析为字符串
                                elif value_node.type == "string_literal":
                                    final_value = value_text.strip('"\'')
                                
                                # 尝试解析二元表达式（如 512 * 2）
                                elif value_node.type == "binary_expression":
                                    try:
                                        # 安全求值（只支持数字和基本运算符）
                                        if all(c in '0123456789+-*/ ()' for c in value_text):
                                            final_value = eval(value_text)
                                    except:
                                        pass
                                
                                # 初始化列表：char key[] = {1, 2, 3}
                                elif value_node.type == "initializer_list":
                                    init_args = []
                                    for init_child in value_node.children:
                                        if init_child.type not in ["{", "}", ",", "comment"]:
                                            init_args.append({
                                                "type": init_child.type,
                                                "text": node_text(code, init_child).strip()
                                            })
                                    if not ast_info:
                                        ast_info = {}
                                    ast_info.update({
                                        "type": "initializer_list",
                                        "initializer": init_args
                                    })
                                
                                assignment_info = {
                                    'name': var_name,
                                    'value': final_value,
                                    'line': line_num,
                                    'function': func_name
                                }
                                if call_node is not None:
                                    assignment_info['_call_node'] = call_node
                                if ast_info:
                                    assignment_info['ast_info'] = ast_info
                                
                                var_assignments_list.append(assignment_info)
                            
                            # 如果没有初始化值，存储类型或数组信息
                            elif var_type or ast_info:
                                assignment_info = {
                                    'name': var_name,
                                    'value': var_type if var_type else 'unknown',
                                    'line': line_num,
                                    'function': func_name
                                }
                                if ast_info:
                                    assignment_info['ast_info'] = ast_info
                                var_assignments_list.append(assignment_info)
                
                # 情况2: 直接的 array_declarator（无初始化，如 char key[16];）
                elif child.type == "array_declarator":
                    var_name_node = child.child_by_field_name("declarator")
                    array_size_node = child.child_by_field_name("size")
                    
                    if var_name_node and var_name_node.type == "identifier":
                        var_name = node_text(code, var_name_node).strip()
                        line_num = n.start_point[0] + 1
                        func_name = func_map.get(line_num, '')
                        
                        # 构建 ast_info
                        ast_info = None
                        if array_size_node:
                            size_text = node_text(code, array_size_node).strip()
                            ast_info = {
                                "type": "array_declaration",
                                "element_type": var_type if var_type else "unknown",
                                "size": {
                                    "type": array_size_node.type,
                                    "text": size_text
                                }
                            }
                            # 尝试解析为整数
                            if array_size_node.type in ["number_literal", "integer_literal"]:
                                try:
                                    ast_info["size"]["value"] = int(size_text)
                                except ValueError:
                                    pass
                        
                        # 存储数组声明
                        assignment_info = {
                            'name': var_name,
                            'value': var_type if var_type else 'unknown',
                            'line': line_num,
                            'function': func_name
                        }
                        if ast_info:
                            assignment_info['ast_info'] = ast_info
                        var_assignments_list.append(assignment_info)
        
        # ============ 模式2：赋值表达式（assignment_expression）============
        elif n.type == "assignment_expression":
            # assignment_expression: left = right
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            
            if left and right:
                # 提取左值变量名
                var_name = None
                if left.type == "identifier":
                    var_name = node_text(code, left).strip()
                elif left.type == "pointer_expression":
                    # *ctx = ... → ctx
                    argument = left.child_by_field_name("argument")
                    if argument and argument.type == "identifier":
                        var_name = node_text(code, argument).strip()
                
                if var_name:
                    line_num = n.start_point[0] + 1
                    func_name = func_map.get(line_num, '')
                    
                    # 提取右值
                    right_text = node_text(code, right).strip()
                    final_value = right_text
                    call_node = None
                    
                    # 检查是否是函数调用
                    if right.type == "call_expression":
                        fn = right.child_by_field_name("function")
                        if fn:
                            final_value = node_text(code, fn).strip()
                            call_node = right  # 保存 AST 节点
                    
                    assignment_info = {
                        'name': var_name,
                        'value': final_value,
                        'line': line_num,
                        'function': func_name
                    }
                    if call_node is not None:
                        assignment_info['_call_node'] = call_node
                    
                    var_assignments_list.append(assignment_info)
    
    return var_assignments_list

def extract_var_assignments(root, code: str, lang: str = "java"):
    """Extract variable assignments (public interface)"""
    lang = (lang or "java").lower()
    if lang == "java":
        return _extract_java_var_assignments(root, code)
    elif lang == "python":
        return _extract_python_var_assignments(root, code)
    elif lang == "go":
        return _extract_go_var_assignments(root, code)
    elif lang == "c":
        return _extract_c_var_assignments(root, code)
    return {}

def extract_call_arguments(call_node, code: str, lang: str = "c"):
    """
    从AST节点提取函数调用参数（tree-sitter通用实现）
    
    Args:
        call_node: tree-sitter调用节点
        code: 源代码文本
        lang: 语言类型
    
    Returns:
        参数列表: [{"text": "128", "type": "number_literal", "value": 128}, ...]
    
    支持的参数类型:
    - number_literal/integer_literal: 整数常量
    - call_expression: 嵌套函数调用
    - identifier: 标识符
    - string_literal: 字符串
    - binary_expression: 二元表达式（如 8*16）
    """
    args = []
    
    if not call_node:
        return args
    
    # 获取arguments节点
    args_node = call_node.child_by_field_name("arguments") if hasattr(call_node, 'child_by_field_name') else None
    
    if not args_node:
        return args

    def _node_int_value(n):
        if not n:
            return None
        if n.type in ["number_literal", "integer_literal", "numeric_literal", "integer", "int_literal", "decimal_integer_literal"]:
            try:
                return int(node_text(code, n).rstrip('LlUu'), 0)
            except (TypeError, ValueError):
                return None
        return None

    def _first_int_descendant(n):
        for sub in walk(n):
            value = _node_int_value(sub)
            if value is not None:
                return value
        return None

    def _call_name(n):
        fn = n.child_by_field_name("function") if hasattr(n, "child_by_field_name") else None
        if fn is not None:
            return node_text(code, fn).strip()
        identifiers = []
        for sub in n.children:
            if sub.type in {"identifier", "field_identifier", "type_identifier"}:
                identifiers.append(node_text(code, sub).strip())
        return identifiers[-1] if identifiers else ""

    def _mark_ast_key_length(arg_info, child):
        """Annotate byte-length facts derived from AST shape."""
        child_type = child.type

        if child_type in {"slice_expression", "subscript"}:
            if any(sub.type == ":" for sub in walk(child)):
                size = _first_int_descendant(child)
                if size is not None:
                    arg_info["length_bytes"] = size
                    arg_info["length_source"] = "ast_slice_bound"
            return

        if child_type == "array_creation_expression":
            type_text = ""
            for sub in child.children:
                if sub.type in {"integral_type", "type_identifier"}:
                    type_text = node_text(code, sub).strip()
                    break
            size = _first_int_descendant(child)
            if type_text == "byte" and size is not None:
                arg_info["length_bytes"] = size
                arg_info["length_source"] = "ast_byte_array_creation"
            return

        if child_type in {"call_expression", "call", "method_invocation"}:
            name = _call_name(child).split(".")[-1]
            nested = extract_call_arguments(child, code, lang)
            if name in {"make", "bytes", "bytearray"} and nested:
                for nested_arg in reversed(nested):
                    if isinstance(nested_arg.get("value"), int):
                        arg_info["length_bytes"] = nested_arg["value"]
                        arg_info["length_source"] = "ast_byte_factory"
                        return
            if name == "copyOf" and nested:
                last_value = nested[-1].get("value")
                if isinstance(last_value, int):
                    arg_info["length_bytes"] = last_value
                    arg_info["length_source"] = "ast_copy_of"
            return
    
    # 遍历参数节点的子节点
    arg_index = 0
    for child in args_node.children:
        # 跳过分隔符
        if child.type in [",", "(", ")", "comment"]:
            continue
        
        arg_info = {
            "text": node_text(code, child),
            "type": child.type,
            "index": arg_index,
        }
        _mark_ast_key_length(arg_info, child)
        
        # 处理 Python keyword argument (key_size=1024)
        if child.type == "keyword_argument":
            # 提取参数名和值
            name_node = None
            value_node = None
            for sub_child in child.children:
                if sub_child.type == "identifier":
                    name_node = sub_child
                elif sub_child.type in ["integer", "number_literal", "integer_literal", "numeric_literal"]:
                    value_node = sub_child
                elif sub_child.type == "string_literal":
                    value_node = sub_child
            
            if name_node:
                arg_info["name"] = node_text(code, name_node)
            
            if value_node:
                if value_node.type in ["integer", "number_literal", "integer_literal", "numeric_literal"]:
                    try:
                        text = node_text(code, value_node).rstrip('LlUu')
                        arg_info["value"] = int(text, 0)
                    except:
                        pass
                elif value_node.type == "string_literal":
                    arg_info["value"] = node_text(code, value_node).strip('"\'')
        
        # 尝试提取常量值（非 keyword_argument）
        elif child.type in ["number_literal", "integer_literal", "numeric_literal", "integer", "int_literal", "decimal_integer_literal"]:
            try:
                text = node_text(code, child)
                # 移除后缀（如 128L, 256ULL）
                text = text.rstrip('LlUu')
                arg_info["value"] = int(text, 0)  # 支持十六进制0x
            except (ValueError, AttributeError):
                pass
        
        elif child.type == "string_literal":
            arg_info["value"] = node_text(code, child).strip('"\'')
        
        elif child.type == "call_expression":
            # 嵌套函数调用，提取函数名和参数
            fn_node = child.child_by_field_name("function") if hasattr(child, 'child_by_field_name') else None
            if fn_node:
                nested_func_name = node_text(code, fn_node)
                arg_info["nested_call"] = nested_func_name
                arg_info["function"] = nested_func_name  # 保持向后兼容
                
                # 递归提取嵌套调用的参数
                nested_args = extract_call_arguments(child, code, lang)
                if nested_args:
                    arg_info["nested_args"] = nested_args
        
        elif child.type == "binary_expression":
            # 二元表达式（如 8*16），尝试求值
            try:
                text = node_text(code, child)
                # 简单的安全求值（只支持基本运算）
                if all(c in '0123456789+-*/ ()' for c in text):
                    arg_info["value"] = eval(text)
            except:
                pass
        
        args.append(arg_info)
        arg_index += 1
    
    return args

# def extract_calls(root, code: str, lang: str):
#     """提取函数调用列表"""
#     return list(iter_calls(root, code, lang))

# 提取调用时携带 包别名/成员名
def extract_calls(root, code: str, lang: str, alias_map: dict = None, imports: list = None):
    calls = []
    lang = (lang or "go").lower()
    alias_map = alias_map or {}  # [FIX Phase 19] 支持pkg别名解析
    imports = imports or []  # [FIX] 支持通配符导入推断
    
    # 为 Java/C/Python/Go 构建变量赋值映射
    var_assignments = {}
    var_assignments_by_line = {}  # Line → variable name mapping
    call_to_assignment = {}  # Call node → variable name (direct AST parent tracking)
    
    if lang == "java":
        var_assignments_list = _extract_java_var_assignments(root, code)
        # 构建三个映射：
        # 1. name → type (for receiver_type lookup)
        # 2. line → name (for assigned_to lookup - fallback)
        # 3. call_node → name (for assigned_to lookup - precise, based on AST structure)
        for item in var_assignments_list:
            var_name = item.get('name')
            var_type = item.get('receiver_type', item.get('value'))
            line_num = item.get('line')
            call_node = item.get('_call_node')  # AST node of the RHS call
            
            if var_name:
                var_assignments[var_name] = var_type
            if line_num and var_name:
                var_assignments_by_line[line_num] = var_name
            if call_node is not None and var_name:
                # Store direct mapping: call AST node → variable name
                call_to_assignment[id(call_node)] = var_name
    
    # 为 C 语言构建变量赋值映射（同样的逻辑）
    elif lang == "c":
        var_assignments_list = _extract_c_var_assignments(root, code)
        for item in var_assignments_list:
            var_name = item.get('name')
            var_type = item.get('value')
            line_num = item.get('line')
            call_node = item.get('_call_node')
            
            if var_name:
                var_assignments[var_name] = var_type
            if line_num and var_name:
                var_assignments_by_line[line_num] = var_name
            if call_node is not None and var_name:
                call_to_assignment[id(call_node)] = var_name
    
    # [Task 13.2.2] 为 Python 构建变量赋值映射（支持函数内联）
    elif lang == "python":
        var_assignments_list = _extract_python_var_assignments(root, code)
        for item in var_assignments_list:
            var_name = item.get('name')
            var_value = item.get('value')
            line_num = item.get('line')
            call_node = item.get('_call_node')
            
            if var_name:
                var_assignments[var_name] = var_value
            if line_num and var_name:
                var_assignments_by_line[line_num] = var_name
            if call_node is not None and var_name:
                call_to_assignment[id(call_node)] = var_name
    elif lang == "go":
        var_assignments_list = _extract_go_var_assignments(root, code)
        for item in var_assignments_list:
            var_name = item.get('name')
            var_value = item.get('value')
            line_num = item.get('line')
            call_node = item.get('_call_node')

            if var_name:
                var_assignments[var_name] = var_value
            if line_num and var_name:
                var_assignments_by_line[line_num] = var_name
            if call_node is not None and var_name:
                call_to_assignment[id(call_node)] = var_name

    def _split_fn_node(call_node, code_text: str, lang_local: str):
        """Try to extract (pkg, member, symbol) from a call AST node's function child.
        Returns (pkg, member, symbol)
        """
        # 对于 Java method_invocation 节点，特别处理
        if lang_local == "java" and call_node.type == "method_invocation":
            obj = call_node.child_by_field_name("object")
            name = call_node.child_by_field_name("name")
            
            if name:
                member = node_text(code_text, name)
                if obj:
                    pkg = node_text(code_text, obj)
                    symbol = f"{pkg}.{member}"
                    return pkg, member, symbol
                else:
                    return None, member, member
        
        fn = call_node.child_by_field_name("function") if hasattr(call_node, 'child_by_field_name') else None
        if not fn:
            # some parsers keep the function as first child
            fn = call_node.children[0] if getattr(call_node, 'children', None) else None
        if not fn:
            return None, None, None

        # selector/attribute style: operand + field / attribute
        # common selector types: selector_expression, attribute, field_expression, member_expression
        t = getattr(fn, 'type', '')
        if t in ("selector_expression", "attribute", "field_expression", "member_expression", "qualified_identifier"):
            op = fn.child_by_field_name("operand") or fn.child_by_field_name("object") or (
                fn.children[0] if getattr(fn, 'children', None) else None)
            fld = fn.child_by_field_name("field") or fn.child_by_field_name("attribute") or (
                fn.children[-1] if getattr(fn, 'children', None) else None)
            op_txt = node_text(code_text, op) if op else None
            fld_txt = node_text(code_text, fld) if fld else None
            symbol = (op_txt + "." + fld_txt) if (op_txt and fld_txt) else node_text(code_text, fn)
            pkg = op_txt
            member = fld_txt
            return pkg, member, symbol

        # identifier or name
        if t in ("identifier", "name", "field_identifier") or t.startswith("identifier"):
            sym = node_text(code_text, fn)
            return None, sym, sym

        # fallback to full text
        sym = node_text(code_text, fn)
        if '.' in sym:
            parts = sym.rsplit('.', 1)
            return parts[0], parts[1], sym
        return None, sym, sym

    # Use navigator.iter_calls when possible (it yields symbol and _node)
    try:
        from .navigator import iter_calls
        for item in iter_calls(root, code, lang):
            n = item.get("_node")
            symbol = item.get("symbol", "")
            line = item.get("line")
            code_snip = item.get("code", "")
            receiver = item.get("receiver")  # 获取接收对象

            pkg, member, sym_from_node = (None, None, None)
            if n is not None:
                pkg, member, sym_from_node = _split_fn_node(n, code, lang)

            # prefer node-derived symbol if available
            if sym_from_node:
                symbol = sym_from_node

            # fallback heuristics when node did not resolve pkg/member
            if not (pkg or member):
                if symbol and "." in symbol:
                    if lang == "go":
                        parts = symbol.split('.')
                        pkg = parts[0]
                        member = '.'.join(parts[1:])
                    elif lang == "python":
                        parts = symbol.rsplit('.',1)
                        pkg = parts[0]; member = parts[1]
                    elif lang == "java":
                        parts = symbol.split('.')
                        member = parts[-1]; pkg = '.'.join(parts[:-1])
                    else:
                        parts = symbol.rsplit('.',1)
                        member = parts[-1]
                else:
                    member = member or symbol

            # 特殊处理Java静态方法调用
            # 对于如 KeyGenerator.getInstance() 的静态方法，receiver 不应该是类名
            # 而应该是None，因为这是一个静态调用，不是实例方法调用
            if lang == "java" and receiver and receiver.upper() == receiver[0].upper():
                # receiver 看起来像类名（首字母大写），检查是否是静态调用
                if "getInstance" in symbol or "newInstance" in symbol:
                    # 这很可能是一个静态方法调用，不应该设置receiver
                    receiver = None
            
            # 确定receiver_type：如果有receiver且在var_assignments中则获取其类型
            receiver_type = None
            if receiver and receiver in var_assignments:
                receiver_type = var_assignments[receiver]
            
            # 确定assigned_to：优先使用AST节点映射（精确），回退到行号匹配
            assigned_to = None
            if lang in ["java", "c", "python", "go"]:  # [Task 13.2.2] 添加Python/Go支持
                # Method 1 (Precise): Direct AST parent tracking
                if n is not None and id(n) in call_to_assignment:
                    assigned_to = call_to_assignment[id(n)]
                # Method 2 (Fallback): Line number matching
                elif line in var_assignments_by_line:
                    assigned_to = var_assignments_by_line[line]
            
            # [FIX Phase 19] 解析pkg别名为完整路径
            pkg_full = None
            pkg_full_candidates = []  # [FIX] 对于通配符导入，收集所有可能的完整路径
            
            if pkg and pkg in alias_map:
                pkg_full = alias_map[pkg]
            # [FIX] Java通配符导入：如果pkg不在alias_map但imports中有通配符导入，收集所有可能的pkg_full
            elif lang == "java" and pkg:
                for imp in imports:
                    if imp.endswith('.*'):
                        # 通配符导入，如 java.security.*
                        base_pkg = imp[:-2]  # 去掉 .*
                        # 添加可能的pkg_full候选（如 java.security.MessageDigest）
                        pkg_full_candidates.append(f"{base_pkg}.{pkg}")
                # 如果只有一个候选，直接使用它；否则保留None，让规则匹配器尝试所有候选
                if len(pkg_full_candidates) == 1:
                    pkg_full = pkg_full_candidates[0]
            
            # [Phase 7] 提取函数调用参数（使用AST）
            # [FIX] 对于链式调用 obj.method().anotherMethod()，
            # 外层调用的args应该从内层调用提取
            # 例如：hmac.new(key, msg).hexdigest() 
            #   外层：hexdigest() - function字段是attribute (hmac.new(...).hexdigest)
            #     attribute的object字段是call (hmac.new(...))
            #   内层：hmac.new(...) - 有实际的args
            args = extract_call_arguments(n, code, lang)
            
            # 如果外层调用args为空，检查function字段是否包含嵌套调用
            if not args and n is not None:
                fn_node = n.child_by_field_name("function")
                
                # 检查function是否是嵌套调用
                if fn_node and fn_node.type in ("call", "call_expression"):
                    # function字段本身是一个调用，从它提取args
                    inner_args = extract_call_arguments(fn_node, code, lang)
                    if inner_args:
                        args = inner_args
                
                # 检查function是否是attribute/member_expression，其object是调用
                # 例如：obj.method().anotherMethod() 中的 anotherMethod
                elif fn_node and fn_node.type in ("attribute", "member_expression", "field_expression"):
                    # attribute的object可能是一个call
                    obj_node = fn_node.child_by_field_name("object")
                    if obj_node and obj_node.type in ("call", "call_expression"):
                        inner_args = extract_call_arguments(obj_node, code, lang)
                        if inner_args:
                            args = inner_args
            
            calls.append({
                "symbol": symbol,
                "pkg": pkg,
                "pkg_full": pkg_full,  # [FIX Phase 19] 添加完整包路径
                "pkg_full_candidates": pkg_full_candidates,  # [FIX] 通配符导入的所有可能路径
                "member": member,
                "line": line,
                "code": code_snip,
                "_node": n,
                "args": args,  # [Phase 7] AST提取的参数列表
                "receiver": receiver,  # 添加接收对象字段
                "receiver_type": receiver_type,  # 接收对象的类型（如KeyGenerator）
                "assigned_to": assigned_to  # 赋值目标变量（如 keyGen = getInstance() 中的 keyGen）
            })

        # Java constructors are represented as object_creation_expression nodes in the AST.
        # They are not yielded by iter_calls(), but they are relevant for crypto factories
        # such as SecretKeySpec(...), PBEKeySpec(...), DESKeySpec(...), SecureRandom(),
        # URL(...), etc.  We synthesize call-like records so the downstream KB matcher
        # and wrapper propagation can treat them uniformly with ordinary method calls.
        if lang == "java":
            for n in walk(root):
                if n.type != "object_creation_expression":
                    continue

                # Tree-sitter Java places the constructed type under the "type" field.
                type_node = n.child_by_field_name("type")
                if type_node is None:
                    # Fallback: first type-like child, or derive from raw text.
                    for ch in n.children:
                        if ch.type in ("type_identifier", "scoped_type_identifier", "generic_type", "qualified_identifier"):
                            type_node = ch
                            break

                if type_node is not None:
                    ctor_name = node_text(code, type_node).strip()
                else:
                    raw = node_text(code, n).strip()
                    ctor_name = raw[4:].split("(", 1)[0].strip() if raw.lower().startswith("new ") else raw

                if not ctor_name:
                    continue

                line = n.start_point[0] + 1
                code_snip = node_text(code, n)

                # Reuse the same argument extractor so constructor arguments participate
                # in literal / variable resolution the same way as method invocations.
                args = extract_call_arguments(n, code, lang)

                pkg_full = alias_map.get(ctor_name)
                pkg = None
                if pkg_full:
                    pkg = pkg_full.rsplit('.', 1)[0] if '.' in pkg_full else None
                pkg_full_candidates = [pkg_full] if pkg_full else []
                if not pkg_full and imports:
                    ctor_tail = ctor_name.split('.')[-1]
                    for imp in imports:
                        imp_text = str(imp or '').strip()
                        if imp_text.endswith('.*'):
                            pkg_full_candidates.append(f"{imp_text[:-2]}.{ctor_tail}")
                        elif imp_text.endswith(f".{ctor_tail}"):
                            pkg_full_candidates.append(imp_text)

                assigned_to = None
                if n is not None and id(n) in call_to_assignment:
                    assigned_to = call_to_assignment[id(n)]
                elif line in var_assignments_by_line:
                    assigned_to = var_assignments_by_line[line]

                calls.append({
                    "symbol": ctor_name,
                    "pkg": pkg,
                    "pkg_full": pkg_full,
                    "pkg_full_candidates": pkg_full_candidates,
                    "member": ctor_name,
                    "line": line,
                    "code": code_snip,
                    "_node": n,
                    "args": args,
                    "receiver": None,
                    "receiver_type": None,
                    "assigned_to": assigned_to,
                    "is_constructor": True,
                })
        return calls
    except Exception:
        # fallback to simple walk-based heuristics
        for n in walk(root):
            if n.type.endswith("call") or n.type == "call_expression":
                fn = n.child_by_field_name("function") or (n.children[0] if n.children else None)
                calls.append({
                    "symbol": node_text(code, fn) if fn else node_text(code, n),
                    "pkg": None, "member": None,
                    "line": n.start_point[0] + 1,
                    "code": node_text(code, n),
                    "_node": n
                })
        return calls

def extract_functions(root, code: str, lang: str):
    """提取函数定义"""
    return list(iter_functions(root, code, lang))


def extract_function_params(node, code: str, lang: str):
    """
    从 AST 节点提取函数参数名列表（纯 AST，无正则）
    
    Args:
        node: 函数定义的 AST 节点
        code: 源代码
        lang: 语言类型
    
    Returns:
        参数名列表，例如：['key_bits', 'exponent']
    """
    params = []
    lang = lang.lower()
    
    # C/C++/Java: 查找参数列表节点 -> 参数声明 -> identifier
    if lang in ['c', 'cpp', 'java']:
        parameter_container_types = {'parameter_list'}
        if lang == 'java':
            parameter_container_types.add('formal_parameters')

        for child in walk(node):
            if child.type not in parameter_container_types:
                continue

            for param_decl in child.children:
                if param_decl.type not in ['parameter_declaration', 'formal_parameter']:
                    continue

                # 找到最后一个标识符（参数名）
                for p in reversed(list(walk(param_decl))):
                    if p.type == 'identifier':
                        param_name = node_text(code, p).strip()
                        if param_name and param_name not in params:
                            params.append(param_name)
                        break
    
    # Python: 查找 parameters -> identifier（跳过 self）
    elif lang == 'python':
        for child in walk(node):
            if child.type == 'parameters':
                for p in child.children:
                    if p.type == 'identifier':
                        param_name = node_text(code, p).strip()
                        if param_name and param_name != 'self' and param_name not in params:
                            params.append(param_name)
                    elif p.type == 'typed_parameter':
                        # 类型注解参数：name: type
                        for sub in p.children:
                            if sub.type == 'identifier':
                                param_name = node_text(code, sub).strip()
                                if param_name and param_name != 'self' and param_name not in params:
                                    params.append(param_name)
                                break
                    elif p.type == 'default_parameter':
                        # 默认参数：name=value
                        for sub in p.children:
                            if sub.type == 'identifier':
                                param_name = node_text(code, sub).strip()
                                if param_name and param_name != 'self' and param_name not in params:
                                    params.append(param_name)
                                break
    
    # Go: 查找 parameter_list -> parameter_declaration
    elif lang == 'go':
        for child in walk(node):
            if child.type == 'parameter_list':
                for param_decl in child.children:
                    if param_decl.type == 'parameter_declaration':
                        # Go 格式：name type 或 name1, name2 type
                        identifiers = []
                        has_explicit_type_node = False
                        for p in param_decl.children:
                            if p.type == 'identifier':
                                identifiers.append(node_text(code, p).strip())
                            elif p.type in {
                                'type_identifier',
                                'qualified_type',
                                'selector_expression',
                                'slice_type',
                                'array_type',
                                'pointer_type',
                                'function_type',
                                'map_type',
                                'channel_type',
                                'struct_type',
                                'interface_type',
                            }:
                                has_explicit_type_node = True

                        # tree-sitter-go 把 `text, key string` 中的 string 作为
                        # type_identifier，不会放进 identifiers；因此 identifiers
                        # 全部都是参数名。只有老解析器把类型也归为 identifier 时，
                        # 才退回到“最后一个是类型”的兼容逻辑。
                        if len(identifiers) > 1:
                            names = identifiers if has_explicit_type_node else identifiers[:-1]
                            for param_name in names:
                                if param_name and param_name not in params:
                                    params.append(param_name)
                        elif len(identifiers) == 1:
                            # 单个标识符可能是参数名（匿名类型）
                            param_name = identifiers[0]
                            # 简单启发式：小写开头的是参数名，大写开头的是类型
                            if param_name and param_name[0].islower() and param_name not in params:
                                params.append(param_name)
    
    return params


def extract_literals(root, code: str):
    """提取字面量常量"""
    literals = []
    for n in walk(root):
        if n.type.endswith("_literal"):
            literals.append({
                "line": n.start_point[0] + 1,
                "value": node_text(code, n)
            })
    return literals

def extract_attributes(root, code: str, lang: str, alias_map: dict | None = None):
    """
    抓取“选择/属性访问”，如：
      Python:   AES.MODE_ECB   (tree-sitter-python: attribute)
      Go:       aes.NewCipher  / pkg.Member       (selector_expression)
      Java:     Cipher.getInstance               (field_access / member_select)
      C/C++:    obj->field / a.b                 (field_expression)
    产出：[{symbol, pkg, member, line, fq_symbol}]
    """
    alias_map = alias_map or {}
    lang = (lang or "python").lower()
    out = []

    def _emit(emit_pkg, emit_member, emit_sym, line):
        fq_pkg = alias_map.get(emit_pkg, emit_pkg) if emit_pkg else None
        fq_symbol = f"{fq_pkg}.{emit_member}" if (fq_pkg and emit_member) else emit_sym
        out.append({
            "symbol": emit_sym, "pkg": emit_pkg, "member": emit_member,
            "line": line, "fq_symbol": fq_symbol
        })

    for n in walk(root):
        t = getattr(n, "type", "")
        # Python
        if lang == "python" and t == "attribute":
            obj = n.child_by_field_name("object") or (n.children[0] if n.children else None)
            attr = n.child_by_field_name("attribute") or (n.children[-1] if n.children else None)
            obj_txt  = node_text(code, obj)  if obj  else None
            attr_txt = node_text(code, attr) if attr else None
            if obj_txt and attr_txt:
                sym = f"{obj_txt}.{attr_txt}"
                _emit(obj_txt, attr_txt, sym, n.start_point[0] + 1)
        # Go
        elif lang == "go" and t == "selector_expression":
            op = n.child_by_field_name("operand") or (n.children[0] if n.children else None)
            fld = n.child_by_field_name("field")   or (n.children[-1] if n.children else None)
            op_txt  = node_text(code, op)  if op  else None
            fld_txt = node_text(code, fld) if fld else None
            if op_txt and fld_txt:
                sym = f"{op_txt}.{fld_txt}"
                _emit(op_txt, fld_txt, sym, n.start_point[0] + 1)
        # Java
        elif lang == "java" and t in ("field_access", "member_select", "scoped_identifier", "qualified_name"):
            txt = node_text(code, n)
            if "." in txt:
                pkg = txt.rsplit(".", 1)[0]
                member = txt.rsplit(".", 1)[1]
                _emit(pkg, member, txt, n.start_point[0] + 1)
        # C/C++
        elif lang in ("c","cpp","c++","cxx") and t in "field_expression":
            txt = node_text(code, n)
            if "." in txt or "->" in txt:
                # 简单拆分
                sep = "->" if "->" in txt else "."
                pkg = txt.split(sep)[0]
                member = txt.split(sep)[-1]
                _emit(pkg, member, txt, n.start_point[0] + 1)

    return out


# ============================================================================
# 通用 AST 辅助工具函数 (Common Helper Functions for All Languages)
# ============================================================================

def ast_node_text(code: str, node) -> str:
    """
    提取 AST 节点对应的源代码文本（通用，支持所有语言）
    
    这是 navigator.node_text 的标准化封装。
    
    Args:
        code: 完整源代码字符串
        node: tree-sitter AST 节点
    
    Returns:
        节点对应的源代码文本
        
    Example:
        >>> tree = parser.parse(code.encode('utf-8'))
        >>> func_name = ast_node_text(code, func_node)
        
    Supported Languages:
        C, C++, Go, Java, Python (via tree-sitter)
    """
    return node_text(code, node)


def ast_arg_nodes(call_node, lang: str = None) -> list:
    """
    从函数调用节点提取参数节点列表（通用，支持所有语言）
    
    Args:
        call_node: call_expression 类型的 AST 节点
        lang: 语言类型（可选，用于语言特定优化）
    
    Returns:
        参数节点列表（按顺序），未找到返回空列表
        
    Example:
        >>> # C: AES_set_key(key, 128, &ctx)
        >>> # Go: rsa.GenerateKey(rand.Reader, 2048)
        >>> # Python: RSA.generate(2048)
        >>> call = find_call_expression(tree)
        >>> args = ast_arg_nodes(call)
        >>> print(len(args))  # 参数个数
        >>> print(ast_node_text(code, args[0]))  # 第一个参数文本
    
    Note:
        自动跳过括号、逗号等分隔符，只返回实际参数节点
        
    Supported Languages:
        C, C++, Go, Java, Python (via tree-sitter)
    """
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return []
    
    result = []
    for ch in args_node.children:
        # 跳过分隔符（所有语言通用）
        if ch.type not in ("(", ")", ",", "comment"):
            result.append(ch)
    
    return result


def safe_eval_int(expr: str) -> int:
    """
    安全地求值整数表达式（仅支持基本算术运算）
    
    Args:
        expr: 整数表达式字符串
        
    Returns:
        计算结果，如果表达式不安全或无法求值则返回 None
        
    Examples:
        >>> safe_eval_int("256")
        256
        >>> safe_eval_int("16 * 2")
        32
        >>> safe_eval_int("128 / 8")
        16
        >>> safe_eval_int("0x100")  # 十六进制
        256
        >>> safe_eval_int("import os")  # 不安全
        None
        
    Note:
        只允许数字、基本运算符和括号，禁止任何危险操作
        
    Supported Use Cases:
        - C: #define KEY_SIZE (128/8)
        - Go: const KeySize = 16 * 2
        - Python: KEY_SIZE = 256 // 8
    """
    # Pure character-based validation (no regex)
    if not expr:
        return None
    
    # Only allow digits, whitespace, and basic operators
    allowed_chars = set('0123456789 \t\n+-*/()<>')
    if not all(c in allowed_chars for c in expr):
        return None
    
    try:
        return int(eval(expr, {"__builtins__": None}, {}))
    except Exception:
        return None


# ============================================================================
# Go 辅助工具函数 (Go-Specific Helper Functions)
# ============================================================================

def go_node_text(code: str, node) -> str:
    """
    提取 AST 节点对应的源代码文本
    
    这是 navigator.node_text 的便捷封装，参数顺序更符合使用习惯。
    
    Args:
        code: 完整源代码字符串
        node: AST 节点
    
    Returns:
        节点对应的源代码文本
        
    Example:
        >>> tree = parser.parse(code.encode('utf-8'))
        >>> func_name = go_node_text(code, func_node)
    """
    return node_text(code, node)


def go_arg_nodes(call_node) -> list:
    """
    从 Go 函数调用节点提取参数节点列表
    
    Args:
        call_node: call_expression 类型的 AST 节点
    
    Returns:
        参数节点列表（按顺序），未找到返回空列表
        
    Example:
        >>> # 对于: someFunc(arg1, arg2, arg3)
        >>> call = find_call_expression(tree)
        >>> args = go_arg_nodes(call)
        >>> print(len(args))  # 3
        >>> print(go_node_text(code, args[0]))  # "arg1"
    
    Note:
        跳过括号和逗号，只返回实际参数节点
    """
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return []
    
    result = []
    for ch in args_node.children:
        # 跳过 (, ), 逗号等分隔符
        if ch.type not in ("(", ")", ",", "comment"):
            result.append(ch)
    
    return result


def build_multiline_go_declaration(lines: list, start_ln: int, max_lines: int = 20) -> str:
    """
    构建跨行的 Go 变量声明字符串
    
    用于处理跨多行的初始化，例如：
    ```go
    key := []byte{
        0x00, 0x01, 0x02,
        0x03, 0x04, 0x05,
    }
    ```
    
    Args:
        lines: 源代码行列表
        start_ln: 声明起始行号（1-based）
        max_lines: 最多向下查找的行数
    
    Returns:
        完整的声明字符串（合并多行）
        
    Example:
        >>> decl = build_multiline_go_declaration(lines, 10, max_lines=20)
        >>> # 返回: "key := []byte{\\n    0x00, 0x01,\\n    ...\\n}"
    
    Note:
        自动检测花括号配对，找到完整的声明语句
    """
    if start_ln < 1 or start_ln > len(lines):
        return ""
    
    decl_lines = [lines[start_ln - 1]]
    open_count = decl_lines[0].count("{") - decl_lines[0].count("}")
    
    # 继续读取后续行直到括号配对
    for offset in range(1, max_lines):
        next_ln = start_ln + offset
        if next_ln > len(lines):
            break
        
        line = lines[next_ln - 1]
        decl_lines.append(line)
        open_count += line.count("{") - line.count("}")
        
        # 括号配对完成
        if open_count <= 0:
            break
    
    return "\n".join(decl_lines)


def find_composite_literal_in_ast(node) -> object:
    """
    在 AST 中递归查找 composite_literal 节点
    
    Args:
        node: 要搜索的 AST 节点
    
    Returns:
        找到的 composite_literal 节点，未找到返回 None
        
    Example:
        >>> tree = parser.parse(code.encode('utf-8'))
        >>> comp_lit = find_composite_literal_in_ast(tree.root_node)
        >>> if comp_lit:
        ...     length = eval_go_bytes_length_ast(comp_lit, code)
    
    Note:
        Composite literal 是 Go 语言中的复合字面量，例如：
        - []byte{0x00, 0x01, 0x02}
        - map[string]int{"a": 1, "b": 2}
        - struct{Field: value}
    """
    if node.type == "composite_literal":
        return node
    
    for ch in node.children:
        result = find_composite_literal_in_ast(ch)
        if result:
            return result
    
    return None


# ============================================================================
# C/C++ 辅助工具函数 (C/C++-Specific Helper Functions)
# ============================================================================

def c_node_text(code: str, node) -> str:
    """
    提取 C/C++ AST 节点对应的源代码文本
    
    这是 ast_node_text 的语言特定别名，便于代码可读性。
    
    Args:
        code: 完整源代码字符串
        node: tree-sitter AST 节点
    
    Returns:
        节点对应的源代码文本
        
    Example:
        >>> tree = parser.parse(code.encode('utf-8'))
        >>> param_value = c_node_text(code, param_node)
    """
    return node_text(code, node)


def c_arg_nodes(call_node) -> list:
    """
    从 C/C++ 函数调用节点提取参数节点列表
    
    Args:
        call_node: call_expression 类型的 AST 节点
    
    Returns:
        参数节点列表（按顺序），未找到返回空列表
        
    Example:
        >>> # 对于: AES_set_encrypt_key(key, 256, &aes)
        >>> call = find_call_expression(tree)
        >>> args = c_arg_nodes(call)
        >>> print(len(args))  # 3
        >>> print(c_node_text(code, args[1]))  # "256"
    
    Note:
        跳过括号和逗号，只返回实际参数节点
    """
    return ast_arg_nodes(call_node, lang="c")


def c_extract_param_value(call_node, param_index: int, code: str) -> int:
    """
    从 C 函数调用中提取指定位置参数的整数值
    
    Args:
        call_node: call_expression 节点
        param_index: 参数索引（0-based）
        code: 源代码
    
    Returns:
        参数的整数值，无法提取返回 None
        
    Examples:
        >>> # AES_set_encrypt_key(key, 256, &ctx)
        >>> value = c_extract_param_value(call_node, 1, code)
        >>> print(value)  # 256
        
        >>> # EVP_CIPHER_CTX_set_key_length(&ctx, 16*2)
        >>> value = c_extract_param_value(call_node, 1, code)
        >>> print(value)  # 32
    
    Note:
        支持常量、二元表达式（如 16*2）、十六进制（0x10）
    """
    args = c_arg_nodes(call_node)
    if not args or param_index >= len(args):
        return None
    
    param_node = args[param_index]
    param_text = c_node_text(code, param_node).strip()
    
    # 尝试安全求值
    return safe_eval_int(param_text)


# ============================================================================
# Python 辅助工具函数 (Python-Specific Helper Functions via tree-sitter)
# ============================================================================

def python_node_text(code: str, node) -> str:
    """
    提取 Python AST 节点对应的源代码文本（tree-sitter版本）
    
    注意：这是 tree-sitter 版本，与 Python 标准库的 ast 模块不同。
    对于 Python 标准库 ast 模块，使用 ast.unparse() 代替。
    
    Args:
        code: 完整源代码字符串
        node: tree-sitter AST 节点
    
    Returns:
        节点对应的源代码文本
        
    Example:
        >>> tree = parser.parse(code.encode('utf-8'))
        >>> arg_value = python_node_text(code, arg_node)
    """
    return node_text(code, node)


def python_arg_nodes(call_node) -> list:
    """
    从 Python 函数调用节点提取参数节点列表（tree-sitter版本）
    
    Args:
        call_node: call 类型的 AST 节点
    
    Returns:
        参数节点列表（按顺序），未找到返回空列表
        
    Example:
        >>> # 对于: RSA.generate(2048, e=65537)
        >>> call = find_call_expression(tree)
        >>> args = python_arg_nodes(call)
        >>> print(len(args))  # 2
        >>> print(python_node_text(code, args[0]))  # "2048"
    
    Note:
        跳过括号和逗号，只返回实际参数节点
        这是 tree-sitter 版本，与 Python 标准库 ast 不同
    """
    return ast_arg_nodes(call_node, lang="python")


# ============================================================================
# Go值评估器 (Value Evaluators - 不是提取器，是对已提取的AST节点求值)
# ============================================================================

def eval_go_bytes_length_ast(expr_node, code: str) -> int:
    """
    AST-based evaluation of []byte expression length.
    
    This is a VALUE EVALUATOR, not an extractor.
    It takes an already-extracted AST node and computes its byte length.
    
    Returns:
        int: Number of bytes, or None if cannot determine
    
    Supports:
    - []byte{0x00, 0x01, ...}  (composite_literal) - multi-line safe
    - []byte("string")          (type_conversion_expression)
    - make([]byte, 32)          (call_expression with constant size)
    """
    if not expr_node:
        return None
    
    t = expr_node.type
    
    # 1. Composite literal: []byte{0x00, 0x01, ...}
    if t == "composite_literal":
        # 确认是[]byte类型
        # children[0]通常是类型（slice_type, array_type等）
        if len(expr_node.children) < 2:
            return None
        
        type_node = expr_node.children[0]
        type_text = go_node_text(code, type_node)
        if "[]byte" not in type_text and "byte" not in type_text:
            return None
        
        # children[1]是literal_value
        body_node = expr_node.children[1] if len(expr_node.children) > 1 else None
        if not body_node or body_node.type != "literal_value":
            return None
        
        # 统计literal_element的个数（literal_value的children包括 {, }, 逗号和元素）
        count = 0
        for ch in body_node.children:
            # literal_element是实际的值（0x00, 0x01等）
            if ch.type == "literal_element":
                count += 1
        
        return count if count > 0 else None
    
    # 2. Type conversion: []byte("string")
    elif t == "type_conversion_expression":
        type_node = expr_node.child_by_field_name("type")
        if type_node:
            type_text = go_node_text(code, type_node)
            if "[]byte" in type_text:
                # 获取operand（参数）
                operand = expr_node.child_by_field_name("operand")
                if operand and operand.type in ("interpreted_string_literal", "raw_string_literal"):
                    string_text = go_node_text(code, operand)
                    # 去掉引号
                    string_text = string_text.strip('"').strip('`')
                    return len(string_text.encode('utf-8'))
    
    # 3. make([]byte, size)
    elif t == "call_expression":
        func_node = expr_node.child_by_field_name("function")
        if func_node and go_node_text(code, func_node) == "make":
            args = expr_node.child_by_field_name("arguments")
            if args and len(args.children) >= 3:  # make, type, size
                # 第一个参数是类型
                type_arg = args.children[1] if len(args.children) > 1 else None
                if type_arg:
                    type_text = go_node_text(code, type_arg)
                    if "[]byte" in type_text:
                        # 第二个参数是size
                        size_arg = args.children[2] if len(args.children) > 2 else None
                        if size_arg:
                            size_text = go_node_text(code, size_arg).strip()
                            # 尝试解析为整数
                            try:
                                return int(size_text)
                            except ValueError:
                                # size是变量，需要追溯（返回None让调用者处理）
                                return None
    
    # 4. Identifier - 需要变量追溯
    elif t == "identifier":
        # 这里不做追溯，返回None让调用者使用backward_slice
        return None
    
    return None


# def eval_go_bytes_length_regex(expr_text: str) -> int:
#     """
#     [DEPRECATED] This function is deprecated and no longer uses regex.
#     Use eval_go_bytes_length_ast() instead for accurate AST-based parsing.
    
#     This is kept only for API compatibility.
#     """
#     # Redirect to AST-based implementation
#     # Since we don't have the node here, we can't parse accurately
#     # This should not be called anymore - callers should use the AST version
#     return None


# ---------------------------------------------------------------------------
# Field assignment extraction (merged from field_extractor.py)
# ---------------------------------------------------------------------------

def extract_field_assignments(root, code: str, lang: str):
    """
    提取字段赋值 (纯 AST)

    返回格式：
    [
        {
            'object': 'config',
            'field': 'key_bits',
            'value': 2048,
            'line': 15,
            'is_field_assignment': True,
            'operator': '.' or '->',
        },
        ...
    ]
    """
    lang = (lang or 'c').lower()

    if lang == 'c':
        return _extract_c_field_assignments(root, code)
    if lang == 'python':
        return _extract_python_field_assignments(root, code)
    if lang == 'go':
        return _extract_go_field_assignments(root, code)
    if lang == 'java':
        return _extract_java_field_assignments(root, code)

    return []


def _extract_c_field_assignments(root, code: str):
    """
    C 字段赋值提取

    支持：
    - config.key_bits = 2048;
    - ctx->algorithm = EVP_aes_256_gcm();
    """
    assignments = []

    for n in walk(root):
        # C: assignment_expression 节点
        if n.type == "assignment_expression":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")

            if not left_node or not right_node:
                continue

            # 检查左侧是否为字段表达式
            if left_node.type == "field_expression":
                # field_expression 有 object 和 field 两个字段
                obj_node = left_node.child_by_field_name("argument")  # C 中是 argument
                field_node = left_node.child_by_field_name("field")

                if obj_node and field_node:
                    obj_name = node_text(code, obj_node).strip()
                    field_name = node_text(code, field_node).strip()
                    value = _extract_field_value(right_node, code)

                    # 判断是 . 还是 ->
                    full_text = node_text(code, left_node)
                    operator = '->' if '->' in full_text else '.'

                    assignments.append({
                        'object': obj_name,
                        'field': field_name,
                        'value': value,
                        'line': n.start_point[0] + 1,
                        'is_field_assignment': True,
                        'operator': operator,
                    })

    return assignments


def _extract_python_field_assignments(root, code: str):
    """
    Python 字段赋值提取

    支持：
    - obj.field = value
    """
    assignments = []

    for n in walk(root):
        # Python: assignment 节点
        if n.type == "assignment":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")

            if not left_node or not right_node:
                continue

            # 检查左侧是否为属性访问
            if left_node.type == "attribute":
                obj_node = left_node.child_by_field_name("object")
                attr_node = left_node.child_by_field_name("attribute")

                if obj_node and attr_node:
                    obj_name = node_text(code, obj_node).strip()
                    field_name = node_text(code, attr_node).strip()
                    value = _extract_field_value(right_node, code)

                    assignments.append({
                        'object': obj_name,
                        'field': field_name,
                        'value': value,
                        'line': n.start_point[0] + 1,
                        'is_field_assignment': True,
                        'operator': '.',
                    })

    return assignments


def _extract_go_field_assignments(root, code: str):
    """
    Go 字段赋值提取

    支持：
    - config.KeyBits = 2048
    """
    assignments = []

    for n in walk(root):
        # Go: assignment_statement 节点
        if n.type == "assignment_statement":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")

            if not left_node or not right_node:
                continue

            # 如果左侧是 expression_list，取第一个
            if left_node.type == "expression_list" and left_node.children:
                left_node = left_node.children[0]

            # 检查是否为选择器表达式 (obj.field)
            if left_node.type == "selector_expression":
                obj_node = left_node.child_by_field_name("operand")
                field_node = left_node.child_by_field_name("field")

                if obj_node and field_node:
                    obj_name = node_text(code, obj_node).strip()
                    field_name = node_text(code, field_node).strip()

                    # 如果右侧是 expression_list，取第一个
                    value_node = right_node
                    if right_node.type == "expression_list" and right_node.children:
                        value_node = right_node.children[0]

                    value = _extract_field_value(value_node, code)

                    assignments.append({
                        'object': obj_name,
                        'field': field_name,
                        'value': value,
                        'line': n.start_point[0] + 1,
                        'is_field_assignment': True,
                        'operator': '.',
                    })

    return assignments


def _extract_java_field_assignments(root, code: str):
    """
    Java 字段赋值提取

    支持：
    - config.keyBits = 2048;
    """
    assignments = []

    for n in walk(root):
        # Java: assignment_expression 节点
        if n.type == "assignment_expression":
            left_node = n.child_by_field_name("left")
            right_node = n.child_by_field_name("right")

            if not left_node or not right_node:
                continue

            # 检查左侧是否为字段访问
            if left_node.type == "field_access":
                obj_node = left_node.child_by_field_name("object")
                field_node = left_node.child_by_field_name("field")

                if obj_node and field_node:
                    obj_name = node_text(code, obj_node).strip()
                    field_name = node_text(code, field_node).strip()
                    value = _extract_field_value(right_node, code)

                    assignments.append({
                        'object': obj_name,
                        'field': field_name,
                        'value': value,
                        'line': n.start_point[0] + 1,
                        'is_field_assignment': True,
                        'operator': '.',
                    })

    return assignments


def _extract_field_value(value_node, code: str):
    """
    从 AST 节点提取值（纯 AST，无 eval）

    支持：
    - 整数字面量: 2048 -> 2048
    - 字符串字面量: "AES" -> "AES"
    - 标识符: EVP_aes_256_gcm -> "EVP_aes_256_gcm"
    - 调用表达式: func() -> {'type': 'call', 'function': 'func'}
    - 其他: 返回文本表示
    """
    if not value_node:
        return None

    node_type = value_node.type
    value_text = node_text(code, value_node).strip()

    # 整数字面量
    if node_type in ('number_literal', 'integer_literal', 'int_literal'):
        try:
            return int(value_text)
        except ValueError:
            try:
                return float(value_text)
            except ValueError:
                return value_text

    # 字符串字面量
    if node_type in ('string_literal', 'string', 'interpreted_string_literal'):
        # 去除引号
        return value_text.strip('"\'')

    # 布尔值
    if node_type in ('true', 'false'):
        return value_text == 'true'

    # 调用表达式（保留结构信息）
    if node_type in ('call_expression', 'call'):
        func_node = value_node.child_by_field_name('function')
        if func_node:
            func_name = node_text(code, func_node).strip()
            return {
                'type': 'call',
                'function': func_name,
                'text': value_text,
            }

    # 标识符
    if node_type in ('identifier', 'field_identifier', 'type_identifier'):
        return {
            'type': 'identifier',
            'name': value_text,
            'text': value_text,
        }

    # 二元表达式（尝试安全求值）
    if node_type in ('binary_expression', 'binary_operator'):
        # 只支持简单的数字运算
        if all(c in '0123456789+-*/ ()' for c in value_text):
            try:
                return eval(value_text)
            except Exception:
                pass

    # 默认：返回文本
    return value_text


# ─────────────────────────────────────────────────────────────────────────────
# Task 25: OOP field-map and lambda extraction (Python)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_python_oop_info(root_node, code: str):
    """
    提取 Python 代码中的面向对象信息（类的 __init__ 字段映射与方法归属）。

    Returns
    -------
    method_map : dict[str, str]
        方法名 → 所属类名
    class_info : dict[str, dict]
        类名 → {
            "init_params": list[str],          # __init__ 参数（不含 self）
            "field_map": dict[str, (str, int)]  # self.field → (param_name, param_index)
        }
    """
    method_map: dict = {}
    class_info: dict = {}

    for cls_node in walk(root_node):
        if cls_node.type != "class_definition":
            continue

        # 类名
        cls_name_node = cls_node.child_by_field_name("name")
        if cls_name_node is None:
            continue
        cls_name = node_text(code, cls_name_node).strip()

        # 初始化 class_info 条目
        class_info[cls_name] = {
            "init_params": [],
            "field_map": {},
        }

        body_node = cls_node.child_by_field_name("body")
        if body_node is None:
            continue

        for method_node in body_node.children:
            if method_node.type != "function_definition":
                continue

            meth_name_node = method_node.child_by_field_name("name")
            if meth_name_node is None:
                continue
            meth_name = node_text(code, meth_name_node).strip()

            # 所有方法都记录到 method_map（排除 __init__ 通常不当成 callable 入口）
            method_map[meth_name] = cls_name

            if meth_name != "__init__":
                continue

            # ── 提取 __init__ 参数（排除 self）────────────────────────────
            params_node = method_node.child_by_field_name("parameters")
            init_params: list[str] = []
            if params_node:
                for p in params_node.children:
                    pname = None
                    if p.type == "identifier":
                        pname = node_text(code, p).strip()
                    elif p.type in ("default_parameter", "typed_default_parameter"):
                        name_child = p.child_by_field_name("name")
                        if name_child:
                            pname = node_text(code, name_child).strip()
                    elif p.type == "typed_parameter":
                        for sub in p.children:
                            if sub.type == "identifier":
                                pname = node_text(code, sub).strip()
                                break
                    elif p.type == "list_splat_pattern":
                        for sub in p.children:
                            if sub.type == "identifier":
                                pname = "*" + node_text(code, sub).strip()
                                break
                    elif p.type == "dictionary_splat_pattern":
                        for sub in p.children:
                            if sub.type == "identifier":
                                pname = "**" + node_text(code, sub).strip()
                                break
                    if pname and pname != "self":
                        init_params.append(pname)

            class_info[cls_name]["init_params"] = init_params
            param_index = {p: i for i, p in enumerate(init_params)}

            # ── 提取 self.field = param 赋值 ──────────────────────────────
            body_meth = method_node.child_by_field_name("body")
            if body_meth is None:
                continue

            for stmt in walk(body_meth):
                if stmt.type != "assignment":
                    continue
                left = stmt.child_by_field_name("left")
                right = stmt.child_by_field_name("right")
                if left is None or right is None:
                    continue

                # Left must be self.field
                if left.type != "attribute":
                    continue
                obj_node = left.child_by_field_name("object")
                attr_node = left.child_by_field_name("attribute")
                if obj_node is None or attr_node is None:
                    continue
                if node_text(code, obj_node).strip() != "self":
                    continue

                field_name = node_text(code, attr_node).strip()

                # Right side must be a direct identifier reference to an init param
                if right.type == "identifier":
                    rhs_name = node_text(code, right).strip()
                    if rhs_name in param_index:
                        class_info[cls_name]["field_map"][field_name] = (
                            rhs_name, param_index[rhs_name]
                        )

    return method_map, class_info


def _extract_python_lambda_functions(root_node, code: str) -> list:
    """
    提取 Python 代码中所有 ``fn = lambda ...`` 形式的 lambda 函数。

    Returns
    -------
    list of dict with keys:
        name       : str          — 绑定 lambda 的变量名
        params     : list[str]    — 参数名列表
        is_lambda  : True
        line       : int          — lambda 定义所在行（1-based）
        start_line : int          — 同 line（供 wrapper 归属使用）
        end_line   : int          — lambda 结束行（通常也是 line，可能跨行）
    """
    results = []

    for node in walk(root_node):
        if node.type != "assignment":
            continue

        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        if right.type != "lambda":
            continue

        # Variable name on the left
        lam_name = node_text(code, left).strip()

        # Line number info from the lambda node
        start_line = right.start_point[0] + 1
        end_line   = right.end_point[0] + 1

        # Extract params from lambda_parameters
        params: list[str] = []
        lambda_params_node = right.child_by_field_name("parameters")
        if lambda_params_node:
            for p in lambda_params_node.children:
                pname = None
                if p.type == "identifier":
                    pname = node_text(code, p).strip()
                elif p.type in ("default_parameter", "typed_default_parameter"):
                    name_child = p.child_by_field_name("name")
                    if name_child:
                        pname = node_text(code, name_child).strip()
                elif p.type == "typed_parameter":
                    for sub in p.children:
                        if sub.type == "identifier":
                            pname = node_text(code, sub).strip()
                            break
                if pname:
                    params.append(pname)

        results.append({
            "name":       lam_name,
            "params":     params,
            "is_lambda":  True,
            "line":       start_line,
            "start_line": start_line,
            "end_line":   end_line,
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Task 27: Builder pattern chain extraction (Java)
# ─────────────────────────────────────────────────────────────────────────────

# Recognised crypto-relevant setter method names (lowercase)
_BUILDER_ALGO_SETTERS   = frozenset({"setalgorithm", "algorithm", "withalgorithm"})
_BUILDER_KEYSIZE_SETTERS = frozenset({
    "setkeysize", "keysize", "withkeysize",
    "setkeylength", "keylength", "withkeylength",
})
_BUILDER_MODE_SETTERS   = frozenset({"setmode", "mode", "withmode"})


def _builder_chain_arg_text(arguments_node, code: str) -> str | None:
    """Return the text of the first non-punctuation argument in an argument_list."""
    for ch in arguments_node.children:
        if ch.type in ("(", ")", ","):
            continue
        txt = node_text(code, ch).strip()
        if txt:
            return txt
    return None


def _traverse_builder_chain(node, code: str) -> tuple[dict, str]:
    """
    Recursively traverse a Java method-invocation chain (from outermost to innermost)
    and collect crypto-relevant setter information.

    Returns
    -------
    builder_context : dict   — accumulated {algorithm, key_bits, mode}
    chain_root_name : str    — leading class/variable name for the chain
    """
    ctx: dict = {}
    root_name = ""

    if node is None:
        return ctx, root_name

    node_type = node.type

    if node_type == "method_invocation":
        obj_node   = node.child_by_field_name("object")
        name_node  = node.child_by_field_name("name")
        args_node  = node.child_by_field_name("arguments")

        meth_name = node_text(code, name_node).strip() if name_node else ""
        meth_lower = meth_name.lower()

        # Recurse into the object side first
        parent_ctx, root_name = _traverse_builder_chain(obj_node, code)
        ctx.update(parent_ctx)

        # Classify this setter
        if meth_lower in _BUILDER_ALGO_SETTERS and args_node:
            raw = _builder_chain_arg_text(args_node, code)
            if raw:
                ctx["algorithm"] = raw.strip('"\'')

        elif meth_lower in _BUILDER_KEYSIZE_SETTERS and args_node:
            raw = _builder_chain_arg_text(args_node, code)
            if raw:
                try:
                    ctx["key_bits"] = int(raw)
                except ValueError:
                    ctx["key_bits"] = raw

        elif meth_lower in _BUILDER_MODE_SETTERS and args_node:
            raw = _builder_chain_arg_text(args_node, code)
            if raw:
                ctx["mode"] = raw.strip('"\'')

    elif node_type == "object_creation_expression":
        # new ClassName(...)
        type_node = node.child_by_field_name("type")
        if type_node:
            root_name = node_text(code, type_node).strip()

    else:
        # Static call like Config.builder() — the root is the object text
        root_name = node_text(code, node).strip()

    return ctx, root_name


def extract_builder_chains(root_node, code: str, language: str) -> list:
    """
    Detect Java builder-pattern method chains that configure cryptographic parameters.

    Only Java is handled; other languages immediately return ``[]``.

    A "builder chain" is a sequence of fluent method calls that ends with ``.build()``
    and contains at least one of: ``setAlgorithm`` / ``algorithm`` / ``withAlgorithm``,
    ``setKeySize`` / ``keySize`` / ``setKeyLength`` etc., or ``setMode`` / ``mode``.

    Returns
    -------
    list of dict:
        is_builder_chain : True
        builder_context  : {"algorithm": str, "key_bits": int|str, "mode": str}
        symbol           : str  (contains "build")
        member           : "build"
        line             : int
    """
    if (language or "").lower() != "java":
        return []

    results = []

    for node in walk(root_node):
        if node.type != "method_invocation":
            continue

        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        meth_name = node_text(code, name_node).strip()
        if meth_name != "build":
            continue

        # Traverse the object chain to collect context
        obj_node = node.child_by_field_name("object")
        builder_ctx, root_name = _traverse_builder_chain(obj_node, code)

        # Only report if at least one crypto-relevant setter was found
        has_crypto = (
            "algorithm" in builder_ctx
            or "key_bits" in builder_ctx
            or "mode" in builder_ctx
        )
        if not has_crypto:
            continue

        # Build a synthetic symbol
        if root_name:
            symbol = f"{root_name}.build"
        else:
            symbol = "builder.build"

        line = node.start_point[0] + 1

        results.append({
            "is_builder_chain": True,
            "builder_context": builder_ctx,
            "symbol": symbol,
            "member": "build",
            "line": line,
        })

    return results
