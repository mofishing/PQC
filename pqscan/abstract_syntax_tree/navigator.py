#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   navigator.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/10/17 15:38   1.0         AST 语义导航与语言适配
"""

# pqscan/abstract_syntax_tree/navigator.py

def walk(node):
    """DFS 遍历整个 AST 树"""
    yield node
    for child in node.children:
        yield from walk(child)


def node_text(code: str, node):
    """返回节点对应的源代码片段"""
    # tree-sitter 使用字节偏移，需要将代码转换为字节串再提取
    code_bytes = code.encode('utf-8')
    text_bytes = code_bytes[node.start_byte:node.end_byte]
    return text_bytes.decode('utf-8')


def find_nodes_by_type(root, node_type: str):
    """查找特定类型的所有节点"""
    result = []
    for n in walk(root):
        if n.type == node_type:
            result.append(n)
    return result

LANG_NODE_MAP = {
    "go": {
        "call": "call_expression",
        "func_def": "function_declaration",
        "import": "import_spec"
    },
    "python": {
        "call": "call",
        "func_def": "function_definition",
        "import": ("import_statement", "import_from_statement"),
        "attribute": "attribute",   # obj.attr
        "identifier": "identifier", # 纯标识符
    },
    "java": {
        "call": "method_invocation",
        "func_def": "method_declaration",
        "import": "import_declaration"
    },
    "c": {
        "call": "call_expression",
        "func_def": "function_definition",
        "import": "preproc_include"
    },
    "cpp": {
        "call": "call_expression",
        "func_def": "function_definition",
        "import": "preproc_include"
    }
}

# cpp-compatible aliases
LANG_NODE_MAP["c++"] = LANG_NODE_MAP["cpp"]
LANG_NODE_MAP["cxx"] = LANG_NODE_MAP["cpp"]

_CPP_QUALIFIED_TYPES = {
    # 常见在 C++ 中作为“函数名/目标”的节点类型
    "field_expression",          # obj.method / obj->method
    "qualified_identifier",      # ns::Class::func
    "scoped_identifier",         # 旧名/等价命名
    "identifier",                # 普通标识符
    "template_function",         # 一些解析器把模板调用包成单独结点（保险起见）
    "template_id",               # func<int>
    "destructor_name",           # ~Class
}

def _is_cpp(lang: str) -> bool:
    return lang in ("cpp", "c++", "cxx")

def _is_java(lang: str) -> bool:
    return lang == "java"

def _rightmost_identifier_like(node):
    """
    在可能的嵌套表达式里取“最右侧的名字片段”
    用于 member/qualified/template 场景的函数名近似提取
    """
    stack = [node]
    last_candidate = None
    while stack:
        n = stack.pop()
        if n.type in ("identifier", "field_identifier", "destructor_name"):
            last_candidate = n
        # 深度优先遍历
        for ch in getattr(n, "children", [])[::-1]:
            stack.append(ch)
    return last_candidate or node  # 兜底

def _cpp_fn_symbol_from_call(node, code: str):
    """
    针对 C++ 的 call_expression，尽量提取“可读的函数名/成员名”
    优先：function 字段；其次第一个子结点；
    若为复合结构（member/qualified/template），取最右标识符
    """
    fn = node.child_by_field_name("function") or (node.children[0] if node.children else None)
    if not fn:
        return node_text(code, node)  # 整段调用
    if fn.type in _CPP_QUALIFIED_TYPES:
        leaf = _rightmost_identifier_like(fn)
        return node_text(code, leaf)
    return node_text(code, fn)

def _cpp_fn_name_from_definition(node, code: str):
    """
    提取 C++ function_definition 的函数名。
    """
    def _extract_name_node(decl):
        if decl is None:
            return None
        if decl.type == "function_declarator":
            # Prefer the declarator child before descending into parameter_list.
            for child in decl.children:
                if child.type in {
                    "qualified_identifier",
                    "scoped_identifier",
                    "identifier",
                    "field_identifier",
                    "destructor_name",
                    "template_function",
                    "template_id",
                    "operator_name",
                }:
                    return child
            inner = decl.child_by_field_name("declarator")
            if inner is not None:
                return _extract_name_node(inner)
        if decl.type in {"pointer_declarator", "reference_declarator", "parenthesized_declarator"}:
            inner = decl.child_by_field_name("declarator")
            if inner is not None:
                return _extract_name_node(inner)
        if decl.type in _CPP_QUALIFIED_TYPES or decl.type in {"field_identifier", "operator_name"}:
            return decl
        for child in decl.children:
            result = _extract_name_node(child)
            if result is not None:
                return result
        return None

    decl = node.child_by_field_name("declarator")
    target = _extract_name_node(decl) if decl else None
    if target is None:
        target = _rightmost_identifier_like(node)
    return node_text(code, target)

def _c_fn_name_from_definition(node, code: str):
    """Extract C function name from function_definition declarator AST."""
    decl = node.child_by_field_name("declarator")
    if decl:
        for ch in decl.children:
            if ch.type == "identifier":
                return node_text(code, ch)
            if ch.type in {"function_declarator", "pointer_declarator", "parenthesized_declarator"}:
                for sub in ch.children:
                    if sub.type == "identifier":
                        return node_text(code, sub)
    return _cpp_fn_name_from_definition(node, code)

def get_node_type(lang: str, kind: str) -> str:
    """获取指定语言对应的节点类型名"""
    return LANG_NODE_MAP.get(lang, {}).get(kind, kind)

def iter_calls(root, code: str, lang: str):
    call_type = get_node_type(lang, "call")
    for n in walk(root):
        if n.type == call_type:
            symbol = None
            receiver = None
            
            if _is_cpp(lang):
                symbol = _cpp_fn_symbol_from_call(n, code)
            elif _is_java(lang):
                # Java method_invocation: 对象是 object，方法是 name（方法名标识符）
                # 提取形式：object.methodName 或仅 methodName
                obj_node = n.child_by_field_name("object")
                name_node = n.child_by_field_name("name")
                
                if name_node:
                    method_name = node_text(code, name_node)
                    if obj_node:
                        obj_text = node_text(code, obj_node)
                        symbol = f"{obj_text}.{method_name}"
                        # 只有当接收对象看起来像变量名（首字母小写）时才设置receiver
                        # 对于类名（首字母大写）的静态调用，不设置receiver
                        if obj_text and obj_text[0].islower():
                            receiver = obj_text  # 这是一个实例方法调用
                        # 如果首字母大写，说明是静态方法调用，不设置receiver
                    else:
                        symbol = method_name
                else:
                    fn = n.child_by_field_name("function") or (n.children[0] if n.children else None)
                    symbol = node_text(code, fn) if fn else node_text(code, n)
            else:
                # Go, Python, C, etc.
                fn = n.child_by_field_name("function") or (n.children[0] if n.children else None)
                
                # [FIX] Python链式调用：obj.method().anotherMethod()
                # function字段可能是attribute类型（obj.method().anotherMethod）
                # 我们应该只提取末尾的方法名（anotherMethod），而不是整个表达式
                if fn and fn.type == "attribute":
                    # attribute节点有attribute字段，包含方法名
                    attr_node = fn.child_by_field_name("attribute")
                    if attr_node:
                        # 只使用attribute部分作为member
                        member_name = node_text(code, attr_node)
                        # object部分是receiver
                        obj_node = fn.child_by_field_name("object")
                        if obj_node:
                            obj_text = node_text(code, obj_node)
                            symbol = f"{obj_text}.{member_name}"
                        else:
                            symbol = member_name
                    else:
                        # 回退：使用整个function文本
                        symbol = node_text(code, fn) if fn else node_text(code, n)
                else:
                    # 普通调用
                    symbol = node_text(code, fn) if fn else node_text(code, n)
            
            # Yield the call with symbol and optional receiver/receiver_type
            yield {
                "symbol": symbol,
                "line": n.start_point[0] + 1,
                "code": node_text(code, n),
                "_node": n,
                "receiver": receiver
            }


def iter_functions(root, code: str, lang: str):
    func_type = get_node_type(lang, "func_def")
    for n in walk(root):
        if n.type == func_type:
            # name_node = n.child_by_field_name("name") or n.children[0]
            # body = n.child_by_field_name("body")

            if lang == "c":
                name = _c_fn_name_from_definition(n, code)
            elif _is_cpp(lang):
                name = _cpp_fn_name_from_definition(n, code)
            else:
                name_node = n.child_by_field_name("name") or (n.children[0] if n.children else None)
                name = node_text(code, name_node) if name_node else node_text(code, n)

            body = n.child_by_field_name("body")

            yield {
                # "name": node_text(code, name_node),
                "name": name,
                "start_line": n.start_point[0] + 1,
                "end_line": n.end_point[0] + 1,
                "src": node_text(code, n),
                "_body": body,
                "_node": n
            }

def iter_imports(root, code: str, lang: str):
    import_type = get_node_type(lang, "import")
    for n in walk(root):
        if n.type == import_type:
            yield node_text(code, n).strip('<>" ')

#-----------------------仅声明函数无实现的提取 -------------------------------

def _iter_c_like_function_decls(root, code: str):
    """
    适配 C / C++：查找 'declaration'（或 'field_declaration'）中包含 function_declarator 的语句，
    但排除已有函数体的 function_definition。
    """
    target_stmt_types = {"declaration", "field_declaration"}  # C/C++ 里函数原型常见的宿主节点
    for n in walk(root):
        if n.type in target_stmt_types:
            # 只要其后代里包含 function_declarator，即可认为是函数声明而非变量声明
            has_func_decl = False
            declarator_node = None
            stack = [n]
            while stack:
                x = stack.pop()
                if x.type == "function_declarator":
                    has_func_decl = True
                    declarator_node = x
                    # 不 break：继续看右侧叶子用于提名（也可立即 break）
                for ch in getattr(x, "children", []):
                    stack.append(ch)
            if not has_func_decl:
                continue

            # 不在 function_definition 下（有函数体的情况由 iter_functions 负责）
            parent = getattr(n, "parent", None)
            is_under_definition = False
            while parent is not None:
                if parent.type == "function_definition":
                    is_under_definition = True
                    break
                parent = getattr(parent, "parent", None)
            if is_under_definition:
                continue

            # 从 declarator 子树中拿“最右侧的 identifier-like”提取名字
            target = _rightmost_identifier_like(declarator_node) if declarator_node else _rightmost_identifier_like(n)
            name = node_text(code, target)

            yield {
                "name": name,
                "start_line": n.start_point[0] + 1,
                "end_line": n.end_point[0] + 1,
                "src": node_text(code, n),
                "_node": n
            }

def _iter_java_function_decls(root, code: str):
    """
    适配 Java 接口中的方法声明
    tree-sitter-java 里为 'interface_method_declaration'
    """
    for n in walk(root):
        if n.type == "interface_method_declaration":
            # 名字一般在 'name' 字段；兜底用第一个子结点
            name_node = n.child_by_field_name("name") or (n.children[0] if getattr(n, "children", None) else None)
            name = node_text(code, name_node) if name_node else node_text(code, n)
            yield {
                "name": name,
                "start_line": n.start_point[0] + 1,
                "end_line": n.end_point[0] + 1,
                "src": node_text(code, n),
                "_node": n
            }

def iter_function_decls(root, code: str, lang: str):
    """
    遍历“只有声明、没有函数体”的函数
    - C/C++：形如 `int foo(int a);`（含模板、命名空间限定同样可被识别）
    - Java：接口中的方法声明
    其它语言（Python/Go 等）通常不存在这种“仅声明”的形式，这里将不会产出结果
    """
    if _is_cpp(lang) or lang == "c":
        yield from _iter_c_like_function_decls(root, code)
    elif _is_java(lang):
        yield from _iter_java_function_decls(root, code)
    else:
        return  # 其它语言无操作
