#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   __init__.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/18 16:48    1.0         None
2026/1/23          2.0         重构：两阶段架构
"""

from typing import Optional, Dict, Any

# Phase 1: AST 快速候选提取
from .scanner import scan_candidates, quick_scan

# 底层工具
from .parser import get_parser
from .extractor import extract_calls, extract_functions, extract_imports, extract_literals, \
    extract_imports_with_aliases, extract_attributes, extract_var_assignments, extract_function_params, \
    extract_field_assignments


def parse_source(code: str, lang: str):
    """解析源代码为 AST（向后兼容）"""
    parser_lang = str(lang or "").lower()
    if parser_lang == "c":
        cpp_markers = ("::", "namespace ", "template<", "std::", "class ", "public:", "private:", "protected:")
        if any(marker in code for marker in cpp_markers):
            parser_lang = "cpp"
    my_parser = get_parser(parser_lang)
    tree = my_parser.parse(code.encode("utf-8"))
    return tree.root_node


__all__ = [
    # Phase 1 主入口
    'scan_candidates',
    'quick_scan',
    
    # 底层工具
    'parse_source',
    'get_parser',
    'extract_features',
    'extract_calls',
    'extract_functions',
    'extract_function_params',
    'extract_imports',
    'extract_literals',
    'extract_field_assignments',
    'build_features_from_source',
]

def extract_features(code: str, lang: str):
    """解析源码并抽取关键特征"""
    root = parse_source(code, lang)
    # imports = extract_imports(root, code, lang)
    # 老的 imports 仍然返回；新增 import_aliases
    funcs = extract_functions(root, code, lang)
    python_method_map = {}
    python_class_info = {}
    if str(lang or '').lower() == 'python':
        from .extractor import _extract_python_oop_info
        python_method_map, python_class_info = _extract_python_oop_info(root, code)
        funcs = _annotate_python_function_classes(funcs)
    
    # [Task 13.2.2] 增强函数定义：添加params和return_expression用于函数内联
    from .function_extractor import enhance_function_definitions
    funcs = enhance_function_definitions(funcs, code, lang)
    if str(lang or '').lower() == 'python':
        funcs = _annotate_python_function_classes(funcs)
    funcs = _normalize_function_symbols(funcs)
    imports, alias_map = extract_imports_with_aliases(root, code, lang)
    calls = extract_calls(root, code, lang, alias_map=alias_map, imports=imports)  # [FIX Phase 19] 传递alias_map和imports
    calls = _normalize_call_symbols(calls, alias_map, lang, functions=funcs)
    calls = _annotate_call_owners(calls, funcs)
    
    literals = extract_literals(root, code)
    attrs = extract_attributes(root, code, lang="python", alias_map=alias_map)
    var_assignments = extract_var_assignments(root, code, lang)  # 新增：变量赋值关系
    field_assignments = extract_field_assignments(root, code, lang)  # 新增：字段赋值关系
    if str(lang or '').lower() == 'python':
        calls = _resolve_python_field_receiver_types(calls, funcs, field_assignments)
    return {
        "lang": lang,
        "imports": imports, ## 兼容旧逻辑 ["crypto/rsa","crypto/aes"]
        "import_aliases": alias_map,  # 新增 {"rsa":"crypto/rsa","aes":"crypto/aes"}
        "calls": calls,
        "functions": funcs,
        "literals": literals,
        "attributes": attrs,
        "var_assignments": var_assignments,  # 新增：{"sig": "Signature", "keyGen": "KeyPairGenerator"}
        "field_assignments": field_assignments,  # 新增：[{'object': 'config', 'field': 'key_bits', 'value': 2048, ...}]
        "python_method_map": python_method_map,
        "python_class_info": python_class_info,
    }


def _normalize_call_symbols(calls, alias_map: Dict[str, str], lang: str, functions=None):
    normalized = []
    alias_map = alias_map or {}
    lang = str(lang or '').lower()
    is_python = lang == 'python'
    is_java = lang == 'java'
    functions = functions or []

    def _normalize_java_type_name(value: str) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        if text.lower().startswith('new '):
            text = text[4:].strip()
        if '(' in text:
            text = text.split('(', 1)[0].strip()
        if '<' in text:
            text = text.split('<', 1)[0].strip()
        if '.' in text:
            tail = text.rsplit('.', 1)[-1].strip()
            if tail:
                text = tail
        return text

    def _normalize_python_type_name(value: str) -> str:
        text = str(value or '').strip()
        if not text:
            return ''
        if text.lower().startswith('new '):
            text = text[4:].strip()
        if '(' in text:
            text = text.split('(', 1)[0].strip()
        if '<' in text:
            text = text.split('<', 1)[0].strip()
        if '.' in text:
            tail = text.rsplit('.', 1)[-1].strip()
            if tail:
                text = tail
        return text

    python_line_to_class = {}
    if is_python:
        for fn in functions or []:
            if not isinstance(fn, dict):
                continue
            cls_name = str(fn.get('class_name') or '').strip()
            start = fn.get('start_line', 0)
            end = fn.get('end_line', 0)
            if not cls_name or not isinstance(start, int) or not isinstance(end, int) or end < start:
                continue
            for line in range(start, end + 1):
                python_line_to_class[line] = cls_name

    for call in calls or []:
        if not isinstance(call, dict):
            normalized.append(call)
            continue

        symbol = str(call.get('symbol', '') or '')
        resolved_symbol = symbol

        if is_python and symbol:
            if symbol in alias_map:
                resolved_symbol = alias_map[symbol]
            elif '.' in symbol:
                head, tail = symbol.rsplit('.', 1)
                target = alias_map.get(head)
                if target:
                    resolved_symbol = f"{target}.{tail}" if tail else target
                else:
                    receiver_type = _normalize_python_type_name(call.get('receiver_type', ''))
                    if receiver_type:
                        resolved_symbol = f"{receiver_type}.{tail}"
                    elif head == 'self':
                        owner_class = python_line_to_class.get(int(call.get('line', 0) or 0), '')
                        if owner_class:
                            resolved_symbol = f"{owner_class}.{tail}"
        elif is_java and symbol and '.' in symbol:
            receiver_type = _normalize_java_type_name(call.get('receiver_type', ''))
            head, tail = symbol.split('.', 1)
            if receiver_type:
                resolved_symbol = f"{receiver_type}.{tail}"
            elif head in alias_map:
                resolved_symbol = f"{head}.{tail}"

        item = dict(call)
        item['resolved_symbol'] = resolved_symbol
        item['resolved_member'] = _normalize_symbol_name(resolved_symbol)
        normalized.append(item)

    return normalized


def _normalize_function_symbols(functions):
    normalized = []
    for fn in functions or []:
        if not isinstance(fn, dict):
            normalized.append(fn)
            continue
        item = dict(fn)
        raw_name = str(item.get('name', '') or '').strip()
        item['normalized_name'] = _normalize_symbol_name(raw_name)
        if '::' in raw_name:
            item.setdefault('qualified_name', raw_name)
            parts = [part for part in raw_name.split('::') if part]
            if len(parts) >= 2:
                item.setdefault('class_name', '::'.join(parts[:-1]))
        normalized.append(item)
    return normalized


def _annotate_python_function_classes(functions):
    annotated = []
    for fn in functions or []:
        if not isinstance(fn, dict):
            annotated.append(fn)
            continue
        item = dict(fn)
        node = item.get('_node')
        class_name = str(item.get('class_name') or '').strip()
        current = getattr(node, 'parent', None)
        while current is not None and not class_name:
            if getattr(current, 'type', '') == 'class_definition':
                name_node = current.child_by_field_name('name')
                if name_node is not None:
                    class_name = bytes(name_node.text).decode('utf-8', errors='replace').strip()
                break
            current = getattr(current, 'parent', None)
        if class_name:
            item['class_name'] = class_name
            raw_name = str(item.get('name', '') or '').strip()
            if raw_name:
                item['qualified_name'] = f"{class_name}.{raw_name}"
        annotated.append(item)
    return annotated


def _normalize_symbol_name(name: str) -> str:
    text = str(name or '').strip()
    if not text:
        return ''
    if '::' in text:
        text = text.split('::')[-1]
    if '.' in text:
        text = text.split('.')[-1]
    return text


def _annotate_call_owners(calls, functions):
    line_to_func = {}
    line_to_qualified = {}
    for fn in functions or []:
        if not isinstance(fn, dict):
            continue
        fn_name = str(fn.get('name', '') or '')
        fn_qualified = str(fn.get('qualified_name', '') or fn_name)
        fn_norm = str(fn.get('normalized_name', '') or '')
        start = fn.get('start_line', 0)
        end = fn.get('end_line', 0)
        if not fn_qualified or not isinstance(start, int) or not isinstance(end, int) or end < start:
            continue
        for line in range(start, end + 1):
            line_to_func[line] = fn_norm or fn_name
            line_to_qualified[line] = fn_qualified

    annotated = []
    for call in calls or []:
        if not isinstance(call, dict):
            annotated.append(call)
            continue

        owner = ''
        scope = call.get('scope', {})
        if isinstance(scope, dict):
            owner = str(scope.get('function_name') or scope.get('function') or '')
        if not owner:
            owner = str(call.get('function', '') or '')
        if not owner:
            line = call.get('line', 0)
            if isinstance(line, int) and line > 0:
                owner = str(line_to_func.get(line, '') or '')
        owner_qualified = ''
        line = call.get('line', 0)
        if isinstance(line, int) and line > 0:
            owner_qualified = str(line_to_qualified.get(line, '') or '')

        item = dict(call)
        item['owner_function'] = owner
        item['owner_function_normalized'] = _normalize_symbol_name(owner)
        item['owner_function_qualified'] = owner_qualified or owner
        annotated.append(item)

    return annotated


def _resolve_python_field_receiver_types(calls, functions, field_assignments):
    line_to_class = {}
    for fn in functions or []:
        if not isinstance(fn, dict):
            continue
        cls_name = str(fn.get('class_name') or '').strip()
        start = fn.get('start_line', 0)
        end = fn.get('end_line', 0)
        if not cls_name or not isinstance(start, int) or not isinstance(end, int) or end < start:
            continue
        for line in range(start, end + 1):
            line_to_class[line] = cls_name

    field_type_map = {}
    for item in field_assignments or []:
        if not isinstance(item, dict):
            continue
        obj = str(item.get('object') or '').strip()
        field = str(item.get('field') or '').strip()
        value = item.get('value')
        line = item.get('line', 0)
        if obj != 'self' or not field or not isinstance(line, int) or line <= 0:
            continue
        if isinstance(value, dict) and value.get('type') == 'call':
            class_name = str(value.get('function') or '').strip()
        else:
            class_name = ''
        if not class_name:
            continue
        owner_class = line_to_class.get(line, '')
        if owner_class:
            field_type_map[(owner_class, f"self.{field}")] = class_name

    resolved_calls = []
    for call in calls or []:
        if not isinstance(call, dict):
            resolved_calls.append(call)
            continue
        item = dict(call)
        if item.get('receiver_type'):
            resolved_calls.append(item)
            continue
        symbol = str(item.get('symbol') or '').strip()
        if '.' not in symbol:
            resolved_calls.append(item)
            continue
        head, tail = symbol.rsplit('.', 1)
        owner_class = line_to_class.get(int(item.get('line', 0) or 0), '')
        field_type = field_type_map.get((owner_class, head))
        if field_type:
            item['receiver_type'] = field_type
            item['resolved_symbol'] = f"{field_type}.{tail}"
            item['resolved_member'] = _normalize_symbol_name(item['resolved_symbol'])
        resolved_calls.append(item)
    return resolved_calls


def build_features_from_source(code: str, lang: str = "go", path: Optional[str] = None) -> Dict[str, Any]:
    """
    解析源码 -> features 字典（兼容入口）。
    """
    features = extract_features(code, lang)
    return {
        "lang": features.get("lang", lang),
        "path": path,
        "functions": features.get("functions", []),
        "calls": features.get("calls", []),
        "imports": features.get("imports", []),
        "import_aliases": features.get("import_aliases", {}),
        "literals": features.get("literals", []),
    }
