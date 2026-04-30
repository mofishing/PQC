"""
SSA/IR Builder
从 AST 构建 SSA (Static Single Assignment) 形式的中间表示
"""

from typing import Any, Dict, List, Optional
from ..symbolic.schema import (
    SSAFunction, SSABlock, SSAInstruction, SSAValue,
    InstructionType
)


class IRBuilder:
    """
    IR 构建器基类
    
    职责：
    1. 从 Tree-sitter AST 构建 SSA/IR
    2. 生成基本块和控制流图
    3. 变量重命名（SSA 形式）
    """
    
    def __init__(self, language: str):
        self.language = language
        self.current_function: Optional[SSAFunction] = None
        self.current_block: Optional[SSABlock] = None
        
        # 变量版本映射（用于 SSA 重命名）
        self.var_versions: Dict[str, int] = {}
    
    def build_function(self, func_ast: Any, func_name: str) -> SSAFunction:
        """
        构建函数的 SSA 表示
        
        Args:
            func_ast: Tree-sitter 函数 AST 节点
            func_name: 函数名
        
        Returns:
            SSA 函数对象
        """
        self.current_function = SSAFunction(name=func_name)
        self.var_versions = {}
        
        # 1. 创建入口块
        entry_block = self.current_function.add_block("entry")
        self.current_block = entry_block
        
        # 2. 提取参数
        params = self._extract_parameters(func_ast)
        for param_name in params:
            param_value = self.current_function.new_value(param_name)
            self.current_function.parameters.append(param_value)
            self.current_function.symbol_table[param_name] = param_value
        
        # 3. 构建函数体
        body = self._get_function_body(func_ast)
        if body:
            self._build_statements(body)
        
        return self.current_function
    
    def _extract_parameters(self, func_ast: Any) -> List[str]:
        """提取函数参数（语言相关，子类实现）"""
        raise NotImplementedError()
    
    def _get_function_body(self, func_ast: Any) -> Any:
        """获取函数体（语言相关，子类实现）"""
        raise NotImplementedError()
    
    def _build_statements(self, statements: Any):
        """
        构建语句序列

        处理：
        - 赋值语句 → ASSIGN 指令
        - 控制流（if/while/for/switch） → BRANCH/PHI
        - 函数调用 → CALL 指令
        - 异常处理（try/catch） → 多路分支
        """
        # 遍历所有语句
        for stmt in self._iterate_statements(statements):
            stmt_type = stmt.type

            if stmt_type in ['expression_statement', 'call_expression']:
                self._build_call(stmt)
            elif stmt_type in ['assignment', 'variable_declaration', 'assignment_expression',
                                'local_variable_declaration']:
                self._build_assignment(stmt)
            elif stmt_type == 'if_statement':
                self._build_if(stmt)
            elif stmt_type == 'return_statement':
                self._build_return(stmt)
            elif stmt_type == 'while_statement':
                self._build_while(stmt)
            elif stmt_type in ['for_statement', 'for_in_statement',
                                 'enhanced_for_statement']:
                self._build_for(stmt)
            elif stmt_type == 'switch_statement':
                self._build_switch(stmt)
            elif stmt_type == 'try_statement':
                self._build_try(stmt)
    
    def _iterate_statements(self, node: Any):
        """迭代语句节点（语言相关）"""
        if hasattr(node, 'children'):
            for child in node.children:
                yield child
    
    def _build_call(self, call_node: Any):
        """构建函数调用指令"""
        # 提取函数名
        func_name = self._extract_function_name(call_node)
        if not func_name:
            return
        
        # 提取参数
        args = self._extract_call_arguments(call_node)
        arg_values = []
        for arg in args:
            arg_value = self._build_expression(arg)
            if arg_value:
                arg_values.append(arg_value)
        
        # 创建 CALL 指令
        result = self.current_function.new_value()
        inst = SSAInstruction(
            type=InstructionType.CALL,
            result=result,
            operands=arg_values,
            function_name=func_name
        )
        
        self.current_block.add_instruction(inst)
        return result
    
    def _build_assignment(self, assign_node: Any):
        """构建赋值指令"""
        # 提取左值（变量名）
        var_name = self._extract_lhs_variable(assign_node)
        if not var_name:
            return
        
        # 提取右值（表达式）
        rhs = self._extract_rhs_expression(assign_node)
        rhs_value = self._build_expression(rhs)
        
        # SSA 重命名：var_name → var_name_v{n}
        new_version = self.var_versions.get(var_name, 0) + 1
        self.var_versions[var_name] = new_version
        
        ssa_name = f"{var_name}_v{new_version}"
        ssa_value = SSAValue(ssa_name)
        
        # 创建 ASSIGN 指令
        inst = SSAInstruction(
            type=InstructionType.ASSIGN,
            result=ssa_value,
            operands=[rhs_value] if rhs_value else []
        )
        
        self.current_block.add_instruction(inst)
        self.current_function.symbol_table[var_name] = ssa_value
        
        return ssa_value
    
    def _build_if(self, if_node: Any):
        """
        构建 if 语句 → 条件分支
        
        转换为：
        Block_current:
            condition = ...
            br condition, Block_then, Block_else
        
        Block_then:
            ...
            goto Block_merge
        
        Block_else:
            ...
            goto Block_merge
        
        Block_merge:
            phi nodes...
        """
        # 1. 构建条件表达式
        condition_expr = self._extract_condition(if_node)
        condition_value = self._build_expression(condition_expr)
        
        # 2. 创建分支块
        then_block = self.current_function.add_block(f"then_{len(self.current_function.blocks)}")
        else_block = self.current_function.add_block(f"else_{len(self.current_function.blocks)}")
        merge_block = self.current_function.add_block(f"merge_{len(self.current_function.blocks)}")
        
        # 3. 当前块添加 BRANCH 指令
        branch_inst = SSAInstruction(
            type=InstructionType.BRANCH,
            operands=[condition_value] if condition_value else [],
            target_label=then_block.label
        )
        self.current_block.add_instruction(branch_inst)
        
        # 设置控制流
        self.current_block.successors.extend([then_block, else_block])
        then_block.predecessors.append(self.current_block)
        else_block.predecessors.append(self.current_block)
        
        # 4. 构建 then 分支（快照用于 PHI）
        before_snapshot = dict(self.current_function.symbol_table)
        self.current_block = then_block
        then_body = self._extract_then_body(if_node)
        if then_body:
            self._build_statements(then_body)
        then_snapshot = dict(self.current_function.symbol_table)

        # 跳转到 merge 块
        jump_inst = SSAInstruction(
            type=InstructionType.JUMP,
            target_label=merge_block.label
        )
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(merge_block)
        merge_block.predecessors.append(self.current_block)

        # 5. 构建 else 分支
        self.current_function.symbol_table = dict(before_snapshot)
        self.current_block = else_block
        else_body = self._extract_else_body(if_node)
        if else_body:
            self._build_statements(else_body)
        else_snapshot = dict(self.current_function.symbol_table)

        # 跳转到 merge 块
        jump_inst = SSAInstruction(
            type=InstructionType.JUMP,
            target_label=merge_block.label
        )
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(merge_block)
        merge_block.predecessors.append(self.current_block)

        # 6. 合并块插入 PHI 节点
        self._insert_phi_nodes(merge_block, [then_snapshot, else_snapshot])

        self.current_block = merge_block
    
    def _build_return(self, return_node: Any):
        """构建返回指令"""
        return_expr = self._extract_return_expression(return_node)
        return_value = self._build_expression(return_expr)

        inst = SSAInstruction(
            type=InstructionType.RETURN,
            operands=[return_value] if return_value else []
        )
        self.current_block.add_instruction(inst)

    def _build_while(self, while_node: Any):
        """
        构建 while 循环

        Block_current → Block_header → Block_body → Block_header (back edge)
                                    ↓
                             Block_exit
        """
        n = len(self.current_function.blocks)
        header_block = self.current_function.add_block(f"while_header_{n}")
        n = len(self.current_function.blocks)
        body_block = self.current_function.add_block(f"while_body_{n}")
        n = len(self.current_function.blocks)
        exit_block = self.current_function.add_block(f"while_exit_{n}")

        # 1. 当前块 → header
        jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=header_block.label)
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(header_block)
        header_block.predecessors.append(self.current_block)

        # 2. header: 条件检查 → body 或 exit
        self.current_block = header_block
        condition_expr = self._extract_while_condition(while_node)
        condition_value = self._build_expression(condition_expr)

        branch_inst = SSAInstruction(
            type=InstructionType.BRANCH,
            operands=[condition_value] if condition_value else [],
            target_label=body_block.label
        )
        header_block.add_instruction(branch_inst)
        header_block.successors.extend([body_block, exit_block])
        body_block.predecessors.append(header_block)
        exit_block.predecessors.append(header_block)

        # 3. 构建循环体（快照用于 PHI）
        before_snapshot = dict(self.current_function.symbol_table)
        self.current_block = body_block
        body = self._extract_while_body(while_node)
        if body:
            self._build_statements(body)
        after_snapshot = dict(self.current_function.symbol_table)

        # 回边：body末尾 → header
        back_edge = SSAInstruction(type=InstructionType.JUMP, target_label=header_block.label)
        self.current_block.add_instruction(back_edge)
        self.current_block.successors.append(header_block)
        header_block.predecessors.append(self.current_block)

        # 4. 在 header 插入修改变量的 PHI 节点（loop-carried）
        self._insert_phi_nodes(header_block, [before_snapshot, after_snapshot])

        self.current_block = exit_block

    def _build_for(self, for_node: Any):
        """
        构建 for 循环（展开为：init → while(cond) { body; update }）
        """
        # 1. 初始化语句
        init = self._extract_for_init(for_node)
        if init:
            for child in self._iterate_statements(init):
                self._build_assignment(child)

        n = len(self.current_function.blocks)
        header_block = self.current_function.add_block(f"for_header_{n}")
        n = len(self.current_function.blocks)
        body_block = self.current_function.add_block(f"for_body_{n}")
        n = len(self.current_function.blocks)
        exit_block = self.current_function.add_block(f"for_exit_{n}")

        # 当前块 → header
        jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=header_block.label)
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(header_block)
        header_block.predecessors.append(self.current_block)

        # header: 条件
        self.current_block = header_block
        condition_expr = self._extract_for_condition(for_node)
        condition_value = self._build_expression(condition_expr) if condition_expr else None

        branch_inst = SSAInstruction(
            type=InstructionType.BRANCH,
            operands=[condition_value] if condition_value else [],
            target_label=body_block.label
        )
        header_block.add_instruction(branch_inst)
        header_block.successors.extend([body_block, exit_block])
        body_block.predecessors.append(header_block)
        exit_block.predecessors.append(header_block)

        # body
        before_snapshot = dict(self.current_function.symbol_table)
        self.current_block = body_block
        body = self._extract_for_body(for_node)
        if body:
            self._build_statements(body)

        # update（作为表达式求值）
        update = self._extract_for_update(for_node)
        if update:
            self._build_expression(update)

        after_snapshot = dict(self.current_function.symbol_table)

        # 回边
        back_edge = SSAInstruction(type=InstructionType.JUMP, target_label=header_block.label)
        self.current_block.add_instruction(back_edge)
        self.current_block.successors.append(header_block)
        header_block.predecessors.append(self.current_block)

        self._insert_phi_nodes(header_block, [before_snapshot, after_snapshot])
        self.current_block = exit_block

    def _build_switch(self, switch_node: Any):
        """
        构建 switch/case 语句

        entry → case_0 → exit
              → case_1 → exit
              → ...    → exit
        """
        switch_expr = self._extract_switch_value(switch_node)
        switch_val = self._build_expression(switch_expr)

        cases = self._extract_switch_cases(switch_node)

        n = len(self.current_function.blocks)
        exit_block = self.current_function.add_block(f"switch_exit_{n}")
        entry_block = self.current_block
        snapshots = [dict(self.current_function.symbol_table)]

        for i, (case_value, case_body) in enumerate(cases):
            n = len(self.current_function.blocks)
            case_block = self.current_function.add_block(f"case_{i}_{n}")

            case_const = SSAValue(
                name=f"case_{case_value}",
                is_constant=True,
                constant_value=case_value
            ) if case_value is not None else None
            branch_inst = SSAInstruction(
                type=InstructionType.BRANCH,
                operands=[switch_val, case_const] if case_const else [switch_val],
                target_label=case_block.label
            )
            entry_block.add_instruction(branch_inst)
            entry_block.successors.append(case_block)
            case_block.predecessors.append(entry_block)

            # 保存/恢复符号表，每个分支独立探索
            saved_table = dict(self.current_function.symbol_table)
            saved_versions = dict(self.var_versions)

            self.current_block = case_block
            if case_body:
                self._build_statements(case_body)

            jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=exit_block.label)
            self.current_block.add_instruction(jump_inst)
            self.current_block.successors.append(exit_block)
            exit_block.predecessors.append(self.current_block)

            snapshots.append(dict(self.current_function.symbol_table))

            self.current_function.symbol_table = saved_table
            self.var_versions = saved_versions

        self._insert_phi_nodes(exit_block, snapshots)
        self.current_block = exit_block

    def _build_try(self, try_node: Any):
        """
        构建 try/catch/finally 语句

        current → try_block  → finally_block → merge
                → catch_block → finally_block → merge
        """
        n = len(self.current_function.blocks)
        try_block = self.current_function.add_block(f"try_body_{n}")
        n = len(self.current_function.blocks)
        catch_block = self.current_function.add_block(f"catch_{n}")
        n = len(self.current_function.blocks)
        finally_block = self.current_function.add_block(f"finally_{n}")
        n = len(self.current_function.blocks)
        merge_block = self.current_function.add_block(f"try_merge_{n}")

        # current → try_block (异常时可跳转到 catch)
        jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=try_block.label)
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.extend([try_block, catch_block])
        try_block.predecessors.append(self.current_block)
        catch_block.predecessors.append(self.current_block)

        # try 体
        saved_table = dict(self.current_function.symbol_table)
        saved_versions = dict(self.var_versions)
        self.current_block = try_block
        try_body = self._extract_try_body(try_node)
        if try_body:
            self._build_statements(try_body)
        try_snapshot = dict(self.current_function.symbol_table)
        jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=finally_block.label)
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(finally_block)
        finally_block.predecessors.append(self.current_block)

        # catch/except 体（恢复进入状态）
        self.current_function.symbol_table = dict(saved_table)
        self.var_versions = dict(saved_versions)
        self.current_block = catch_block
        handlers = self._extract_catch_handlers(try_node)
        for handler_body in handlers:
            if handler_body:
                self._build_statements(handler_body)
        catch_snapshot = dict(self.current_function.symbol_table)
        jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=finally_block.label)
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(finally_block)
        finally_block.predecessors.append(self.current_block)

        # finally 体
        self.current_block = finally_block
        finally_body = self._extract_finally_body(try_node)
        if finally_body:
            self._build_statements(finally_body)
        jump_inst = SSAInstruction(type=InstructionType.JUMP, target_label=merge_block.label)
        self.current_block.add_instruction(jump_inst)
        self.current_block.successors.append(merge_block)
        merge_block.predecessors.append(self.current_block)

        # PHI 节点合并 try/catch 路径的差异
        self._insert_phi_nodes(merge_block, [try_snapshot, catch_snapshot])
        self.current_block = merge_block

    def _insert_phi_nodes(self, merge_block: Any, snapshots: List[Dict]):
        """
        在合并块插入 PHI 节点

        Args:
            merge_block: 目标 SSABlock
            snapshots: 各前驱路径合并前的符号表快照列表
        """
        if len(snapshots) < 2:
            return

        all_vars: set = set()
        for snap in snapshots:
            all_vars.update(snap.keys())

        for var_name in sorted(all_vars):
            versions = [snap.get(var_name) for snap in snapshots]
            unique = {v.name if v is not None else None for v in versions}
            if len(unique) <= 1:
                continue  # 所有路径相同，不需要 PHI

            phi_result = SSAValue(name=f"{var_name}_phi")
            valid_operands = [v for v in versions if v is not None]
            phi_inst = SSAInstruction(
                type=InstructionType.PHI,
                result=phi_result,
                operands=valid_operands
            )
            merge_block.add_instruction(phi_inst)
            # 更新符号表指向合并后的 PHI 值
            self.current_function.symbol_table[var_name] = phi_result
    
    def _build_expression(self, expr_node: Any) -> Optional[SSAValue]:
        """
        构建表达式 → SSA 值
        
        处理：
        - 字面量 → 常量 SSA 值
        - 变量引用 → 查符号表
        - 二元运算 → BINARY_OP 指令
        - 函数调用 → CALL 指令
        """
        if not expr_node:
            return None
        
        expr_type = expr_node.type
        
        # 字面量
        if expr_type in ['number', 'integer_literal', 'float_literal']:
            value = self._extract_literal_value(expr_node)
            return SSAValue(
                name=f"const_{value}",
                is_constant=True,
                constant_value=value
            )
        
        # 字符串
        elif expr_type in ['string', 'string_literal']:
            value = self._extract_string_value(expr_node)
            return SSAValue(
                name=f'const_"{value}"',
                is_constant=True,
                constant_value=value
            )
        
        # 变量引用
        elif expr_type in ['identifier', 'variable_name']:
            var_name = expr_node.text.decode('utf-8')
            # 查符号表，返回最新版本
            return self.current_function.symbol_table.get(var_name)
        
        # 二元运算
        elif expr_type in ['binary_expression', 'binary_operator']:
            return self._build_binary_op(expr_node)
        
        # 函数调用
        elif expr_type in ['call_expression', 'function_call']:
            return self._build_call(expr_node)
        
        # 默认：返回占位符
        return SSAValue(name="unknown")
    
    def _build_binary_op(self, op_node: Any) -> SSAValue:
        """构建二元运算"""
        # 提取左右操作数
        left = self._extract_left_operand(op_node)
        right = self._extract_right_operand(op_node)
        operator = self._extract_operator(op_node)
        
        left_value = self._build_expression(left)
        right_value = self._build_expression(right)
        
        # 创建 BINARY_OP 指令
        result = self.current_function.new_value()
        inst = SSAInstruction(
            type=InstructionType.BINARY_OP,
            result=result,
            operands=[left_value, right_value],
            operator=operator
        )
        
        self.current_block.add_instruction(inst)
        return result
    
    # ===== 语言相关方法（子类实现）=====
    
    def _extract_function_name(self, call_node: Any) -> Optional[str]:
        """提取函数名"""
        raise NotImplementedError()
    
    def _extract_call_arguments(self, call_node: Any) -> List[Any]:
        """提取调用参数"""
        raise NotImplementedError()
    
    def _extract_lhs_variable(self, assign_node: Any) -> Optional[str]:
        """提取赋值左值变量名"""
        raise NotImplementedError()
    
    def _extract_rhs_expression(self, assign_node: Any) -> Any:
        """提取赋值右值表达式"""
        raise NotImplementedError()
    
    def _extract_condition(self, if_node: Any) -> Any:
        """提取 if 条件"""
        raise NotImplementedError()
    
    def _extract_then_body(self, if_node: Any) -> Any:
        """提取 then 分支"""
        raise NotImplementedError()
    
    def _extract_else_body(self, if_node: Any) -> Any:
        """提取 else 分支"""
        raise NotImplementedError()
    
    def _extract_return_expression(self, return_node: Any) -> Any:
        """提取返回表达式"""
        raise NotImplementedError()

    # ----- 循环/switch/try 提取（子类实现）-----

    def _extract_while_condition(self, while_node: Any) -> Any:
        """提取 while 条件表达式（语言相关，子类实现）"""
        raise NotImplementedError()

    def _extract_while_body(self, while_node: Any) -> Any:
        """提取 while 循环体（语言相关，子类实现）"""
        raise NotImplementedError()

    def _extract_for_init(self, for_node: Any) -> Any:
        """提取 for 初始化部分（语言相关，子类实现）"""
        return None  # 默认无初始化（for-in/enhanced-for）

    def _extract_for_condition(self, for_node: Any) -> Any:
        """提取 for 条件部分（语言相关，子类实现）"""
        return None

    def _extract_for_update(self, for_node: Any) -> Any:
        """提取 for 更新部分（语言相关，子类实现）"""
        return None

    def _extract_for_body(self, for_node: Any) -> Any:
        """提取 for 循环体（语言相关，子类实现）"""
        raise NotImplementedError()

    def _extract_switch_value(self, switch_node: Any) -> Any:
        """提取 switch 表达式（语言相关，子类实现）"""
        raise NotImplementedError()

    def _extract_switch_cases(self, switch_node: Any) -> List[tuple]:
        """提取 switch case 列表 → [(case_value_or_None, body_node), ...]"""
        raise NotImplementedError()

    def _extract_try_body(self, try_node: Any) -> Any:
        """提取 try 主体（语言相关，子类实现）"""
        raise NotImplementedError()

    def _extract_catch_handlers(self, try_node: Any) -> List[Any]:
        """提取 catch/except 处理块列表（语言相关，子类实现）"""
        raise NotImplementedError()

    def _extract_finally_body(self, try_node: Any) -> Any:
        """提取 finally 块（语言相关，子类实现）"""
        return None  # 默认无 finally

    def _extract_literal_value(self, literal_node: Any) -> Any:
        """提取字面量值"""
        text = literal_node.text.decode('utf-8')
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text
    
    def _extract_string_value(self, string_node: Any) -> str:
        """提取字符串值"""
        text = string_node.text.decode('utf-8')
        return text.strip('"').strip("'")
    
    def _extract_left_operand(self, op_node: Any) -> Any:
        """提取左操作数"""
        if hasattr(op_node, 'children') and len(op_node.children) >= 1:
            return op_node.children[0]
        return None
    
    def _extract_right_operand(self, op_node: Any) -> Any:
        """提取右操作数"""
        if hasattr(op_node, 'children') and len(op_node.children) >= 3:
            return op_node.children[2]
        return None
    
    def _extract_operator(self, op_node: Any) -> str:
        """提取运算符"""
        if hasattr(op_node, 'children') and len(op_node.children) >= 2:
            return op_node.children[1].text.decode('utf-8')
        return "?"


# ===== 语言特定的 IR 构建器 =====

class CIRBuilder(IRBuilder):
    """C 语言 IR 构建器"""
    
    def __init__(self):
        super().__init__("c")
    
    def _extract_parameters(self, func_ast: Any) -> List[str]:
        """C 函数参数提取"""
        params = []
        for child in func_ast.children:
            if child.type == 'function_declarator':
                # 查找参数列表
                for subchild in child.children:
                    if subchild.type == 'parameter_list':
                        for param in subchild.children:
                            if param.type == 'parameter_declaration':
                                # 提取参数名
                                for p in param.children:
                                    if p.type == 'identifier':
                                        params.append(p.text.decode('utf-8'))
        return params
    
    def _get_function_body(self, func_ast: Any) -> Any:
        """C 函数体提取"""
        for child in func_ast.children:
            if child.type == 'compound_statement':
                return child
        return None
    
    def _extract_function_name(self, call_node: Any) -> Optional[str]:
        """C 函数调用名称提取"""
        for child in call_node.children:
            if child.type in ['identifier', 'field_expression']:
                return child.text.decode('utf-8')
        return None
    
    def _extract_call_arguments(self, call_node: Any) -> List[Any]:
        """C 函数参数提取"""
        for child in call_node.children:
            if child.type == 'argument_list':
                return [arg for arg in child.children if arg.type != ',']
        return []
    
    def _extract_lhs_variable(self, assign_node: Any) -> Optional[str]:
        """C 赋值左值提取"""
        if assign_node.type == 'assignment_expression':
            # assignment_expression: left = right
            for child in assign_node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8')
        elif assign_node.type == 'declaration':
            # declaration: type identifier = value
            for child in assign_node.children:
                if child.type == 'init_declarator':
                    for subchild in child.children:
                        if subchild.type == 'identifier':
                            return subchild.text.decode('utf-8')
        return None
    
    def _extract_rhs_expression(self, assign_node: Any) -> Any:
        """C 赋值右值提取"""
        if assign_node.type == 'assignment_expression':
            # 找到 = 后的表达式
            found_eq = False
            for child in assign_node.children:
                if found_eq:
                    return child
                if child.type == '=' or child.text == b'=':
                    found_eq = True
        elif assign_node.type == 'declaration':
            # declaration: type identifier = value
            for child in assign_node.children:
                if child.type == 'init_declarator':
                    found_eq = False
                    for subchild in child.children:
                        if found_eq:
                            return subchild
                        if subchild.type == '=' or subchild.text == b'=':
                            found_eq = True
        return None
    
    def _extract_condition(self, if_node: Any) -> Any:
        """C if 条件提取"""
        for child in if_node.children:
            if child.type == 'parenthesized_expression':
                # 返回括号内的表达式
                for subchild in child.children:
                    if subchild.type != '(' and subchild.type != ')':
                        return subchild
        return None
    
    def _extract_then_body(self, if_node: Any) -> Any:
        """C then 分支提取"""
        # 第一个 compound_statement 或单个语句
        for child in if_node.children:
            if child.type in ['compound_statement', 'expression_statement', 'return_statement']:
                return child
        return None
    
    def _extract_else_body(self, if_node: Any) -> Any:
        """C else 分支提取"""
        # 查找 else 关键字后的语句
        found_else = False
        for child in if_node.children:
            if found_else:
                if child.type in ['compound_statement', 'expression_statement', 'return_statement', 'if_statement']:
                    return child
            if child.type == 'else' or child.text == b'else':
                found_else = True
        return None
    
    def _extract_return_expression(self, return_node: Any) -> Any:
        """C return 表达式提取"""
        for child in return_node.children:
            if child.type not in ['return', ';']:
                return child
        return None

    # ----- C 循环提取 -----

    def _extract_while_condition(self, while_node: Any) -> Any:
        """C while 条件提取: while (cond) { }"""
        for child in while_node.children:
            if child.type == 'parenthesized_expression':
                for sub in child.children:
                    if sub.type not in ['(', ')']:
                        return sub
        return None

    def _extract_while_body(self, while_node: Any) -> Any:
        """C while 体提取"""
        for child in while_node.children:
            if child.type == 'compound_statement':
                return child
        return None

    def _extract_for_init(self, for_node: Any) -> Any:
        """C for 初始化提取: 第一个 ; 前的语句"""
        inside = False
        for child in for_node.children:
            if child.type == '(':
                inside = True
                continue
            if not inside:
                continue
            if child.type == ';':
                break
            if child.type not in ['for', ')']:
                return child
        return None

    def _extract_for_condition(self, for_node: Any) -> Any:
        """C for 条件提取: 两个 ; 之间"""
        semi_count = 0
        for child in for_node.children:
            if child.type == ';':
                semi_count += 1
                continue
            if semi_count == 1 and child.type not in ['for', '(', ')']:
                return child
        return None

    def _extract_for_update(self, for_node: Any) -> Any:
        """C for 更新提取: 第二个 ; 后、) 前"""
        semi_count = 0
        for child in for_node.children:
            if child.type == ';':
                semi_count += 1
                continue
            if child.type == ')':
                break
            if semi_count == 2 and child.type not in ['for', '(']:
                return child
        return None

    def _extract_for_body(self, for_node: Any) -> Any:
        """C for 循环体提取"""
        for child in reversed(for_node.children):
            if child.type == 'compound_statement':
                return child
        return None

    # ----- C switch 提取 -----

    def _extract_switch_value(self, switch_node: Any) -> Any:
        """C switch 表达式提取"""
        for child in switch_node.children:
            if child.type == 'parenthesized_expression':
                for sub in child.children:
                    if sub.type not in ['(', ')']:
                        return sub
        return None

    def _extract_switch_cases(self, switch_node: Any) -> List[tuple]:
        """C switch case 列表提取 -> [(case_value, body_node), ...]"""
        cases = []
        body_node = None
        for child in switch_node.children:
            if child.type == 'compound_statement':
                body_node = child
                break
        if not body_node:
            return cases
        current_value = None
        current_stmts = []
        for child in body_node.children:
            if child.type == 'case_statement':
                if current_value is not None or current_stmts:
                    cases.append((current_value, _StmtList(current_stmts)))
                current_value = None
                current_stmts = []
                for sub in child.children:
                    if sub.type not in ['case', 'default', ':']:
                        try:
                            current_value = int(sub.text.decode('utf-8'))
                        except (ValueError, AttributeError):
                            current_value = sub.text.decode('utf-8') if hasattr(sub, 'text') else None
                        break
            elif child.type not in ['{', '}']:
                current_stmts.append(child)
        if current_value is not None or current_stmts:
            cases.append((current_value, _StmtList(current_stmts)))
        return cases

    # ----- C 无 try/catch，返回空 -----

    def _extract_try_body(self, try_node: Any) -> Any:
        return None

    def _extract_catch_handlers(self, try_node: Any) -> List[Any]:
        return []


class _StmtList:
    """helper: 包装一组语句节点供 _iterate_statements 遍历"""
    def __init__(self, children: list):
        self.children = children


class PythonIRBuilder(IRBuilder):
    """Python IR 构建器"""
    
    def __init__(self):
        super().__init__("python")
    
    def _extract_parameters(self, func_ast: Any) -> List[str]:
        """Python 函数参数提取"""
        params = []
        for child in func_ast.children:
            if child.type == 'parameters':
                for param in child.children:
                    if param.type == 'identifier':
                        params.append(param.text.decode('utf-8'))
                    elif param.type == 'typed_parameter':
                        # 带类型注解的参数: name: type
                        for subchild in param.children:
                            if subchild.type == 'identifier':
                                params.append(subchild.text.decode('utf-8'))
                                break
        return params
    
    def _get_function_body(self, func_ast: Any) -> Any:
        """Python 函数体提取"""
        for child in func_ast.children:
            if child.type == 'block':
                return child
        return None
    
    def _extract_function_name(self, call_node: Any) -> Optional[str]:
        """Python 函数调用名称提取"""
        # call: function(args)
        if call_node.type == 'call':
            for child in call_node.children:
                if child.type in ['identifier', 'attribute']:
                    return child.text.decode('utf-8')
        # expression_statement 可能包含 call
        elif call_node.type == 'expression_statement':
            for child in call_node.children:
                if child.type == 'call':
                    return self._extract_function_name(child)
        return None
    
    def _extract_call_arguments(self, call_node: Any) -> List[Any]:
        """Python 函数参数提取"""
        # 查找 argument_list
        if call_node.type == 'call':
            for child in call_node.children:
                if child.type == 'argument_list':
                    args = []
                    for arg in child.children:
                        if arg.type not in ['(', ')', ',']:
                            args.append(arg)
                    return args
        # expression_statement 可能包含 call
        elif call_node.type == 'expression_statement':
            for child in call_node.children:
                if child.type == 'call':
                    return self._extract_call_arguments(child)
        return []
    
    def _extract_lhs_variable(self, assign_node: Any) -> Optional[str]:
        """Python 赋值左值提取"""
        # assignment: identifier = expression
        # expression_statement > assignment
        if assign_node.type == 'expression_statement':
            for child in assign_node.children:
                if child.type == 'assignment':
                    return self._extract_lhs_variable(child)
        elif assign_node.type == 'assignment':
            for child in assign_node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8')
        return None
    
    def _extract_rhs_expression(self, assign_node: Any) -> Any:
        """Python 赋值右值提取"""
        if assign_node.type == 'expression_statement':
            for child in assign_node.children:
                if child.type == 'assignment':
                    return self._extract_rhs_expression(child)
        elif assign_node.type == 'assignment':
            # 找到 = 后的表达式
            found_eq = False
            for child in assign_node.children:
                if found_eq:
                    return child
                if child.type == '=' or child.text == b'=':
                    found_eq = True
        return None
    
    def _extract_condition(self, if_node: Any) -> Any:
        """Python if 条件提取"""
        # if_statement: if condition: block
        for child in if_node.children:
            if child.type not in ['if', ':', 'block', 'elif_clause', 'else_clause']:
                return child
        return None
    
    def _extract_then_body(self, if_node: Any) -> Any:
        """Python then 分支提取"""
        # 第一个 block
        for child in if_node.children:
            if child.type == 'block':
                return child
        return None
    
    def _extract_else_body(self, if_node: Any) -> Any:
        """Python else 分支提取"""
        # 查找 else_clause
        for child in if_node.children:
            if child.type == 'else_clause':
                # else_clause 包含 block
                for subchild in child.children:
                    if subchild.type == 'block':
                        return subchild
        return None
    
    def _extract_return_expression(self, return_node: Any) -> Any:
        """Python return 表达式提取"""
        for child in return_node.children:
            if child.type not in ['return']:
                return child
        return None

    # ----- Python 循环提取 -----

    def _extract_while_condition(self, while_node: Any) -> Any:
        """Python while 条件提取"""
        for child in while_node.children:
            if child.type not in ['while', ':', 'block', 'comment']:
                return child
        return None

    def _extract_while_body(self, while_node: Any) -> Any:
        """Python while 体提取"""
        for child in while_node.children:
            if child.type == 'block':
                return child
        return None

    def _extract_for_body(self, for_node: Any) -> Any:
        """Python for 体提取"""
        for child in for_node.children:
            if child.type == 'block':
                return child
        return None

    # ----- Python match/case (3.10+) 或备用空实现 -----

    def _extract_switch_value(self, switch_node: Any) -> Any:
        """Python match 语句的匹配表达式"""
        for child in switch_node.children:
            if child.type not in ['match', ':', 'block']:
                return child
        return None

    def _extract_switch_cases(self, switch_node: Any) -> List[tuple]:
        """Python match/case 列表提取"""
        cases = []
        for child in switch_node.children:
            if child.type == 'block':
                for sub in child.children:
                    if sub.type == 'case_block':
                        case_val = None
                        case_body = None
                        for part in sub.children:
                            if part.type not in ['case', ':']:
                                if case_val is None:
                                    try:
                                        case_val = int(part.text.decode('utf-8'))
                                    except (ValueError, AttributeError):
                                        case_val = part.text.decode('utf-8') if hasattr(part, 'text') else None
                                elif part.type == 'block':
                                    case_body = part
                        cases.append((case_val, case_body))
        return cases

    # ----- Python try/except/finally -----

    def _extract_try_body(self, try_node: Any) -> Any:
        """Python try 主体提取"""
        for child in try_node.children:
            if child.type == 'block':
                return child
        return None

    def _extract_catch_handlers(self, try_node: Any) -> List[Any]:
        """Python except_clause 列表提取"""
        handlers = []
        for child in try_node.children:
            if child.type in ['except_clause', 'except_group_clause']:
                for sub in child.children:
                    if sub.type == 'block':
                        handlers.append(sub)
        return handlers

    def _extract_finally_body(self, try_node: Any) -> Any:
        """Python finally 块提取"""
        for child in try_node.children:
            if child.type == 'finally_clause':
                for sub in child.children:
                    if sub.type == 'block':
                        return sub
        return None


class JavaIRBuilder(IRBuilder):
    """Java IR 构建器"""

    def __init__(self):
        super().__init__("java")

    def _extract_parameters(self, func_ast: Any) -> List[str]:
        """Java 函数参数提取"""
        params = []
        for child in func_ast.children:
            if child.type == 'formal_parameters':
                for param in child.children:
                    if param.type in ['formal_parameter', 'spread_parameter']:
                        for sub in param.children:
                            if sub.type == 'identifier':
                                params.append(sub.text.decode('utf-8'))
        return params

    def _get_function_body(self, func_ast: Any) -> Any:
        """Java 函数体提取"""
        for child in func_ast.children:
            if child.type == 'block':
                return child
        return None

    def _extract_function_name(self, call_node: Any) -> Optional[str]:
        """Java 函数调用名提取"""
        for child in call_node.children:
            if child.type in ['identifier', 'method_invocation', 'field_access']:
                return child.text.decode('utf-8')
        return None

    def _extract_call_arguments(self, call_node: Any) -> List[Any]:
        """Java 调用参数提取"""
        for child in call_node.children:
            if child.type == 'argument_list':
                return [c for c in child.children if c.type not in ['(', ')', ',']]
        return []

    def _extract_lhs_variable(self, assign_node: Any) -> Optional[str]:
        """Java 赋值左值提取"""
        if assign_node.type == 'assignment_expression':
            for child in assign_node.children:
                if child.type == 'identifier':
                    return child.text.decode('utf-8')
        elif assign_node.type == 'local_variable_declaration':
            for child in assign_node.children:
                if child.type == 'variable_declarator':
                    for sub in child.children:
                        if sub.type == 'identifier':
                            return sub.text.decode('utf-8')
        return None

    def _extract_rhs_expression(self, assign_node: Any) -> Any:
        """Java 赋值右值提取"""
        if assign_node.type == 'assignment_expression':
            found_eq = False
            for child in assign_node.children:
                if found_eq:
                    return child
                if child.type == '=' or child.text == b'=':
                    found_eq = True
        elif assign_node.type == 'local_variable_declaration':
            for child in assign_node.children:
                if child.type == 'variable_declarator':
                    found_eq = False
                    for sub in child.children:
                        if found_eq:
                            return sub
                        if sub.type == '=' or sub.text == b'=':
                            found_eq = True
        return None

    def _extract_condition(self, if_node: Any) -> Any:
        """Java if 条件提取"""
        for child in if_node.children:
            if child.type == 'parenthesized_expression':
                for sub in child.children:
                    if sub.type not in ['(', ')']:
                        return sub
        return None

    def _extract_then_body(self, if_node: Any) -> Any:
        """Java then 分支提取"""
        for child in if_node.children:
            if child.type in ['block', 'expression_statement', 'return_statement']:
                return child
        return None

    def _extract_else_body(self, if_node: Any) -> Any:
        """Java else 分支提取"""
        found_else = False
        for child in if_node.children:
            if found_else:
                if child.type in ['block', 'expression_statement', 'return_statement', 'if_statement']:
                    return child
            if child.type == 'else' or child.text == b'else':
                found_else = True
        return None

    def _extract_return_expression(self, return_node: Any) -> Any:
        """Java return 表达式提取"""
        for child in return_node.children:
            if child.type not in ['return', ';']:
                return child
        return None

    # ----- Java 循环提取 -----

    def _extract_while_condition(self, while_node: Any) -> Any:
        for child in while_node.children:
            if child.type == 'parenthesized_expression':
                for sub in child.children:
                    if sub.type not in ['(', ')']:
                        return sub
        return None

    def _extract_while_body(self, while_node: Any) -> Any:
        for child in while_node.children:
            if child.type == 'block':
                return child
        return None

    def _extract_for_init(self, for_node: Any) -> Any:
        """Java for 初始化 (for-each 无 init)"""
        if for_node.type == 'enhanced_for_statement':
            return None
        inside = False
        for child in for_node.children:
            if child.type == '(':
                inside = True
                continue
            if not inside:
                continue
            if child.type == ';':
                break
            if child.type not in ['for']:
                return child
        return None

    def _extract_for_condition(self, for_node: Any) -> Any:
        if for_node.type == 'enhanced_for_statement':
            return None
        semi_count = 0
        for child in for_node.children:
            if child.type == ';':
                semi_count += 1
                continue
            if semi_count == 1 and child.type not in ['for', '(', ')']:
                return child
        return None

    def _extract_for_update(self, for_node: Any) -> Any:
        if for_node.type == 'enhanced_for_statement':
            return None
        semi_count = 0
        for child in for_node.children:
            if child.type == ';':
                semi_count += 1
                continue
            if child.type == ')':
                break
            if semi_count == 2 and child.type not in ['for', '(']:
                return child
        return None

    def _extract_for_body(self, for_node: Any) -> Any:
        for child in reversed(for_node.children):
            if child.type == 'block':
                return child
        return None

    # ----- Java switch 提取 -----

    def _extract_switch_value(self, switch_node: Any) -> Any:
        for child in switch_node.children:
            if child.type == 'parenthesized_expression':
                for sub in child.children:
                    if sub.type not in ['(', ')']:
                        return sub
        return None

    def _extract_switch_cases(self, switch_node: Any) -> List[tuple]:
        """Java switch 中的 case 列表"""
        cases = []
        for child in switch_node.children:
            if child.type == 'switch_block':
                current_value = None
                current_stmts = []
                for sub in child.children:
                    if sub.type == 'switch_label':
                        if current_value is not None or current_stmts:
                            cases.append((current_value, _StmtList(current_stmts)))
                        current_value = None
                        current_stmts = []
                        for part in sub.children:
                            if part.type not in ['case', 'default', ':']:
                                try:
                                    current_value = int(part.text.decode('utf-8'))
                                except (ValueError, AttributeError):
                                    current_value = part.text.decode('utf-8') if hasattr(part, 'text') else None
                                break
                    elif sub.type not in ['{', '}']:
                        current_stmts.append(sub)
                if current_value is not None or current_stmts:
                    cases.append((current_value, _StmtList(current_stmts)))
        return cases

    # ----- Java try/catch/finally -----

    def _extract_try_body(self, try_node: Any) -> Any:
        for child in try_node.children:
            if child.type == 'block':
                return child
        return None

    def _extract_catch_handlers(self, try_node: Any) -> List[Any]:
        handlers = []
        for child in try_node.children:
            if child.type == 'catch_clause':
                for sub in child.children:
                    if sub.type == 'block':
                        handlers.append(sub)
        return handlers

    def _extract_finally_body(self, try_node: Any) -> Any:
        for child in try_node.children:
            if child.type == 'finally_clause':
                for sub in child.children:
                    if sub.type == 'block':
                        return sub
        return None


class GoIRBuilder(IRBuilder):
    """
    Go 语言 IR 构建器

    Go 语法特殊性（与 C/Java 不同）：
    - 短变量声明 `x := expr`      → short_var_declaration
    - 普通赋值 `x = expr`          → assignment_statement
    - var 声明 `var x T = expr`    → var_declaration / var_spec
    - for 循环（while 形式）        → for_statement（无 range_clause）
    - for-range 循环               → for_statement（含 range_clause）
    - if/switch/for 条件均无括号
    - switch 语句                   → expression_switch_statement / expression_case_clause
    - 异常模型：defer + recover      → defer_statement（建模为 finally）
    - 函数调用 pkg.Func()           → call_expression → selector_expression
    """

    def __init__(self):
        super().__init__("go")

    # ----- 语句分发（覆盖基类，处理 Go 特有节点类型）-----

    def _build_statements(self, statements: Any):
        """Go 专用语句分发"""
        for stmt in self._iterate_statements(statements):
            stype = stmt.type
            if stype == 'expression_statement':
                self._build_call(stmt)
            elif stype == 'call_expression':
                self._build_call(stmt)
            elif stype in ['short_var_declaration', 'assignment_statement',
                           'var_declaration']:
                self._build_assignment(stmt)
            elif stype == 'if_statement':
                self._build_if(stmt)
            elif stype == 'return_statement':
                self._build_return(stmt)
            elif stype == 'for_statement':
                # Go for_statement: plain for (while-like) OR for range
                has_range = any(
                    c.type in ['range_clause', 'for_range_clause']
                    for c in stmt.children
                )
                if has_range:
                    self._build_for(stmt)
                else:
                    self._build_while(stmt)
            elif stype == 'expression_switch_statement':
                self._build_switch(stmt)
            elif stype == 'defer_statement':
                self._build_try(stmt)
            # 跳过 comment、import_declaration 等不产生 IR 的节点

    # ----- 核心基础设施 (14.1) -----

    def _extract_parameters(self, func_ast: Any) -> List[str]:
        """Go 函数参数提取 (parameter_list → parameter_declaration)"""
        params = []
        for child in func_ast.children:
            if child.type == 'parameter_list':
                for param in child.children:
                    if param.type == 'parameter_declaration':
                        # 同类型多名称：a, b int → 先收集所有 identifier（最后一个是类型名，其余为参数名）
                        idents = [sub for sub in param.children if sub.type == 'identifier']
                        # 如果还有 type_identifier / qualified_type 等，identifier 列表最后一项是类型
                        # 如果参数写为 (n int)，idents = [n, int]；(n, m int) → [n, m, int]
                        # tree-sitter-go 中类型用独立节点（type_identifier 等），identifier 只是参数名
                        # 实际上 tree-sitter-go parameter_declaration:
                        #   children: [identifier..., type]  其中 type 不是 identifier
                        # 所以直接取所有 identifier 均为参数名
                        for sub in param.children:
                            if sub.type == 'identifier':
                                params.append(sub.text.decode('utf-8'))
        return params

    def _get_function_body(self, func_ast: Any) -> Any:
        """Go 函数体提取 (function_declaration → block)"""
        for child in func_ast.children:
            if child.type == 'block':
                return child
        return None

    def _extract_function_name(self, call_node: Any) -> Optional[str]:
        """Go 函数调用名提取（处理 pkg.Func() 的 selector_expression）"""
        actual = call_node
        # 展开 expression_statement 外层
        if call_node.type == 'expression_statement':
            for child in call_node.children:
                if child.type == 'call_expression':
                    actual = child
                    break

        # 尝试通过字段名获取 function 节点
        func_node = None
        if hasattr(actual, 'child_by_field_name'):
            func_node = actual.child_by_field_name('function')
        if func_node is None:
            for child in actual.children:
                if child.type in ['identifier', 'selector_expression']:
                    func_node = child
                    break

        if func_node is None:
            return None
        return func_node.text.decode('utf-8')

    def _extract_call_arguments(self, call_node: Any) -> List[Any]:
        """Go 调用参数提取 (argument_list)"""
        actual = call_node
        if call_node.type == 'expression_statement':
            for child in call_node.children:
                if child.type == 'call_expression':
                    actual = child
                    break

        # 尝试字段名 arguments
        args_node = None
        if hasattr(actual, 'child_by_field_name'):
            args_node = actual.child_by_field_name('arguments')
        if args_node is not None:
            return [c for c in args_node.children if c.type not in ['(', ')', ',']]
        # fallback: 找 argument_list 子节点
        for child in actual.children:
            if child.type == 'argument_list':
                return [c for c in child.children if c.type not in ['(', ')', ',']]
        return []

    def _extract_lhs_variable(self, assign_node: Any) -> Optional[str]:
        """Go 赋值左值提取"""
        if assign_node.type == 'short_var_declaration':
            # 尝试字段 left
            left = None
            if hasattr(assign_node, 'child_by_field_name'):
                left = assign_node.child_by_field_name('left')
            if left is None:
                for child in assign_node.children:
                    if child.type in ['identifier', 'expression_list']:
                        left = child
                        break
            if left is not None:
                if left.type == 'expression_list':
                    for sub in left.children:
                        if sub.type == 'identifier':
                            return sub.text.decode('utf-8')
                elif left.type == 'identifier':
                    return left.text.decode('utf-8')

        elif assign_node.type == 'assignment_statement':
            for child in assign_node.children:
                if child.type == 'expression_list':
                    for sub in child.children:
                        if sub.type == 'identifier':
                            return sub.text.decode('utf-8')
                    break
                if child.type == 'identifier':
                    return child.text.decode('utf-8')

        elif assign_node.type == 'var_declaration':
            for child in assign_node.children:
                if child.type == 'var_spec':
                    for sub in child.children:
                        if sub.type == 'identifier':
                            return sub.text.decode('utf-8')
        return None

    def _extract_rhs_expression(self, assign_node: Any) -> Any:
        """Go 赋值右值提取"""
        if assign_node.type == 'short_var_declaration':
            right = None
            if hasattr(assign_node, 'child_by_field_name'):
                right = assign_node.child_by_field_name('right')
            if right is not None:
                if right.type == 'expression_list':
                    for child in right.children:
                        if child.type != ',':
                            return child
                return right
            # fallback: 找 ':=' 之后的节点
            found_op = False
            for child in assign_node.children:
                if hasattr(child, 'text') and child.text == b':=':
                    found_op = True
                    continue
                if found_op:
                    return child

        elif assign_node.type == 'assignment_statement':
            found_op = False
            for child in assign_node.children:
                if child.type in ['=', '+=', '-=', '*='] or (
                    hasattr(child, 'text') and child.text in [b'=', b'+=', b'-=']
                ):
                    found_op = True
                    continue
                if found_op:
                    if child.type == 'expression_list':
                        for sub in child.children:
                            if sub.type != ',':
                                return sub
                    return child

        elif assign_node.type == 'var_declaration':
            for child in assign_node.children:
                if child.type == 'var_spec':
                    found_eq = False
                    for sub in child.children:
                        if hasattr(sub, 'text') and sub.text == b'=':
                            found_eq = True
                            continue
                        if found_eq:
                            return sub
        return None

    def _extract_condition(self, if_node: Any) -> Any:
        """Go if 条件提取（无括号，通过字段名 condition）"""
        if hasattr(if_node, 'child_by_field_name'):
            cond = if_node.child_by_field_name('condition')
            if cond is not None:
                return cond
        # fallback: 第一个非 'if'/'else'/'block' 子节点
        for child in if_node.children:
            if child.type not in ['if', 'block', 'else', '{', '}']:
                return child
        return None

    def _extract_then_body(self, if_node: Any) -> Any:
        """Go then 分支提取"""
        if hasattr(if_node, 'child_by_field_name'):
            cons = if_node.child_by_field_name('consequence')
            if cons is not None:
                return cons
        for child in if_node.children:
            if child.type == 'block':
                return child
        return None

    def _extract_else_body(self, if_node: Any) -> Any:
        """Go else 分支提取"""
        if hasattr(if_node, 'child_by_field_name'):
            alt = if_node.child_by_field_name('alternative')
            if alt is not None:
                return alt
        found_else = False
        for child in if_node.children:
            if found_else:
                if child.type in ['block', 'if_statement']:
                    return child
            if child.type == 'else' or (hasattr(child, 'text') and child.text == b'else'):
                found_else = True
        return None

    def _extract_return_expression(self, return_node: Any) -> Any:
        """Go return 表达式提取"""
        for child in return_node.children:
            if child.type not in ['return']:
                return child
        return None

    # ----- 循环提取 (14.2) -----

    def _extract_while_condition(self, for_node: Any) -> Any:
        """Go for (while-like) 条件提取

        Go 的纯 for 有两种形式：
        - `for condition { ... }` → condition 是 for_node 的直接子节点（非 block）
        - `for ; condition; { ... }` → 有 for_clause，condition 字段
        """
        for child in for_node.children:
            if child.type == 'for_clause':
                if hasattr(child, 'child_by_field_name'):
                    cond = child.child_by_field_name('condition')
                    if cond is not None:
                        return cond
                # fallback: 第二个分号之间的节点
                semi_count = 0
                for sub in child.children:
                    if sub.type == ';':
                        semi_count += 1
                        continue
                    if semi_count == 1:
                        return sub
        # `for condition { }` — condition 是 for_node 直接子节点
        for child in for_node.children:
            if child.type not in ['for', 'block', 'for_clause', 'range_clause',
                                   'for_range_clause', '{', '}']:
                return child
        return None

    def _extract_while_body(self, for_node: Any) -> Any:
        """Go for 循环体（block）"""
        for child in for_node.children:
            if child.type == 'block':
                return child
        return None

    def _extract_for_init(self, for_node: Any) -> Any:
        """Go for-range 无 C-style init"""
        return None

    def _extract_for_condition(self, for_node: Any) -> Any:
        """Go for-range 无显式 condition"""
        return None

    def _extract_for_update(self, for_node: Any) -> Any:
        """Go for-range 无 update"""
        return None

    def _extract_for_body(self, for_node: Any) -> Any:
        """Go for-range 循环体"""
        for child in for_node.children:
            if child.type == 'block':
                return child
        return None

    # ----- Switch 提取 (14.3) -----

    def _extract_switch_value(self, switch_node: Any) -> Any:
        """Go expression_switch_statement 条件提取（无括号）"""
        if hasattr(switch_node, 'child_by_field_name'):
            val = switch_node.child_by_field_name('value')
            if val is not None:
                return val
        for child in switch_node.children:
            if child.type not in ['switch', 'body', '{', '}',
                                   'expression_case_clause', 'default_case']:
                return child
        return None

    def _extract_switch_cases(self, switch_node: Any) -> List[tuple]:
        """Go expression_switch_statement → [(case_value_or_None, body_stmtlist), ...]"""
        cases = []
        for child in switch_node.children:
            if child.type == 'expression_case_clause':
                # expression_case_clause: (case <expr> | default) : <stmts...>
                case_val = None
                stmts: List[Any] = []
                after_colon = False
                for sub in child.children:
                    if sub.type in ['case', 'default']:
                        continue
                    if sub.type == ':':
                        after_colon = True
                        continue
                    if not after_colon:
                        if case_val is None:
                            try:
                                case_val = int(sub.text.decode('utf-8'))
                            except (ValueError, AttributeError):
                                case_val = sub.text.decode('utf-8') if hasattr(sub, 'text') else None
                    else:
                        stmts.append(sub)
                cases.append((case_val, _StmtList(stmts)))
        return cases

    # ----- Defer/Recover 建模为 try/finally (14.4) -----

    def _extract_try_body(self, defer_node: Any) -> Any:
        """Go defer 无 try 主体（defer 本身是 finally 模型，try 主体返回 None）"""
        return None

    def _extract_catch_handlers(self, defer_node: Any) -> List[Any]:
        """Go 无显式 catch（recover 简化为空列表）"""
        return []

    def _extract_finally_body(self, defer_node: Any) -> Any:
        """Go defer 调用体作为 finally 块"""
        for child in defer_node.children:
            if child.type == 'call_expression':
                return child
        return None


def create_ir_builder(language: str) -> IRBuilder:
    """工厂函数：创建语言特定的 IR 构建器

    支持语言：'c', 'python', 'java', 'go'
    """
    if language == 'c':
        return CIRBuilder()
    elif language == 'python':
        return PythonIRBuilder()
    elif language == 'java':
        return JavaIRBuilder()
    elif language == 'go':
        return GoIRBuilder()
    else:
        raise ValueError(f"Unsupported language: {language}")


def build_ssa(code: str, language: str, target_function: Optional[str] = None) -> Optional[Any]:
    """
    构建 SSA/IR 的便捷函数（简化实现，专注变量追踪）
    
    Args:
        code: 源代码
        language: 语言类型 ('c', 'python', 'go', 'java')
        target_function: 目标函数名（可选，如果指定则只构建该函数）
    
    Returns:
        SSAFunction 对象，如果失败则返回 None
    
    注意：
        当前为简化实现：从 AST features 构建最小化 SSA
        只关注 ASSIGN 指令（常量传播）
    """
    try:
        from ..abstract_syntax_tree import extract_features, parse_code
        from ..abstract_syntax_tree.navigator import iter_functions
        from .schema import SSAFunction, SSABlock, SSAInstruction, SSAValue, InstructionType
        from ..analysis.candidate import Location
        
        # 1. 解析代码为 AST
        root = parse_code(code, language)
        if not root:
            return None
        
        # 2. 提取特征
        features = extract_features(code, language)
        functions = features.get('functions', [])
        var_assignments = features.get('var_assignments', {})
        
        if not functions:
            return None
        
        # 3. 找到目标函数
        target_func_info = None
        if target_function:
            for func in functions:
                if func.get('name') == target_function:
                    target_func_info = func
                    break
        else:
            # 默认使用第一个函数
            target_func_info = functions[0] if functions else None
        
        if not target_func_info:
            return None
        
        # 4. 构建 SSA 函数
        func_name = target_func_info.get('name', 'unknown')
        ssa_func = SSAFunction(name=func_name)
        
        # 5. 创建入口块
        entry_block = ssa_func.add_block(f"{func_name}_entry")
        
        # 6. 提取函数范围内的变量赋值
        func_start = target_func_info.get('start_line', 0)
        func_end = target_func_info.get('end_line', 999999)
        
        # 为每个变量赋值创建 SSA 指令
        if isinstance(var_assignments, dict):
            for var_name, value in var_assignments.items():
                # 创建 SSA 值
                result_value = SSAValue(name=f"{var_name}0")
                
                # 创建常量操作数
                if isinstance(value, int):
                    operand = SSAValue(name=str(value), is_constant=True, constant_value=value)
                elif isinstance(value, str):
                    operand = SSAValue(name=f'"{value}"', is_constant=True, constant_value=value)
                else:
                    # 非常量值，跳过
                    continue
                
                # 创建 ASSIGN 指令
                inst = SSAInstruction(
                    type=InstructionType.ASSIGN,
                    result=result_value,
                    operands=[operand],
                    location=Location(file="", line=0)  # 简化：不追踪精确位置
                )
                
                entry_block.add_instruction(inst)
                
                # 更新符号表
                ssa_func.symbol_table[var_name] = result_value
        
        elif isinstance(var_assignments, list):
            # 处理列表格式：[{"name": ..., "value": ..., "line": ...}]
            for assignment in var_assignments:
                if not isinstance(assignment, dict):
                    continue
                
                var_name = assignment.get('name')
                value = assignment.get('value')
                line = assignment.get('line', 0)
                
                # 只处理目标函数范围内的赋值
                if not (func_start <= line <= func_end):
                    continue
                
                if not var_name:
                    continue
                
                # 创建 SSA 值
                result_value = SSAValue(name=f"{var_name}0")
                
                # 创建常量操作数
                if isinstance(value, int):
                    operand = SSAValue(name=str(value), is_constant=True, constant_value=value)
                elif isinstance(value, str):
                    operand = SSAValue(name=f'"{value}"', is_constant=True, constant_value=value)
                else:
                    continue
                
                # 创建 ASSIGN 指令
                inst = SSAInstruction(
                    type=InstructionType.ASSIGN,
                    result=result_value,
                    operands=[operand],
                    location=Location(file="", line=line)
                )
                
                entry_block.add_instruction(inst)
                ssa_func.symbol_table[var_name] = result_value
        
        return ssa_func
        
    except Exception as e:
        # 构建失败，静默返回 None
        # print(f"[DEBUG] build_ssa failed: {e}")
        return None

