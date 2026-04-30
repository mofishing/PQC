from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union, Tuple
from enum import Enum


class NodeType(Enum):
    """值图节点类型"""
    CONST = "const"              # 常量
    VAR_DEF = "var_def"          # 变量定义
    PHI = "phi"                  # Phi 节点（路径合并）
    CALL = "call"                # 函数调用
    FIELD_READ = "field_read"    # 字段读取
    FIELD_WRITE = "field_write"  # 字段写入
    INDEX_READ = "index_read"    # 数组/切片读取
    INDEX_WRITE = "index_write"  # 数组/切片写入
    BIN_OP = "bin_op"            # 二元运算
    COND_SELECT = "cond_select"  # 条件选择


@dataclass
class ValueNode:
    """
    值图节点（统一抽象）
    
    无论来自 Go SSA、Jimple、LLVM IR 还是 AST，
    最终都转换为这个统一表示
    """
    node_type: NodeType
    name: str                    # 节点名称（如变量名）
    location: Optional[Any] = None  # 源码位置
    
    # 不同节点类型的特定字段
    value: Any = None            # CONST: 常量值
    version: int = 0             # VAR_DEF: SSA 版本号
    rhs: Optional['ValueNode'] = None  # VAR_DEF: 右侧表达式
    
    operands: List['ValueNode'] = field(default_factory=list)  # PHI, BIN_OP 等
    
    # CALL 特定字段
    func_name: Optional[str] = None
    args: List['ValueNode'] = field(default_factory=list)
    ret_value: Optional['ValueNode'] = None
    
    # FIELD_READ/WRITE 特定字段
    obj: Optional['ValueNode'] = None
    field_name: Optional[str] = None
    
    # BIN_OP 特定字段
    operator: Optional[str] = None  # +, -, *, /, ==, <, etc.
    
    # COND_SELECT 特定字段
    condition: Optional['ValueNode'] = None
    true_value: Optional['ValueNode'] = None
    false_value: Optional['ValueNode'] = None
    
    # 元数据
    source_ir: str = "ast"       # 来源：go_ssa, jimple, llvm, ast
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.node_type, self.name, self.version))
    
    def __eq__(self, other):
        if not isinstance(other, ValueNode):
            return False
        return (self.node_type == other.node_type and 
                self.name == other.name and 
                self.version == other.version)


@dataclass
class ValueGraph:
    """
    值图（Partial SSA Def-Use Graph）
    
    特点：
    1. 不追求完整 SSA（无需 dominance frontier）
    2. 只记录关键的 def-use 关系
    3. 支持按需分析（lazy evaluation）
    4. 为后向切片和稀疏传播优化
    """
    nodes: List[ValueNode] = field(default_factory=list)
    
    # Def-use 映射
    def_map: Dict[str, List[ValueNode]] = field(default_factory=dict)  # var_name -> [def_nodes]
    use_map: Dict[ValueNode, List[ValueNode]] = field(default_factory=dict)  # node -> [users]
    
    # 调用图（用于过程间分析）
    call_graph: Dict[str, List[str]] = field(default_factory=dict)  # func_name -> [called_funcs]
    call_sites: List[ValueNode] = field(default_factory=list)  # 所有 CALL 节点
    
    # 别名分析缓存
    alias_sets: Dict[str, Set[str]] = field(default_factory=dict)  # var -> {aliases}
    
    # 入口节点（如函数参数、全局变量）
    entry_nodes: List[ValueNode] = field(default_factory=list)
    
    def add_node(self, node: ValueNode):
        """添加节点到图"""
        self.nodes.append(node)
        
        # 更新 def_map
        if node.node_type == NodeType.VAR_DEF:
            if node.name not in self.def_map:
                self.def_map[node.name] = []
            self.def_map[node.name].append(node)
        
        # 记录 CALL 节点
        if node.node_type == NodeType.CALL:
            self.call_sites.append(node)
            
            # 更新调用图
            if node.metadata.get('caller_func'):
                caller = node.metadata['caller_func']
                if caller not in self.call_graph:
                    self.call_graph[caller] = []
                if node.func_name:
                    self.call_graph[caller].append(node.func_name)
    
    def add_use(self, def_node: ValueNode, use_node: ValueNode):
        """记录 use 关系"""
        if def_node not in self.use_map:
            self.use_map[def_node] = []
        self.use_map[def_node].append(use_node)
    
    def add_alias(self, var1: str, var2: str):
        """
        记录别名关系（用于指针/引用分析）
        
        例如：p = &obj  -> add_alias('p', 'obj')
        """
        if var1 not in self.alias_sets:
            self.alias_sets[var1] = {var1}
        if var2 not in self.alias_sets:
            self.alias_sets[var2] = {var2}
        
        # 合并别名集合
        aliases = self.alias_sets[var1] | self.alias_sets[var2]
        for var in aliases:
            self.alias_sets[var] = aliases
    
    def get_aliases(self, var_name: str) -> Set[str]:
        """获取变量的所有别名"""
        return self.alias_sets.get(var_name, {var_name})
    
    def get_reaching_defs(self, var_name: str, at_line: Optional[int] = None) -> List[ValueNode]:
        """
        获取变量的到达定义（考虑别名）
        
        Args:
            var_name: 变量名
            at_line: 目标行号（如果为 None，返回所有定义）
        
        Returns:
            定义该变量的 ValueNode 列表
        """
        # 考虑所有别名
        all_names = self.get_aliases(var_name)
        defs = []
        
        for name in all_names:
            defs.extend(self.def_map.get(name, []))
        
        if at_line is None:
            return defs
        
        # 过滤出目标行之前的定义
        valid_defs = [
            d for d in defs
            if d.location and hasattr(d.location, 'line') and d.location.line <= at_line
        ]
        
        return valid_defs
    
    def backward_slice(
        self, 
        start_node: ValueNode, 
        max_depth: int = 10,
        include_calls: bool = True
    ) -> Set[ValueNode]:
        """
        后向切片：从起始节点回溯所有依赖
        
        这是核心分析方法：
        1. 从切片准则（如 RSA_generate_key 的 bits 参数）开始
        2. 后向遍历 def-use 链
        3. 可选地跟踪跨过程调用
        
        Args:
            start_node: 切片准则（如 call 的某个参数）
            max_depth: 最大回溯深度
            include_calls: 是否跟踪过程间依赖
        
        Returns:
            影响 start_node 的所有节点集合（切片子图）
        """
        slice_nodes = set()
        worklist = [(start_node, 0)]
        visited = set()
        
        while worklist:
            node, depth = worklist.pop(0)
            
            if node in visited or depth > max_depth:
                continue
            
            visited.add(node)
            slice_nodes.add(node)
            
            # 添加该节点的所有操作数（直接依赖）
            if node.rhs:
                worklist.append((node.rhs, depth + 1))
            
            for operand in node.operands:
                worklist.append((operand, depth + 1))
            
            if node.obj:
                worklist.append((node.obj, depth + 1))
            
            for arg in node.args:
                worklist.append((arg, depth + 1))
            
            # 如果是变量引用，查找其定义
            if node.node_type == NodeType.VAR_DEF:
                # 考虑别名
                for alias in self.get_aliases(node.name):
                    reaching_defs = self.def_map.get(alias, [])
                    for def_node in reaching_defs:
                        if def_node != node:  # 避免自环
                            worklist.append((def_node, depth + 1))
            
            # 过程间分析：如果是 CALL 且 include_calls=True
            if include_calls and node.node_type == NodeType.CALL:
                # TODO: 跟踪到被调用函数的参数定义
                # 这里需要 CHA（Class Hierarchy Analysis）或调用图
                pass
        
        return slice_nodes
    
    def forward_slice_for_aliases(
        self, 
        start_vars: Set[str], 
        max_depth: int = 5
    ) -> Dict[str, Set[str]]:
        """
        局部前向切片：扫描指针/别名赋值
        
        场景：
        - p = &obj
        - q = p
        - *p = value
        
        Args:
            start_vars: 起始变量集合
            max_depth: 最大前向深度
        
        Returns:
            别名映射 {var: {aliases}}
        """
        aliases = {var: {var} for var in start_vars}
        worklist = [(var, 0) for var in start_vars]
        visited = set()
        
        while worklist:
            var, depth = worklist.pop(0)
            
            if var in visited or depth > max_depth:
                continue
            
            visited.add(var)
            
            # 扫描所有节点，查找涉及 var 的赋值
            for node in self.nodes:
                if node.node_type == NodeType.VAR_DEF:
                    # 检查是否是别名赋值（p = q）
                    if node.rhs and node.rhs.name in aliases.get(var, set()):
                        # node.name 是 var 的别名
                        if var not in aliases:
                            aliases[var] = set()
                        aliases[var].add(node.name)
                        
                        # 继续前向传播
                        worklist.append((node.name, depth + 1))
        
        return aliases
    
    def build_call_graph_cha(self, functions: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        构建调用图（使用 CHA - Class Hierarchy Analysis）
        
        简化版：基于函数名匹配，不考虑虚函数
        
        Args:
            functions: {func_name: func_info} 映射
        
        Returns:
            调用图 {caller: [callees]}
        """
        # 已在 add_node 时构建，这里只需返回
        return self.call_graph
    
    def inter_procedural_trace(
        self, 
        call_node: ValueNode, 
        arg_index: int
    ) -> Optional[ValueNode]:
        """
        过程间追踪：从调用点追踪参数到被调用函数
        
        例如：
        caller: foo(2048)
        callee: bar(bits) { RSA_generate_key(..., bits, ...) }
        
        追踪 foo 的参数 2048 → bar 的参数 bits
        
        Args:
            call_node: CALL 节点
            arg_index: 参数索引
        
        Returns:
            被调用函数中对应的参数节点
        """
        if call_node.node_type != NodeType.CALL:
            return None
        
        if arg_index >= len(call_node.args):
            return None
        
        # TODO: 实现过程间映射
        # 需要：
        # 1. 找到被调用函数的 IR
        # 2. 找到对应位置的参数节点
        # 3. 返回该节点
        
        return None
    
    def evaluate(self, node: ValueNode, context: Dict[str, Any] = None) -> Optional[Any]:
        """
        稀疏常量传播：只在切片子图上求值
        
        优化策略：
        1. 只求值必要的节点（通过 backward_slice 确定）
        2. 缓存求值结果
        3. 特殊处理密码学常见模式
        
        Args:
            node: 要求值的节点
            context: 上下文变量值
        
        Returns:
            常量值（如果能求值），否则 None
        """
        context = context or {}
        
        # 缓存检查
        if hasattr(node, '_eval_cache'):
            return node._eval_cache
        
        result = None
        
        if node.node_type == NodeType.CONST:
            result = node.value
        
        elif node.node_type == NodeType.VAR_DEF:
            # 尝试从 context 获取
            if node.name in context:
                result = context[node.name]
            # 尝试求值 rhs
            elif node.rhs:
                result = self.evaluate(node.rhs, context)
        
        elif node.node_type == NodeType.BIN_OP:
            left_val = self.evaluate(node.operands[0], context) if node.operands else None
            right_val = self.evaluate(node.operands[1], context) if len(node.operands) > 1 else None
            
            if left_val is not None and right_val is not None:
                # 简单求值
                if node.operator == '+':
                    result = left_val + right_val
                elif node.operator == '-':
                    result = left_val - right_val
                elif node.operator == '*':
                    result = left_val * right_val
                elif node.operator == '/':
                    result = left_val / right_val if right_val != 0 else None
        
        elif node.node_type == NodeType.PHI:
            # 如果所有分支都是同一个常量，返回该常量
            values = set()
            for operand in node.operands:
                val = self.evaluate(operand, context)
                if val is not None:
                    values.add(val)
            
            if len(values) == 1:
                result = values.pop()
        
        elif node.node_type == NodeType.CALL:
            # 特殊处理密码学 API 调用
            result = self._evaluate_crypto_call(node, context)
        
        # 缓存结果
        if result is not None:
            node._eval_cache = result
        
        return result
    
    def _evaluate_crypto_call(self, call_node: ValueNode, context: Dict[str, Any]) -> Optional[Any]:
        """
        特殊处理密码学 API 调用
        
        例如：
        - make([]byte, 16) → 16 (bytes) → 128 (bits)
        - b'0123456789abcdef' → 16 (bytes) → 128 (bits)
        - EVP_aes_256_gcm() → {"algorithm": "AES-256-GCM", "key_bits": 256}
        """
        func_name = call_node.func_name or ""
        
        # Go: make([]byte, N)
        if "make" in func_name and len(call_node.args) >= 2:
            # 第二个参数是长度
            size_node = call_node.args[1]
            size = self.evaluate(size_node, context)
            if isinstance(size, int):
                return {"bytes": size, "bits": size * 8}
        
        # EVP_aes_*_* 系列
        if "EVP_aes" in func_name:
            # 从函数名提取密钥长度
            if "128" in func_name:
                return {"algorithm": "AES", "key_bits": 128}
            elif "192" in func_name:
                return {"algorithm": "AES", "key_bits": 192}
            elif "256" in func_name:
                return {"algorithm": "AES", "key_bits": 256}
        
        # Python: AES.new(key, ...)
        if "AES.new" in func_name and call_node.args:
            key_node = call_node.args[0]
            key_val = self.evaluate(key_node, context)
            
            # 如果 key 是字节字符串，计算长度
            if isinstance(key_val, str):
                if key_val.startswith("b'") or key_val.startswith('b"'):
                    # 去掉 b' 和 '
                    key_str = key_val[2:-1]
                    key_bits = len(key_str) * 8
                    return {"algorithm": "AES", "key_bits": key_bits}
        
        return None
    
    def sparse_evaluate_slice(
        self, 
        slice_nodes: Set[ValueNode], 
        context: Dict[str, Any] = None
    ) -> Dict[ValueNode, Any]:
        """
        在切片子图上进行稀疏求值
        
        只对切片中的节点求值，避免分析整个程序
        
        Args:
            slice_nodes: 切片子图节点集合
            context: 初始上下文
        
        Returns:
            {node: evaluated_value} 映射
        """
        context = context or {}
        results = {}
        
        # 拓扑排序（简化版：按依赖顺序求值）
        sorted_nodes = self._topological_sort(slice_nodes)
        
        for node in sorted_nodes:
            val = self.evaluate(node, context)
            if val is not None:
                results[node] = val
                # 更新 context
                if node.node_type == NodeType.VAR_DEF:
                    context[node.name] = val
        
        return results
    
    def _topological_sort(self, nodes: Set[ValueNode]) -> List[ValueNode]:
        """
        拓扑排序节点（简化版）
        
        确保先求值依赖，再求值使用
        """
        # 简单策略：CONST 先，VAR_DEF 后
        const_nodes = [n for n in nodes if n.node_type == NodeType.CONST]
        var_nodes = [n for n in nodes if n.node_type == NodeType.VAR_DEF]
        other_nodes = [n for n in nodes if n not in const_nodes and n not in var_nodes]
        
        return const_nodes + var_nodes + other_nodes
    
    def __str__(self) -> str:
        lines = [f"ValueGraph ({len(self.nodes)} nodes):"]
        for node in self.nodes[:10]:  # 只显示前 10 个
            lines.append(f"  {node.node_type.value}: {node.name}")
        if len(self.nodes) > 10:
            lines.append(f"  ... ({len(self.nodes) - 10} more)")
        return '\n'.join(lines)


# ============================================================
# IR 转换器（从不同来源构建 ValueGraph）
# ============================================================

class ValueGraphBuilder:
    """从不同 IR 构建 ValueGraph 的基类"""
    
    def __init__(self):
        self.graph = ValueGraph()
    
    def build(self, source: Any, lang: str) -> ValueGraph:
        """
        构建 ValueGraph
        
        Args:
            source: IR 源（AST, Go SSA, Jimple 等）
            lang: 语言类型
        
        Returns:
            ValueGraph
        """
        raise NotImplementedError("Subclass must implement build()")


class ASTValueGraphBuilder(ValueGraphBuilder):
    """从 AST features 构建 ValueGraph（当前使用）"""
    
    def build(self, features: Dict, lang: str) -> ValueGraph:
        """
        从 AST features 构建 ValueGraph
        
        这是当前实现的桥接：scope-aware var_assignments → ValueGraph
        """
        var_assignments = features.get('var_assignments', [])
        
        if not isinstance(var_assignments, list):
            # 旧格式，暂不处理
            return self.graph
        
        # 为每个赋值创建 VarDef 节点
        for assignment in var_assignments:
            if not isinstance(assignment, dict):
                continue
            
            var_name = assignment.get('name', 'unknown')
            value = assignment.get('value')
            line = assignment.get('line', 0)
            func_name = assignment.get('function', '')
            
            # 创建右侧节点
            rhs_node = None
            if isinstance(value, (int, float)):
                # 常量
                rhs_node = ValueNode(
                    node_type=NodeType.CONST,
                    name=f"const_{value}",
                    value=value,
                    source_ir="ast"
                )
                self.graph.add_node(rhs_node)
            elif isinstance(value, str):
                # 可能是表达式或类型名
                # 简单处理：作为符号常量
                rhs_node = ValueNode(
                    node_type=NodeType.CONST,
                    name=f"symbol_{value}",
                    value=value,
                    source_ir="ast",
                    metadata={"original_expr": value}
                )
                self.graph.add_node(rhs_node)
            
            # 创建变量定义节点
            var_def = ValueNode(
                node_type=NodeType.VAR_DEF,
                name=var_name,
                version=0,  # AST 没有 SSA 版本，统一用 0
                rhs=rhs_node,
                location=type('Location', (), {'line': line, 'function': func_name})(),
                source_ir="ast"
            )
            
            self.graph.add_node(var_def)
        
        return self.graph


# TODO: 未来扩展的转换器
# class GoSSAValueGraphBuilder(ValueGraphBuilder):
#     """从 Go SSA 构建 ValueGraph"""
#     pass
# 
# class JimpleValueGraphBuilder(ValueGraphBuilder):
#     """从 Soot Jimple 构建 ValueGraph"""
#     pass
# 
# class LLVMValueGraphBuilder(ValueGraphBuilder):
#     """从 LLVM IR 构建 ValueGraph"""
#     pass
