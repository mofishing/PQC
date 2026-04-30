from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from pqscan.analysis.param_eval import ParameterBindingExtractor, ParamBinding, eval_expr
from pqscan.symbolic.object_state_tracker import ObjectStateTracker, ObjectState

from pqscan.analysis.wrapper_summary import (
    CallersIndex, CallSite, Contract, Effect
)

class NodeStatus(Enum):
    """传播节点状态"""
    SENSITIVE = "sensitive"      # 敏感点（敏感 API）
    PROPAGATED = "propagated"    # 已传播（封装函数）
    PRUNED = "pruned"            # 剪枝（SAT）
    SUSPECT = "suspect"          # 可疑（UNKNOWN）
    ENTRY = "entry"              # 入口点（无调用者）


@dataclass
class PropagationNode:
    """传播节点（callsite 级别）"""
    callsite_id: str                  # callsite 唯一标识（function@line）
    function: str                     # 函数名
    line: int                         # 行号
    file: Optional[str] = None        # 文件路径
    status: NodeStatus = NodeStatus.PROPAGATED
    
    # 参数信息
    args_repr: List[str] = field(default_factory=list)
    param_values: Dict[str, Any] = field(default_factory=dict)
    
    # 对象状态信息
    object_states: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # {obj_id: {field: value}}
    
    # 约束信息
    contract: Optional[Contract] = None
    sat_result: Optional[bool] = None  # True=SAT, False=UNSAT, None=UNKNOWN
    
    # 传播信息
    depth: int = 0                    # 从敏感点的深度
    caller_node: Optional[str] = None # 调用者节点 ID
    
    def __hash__(self):
        return hash(self.callsite_id)
    
    def __eq__(self, other):
        if isinstance(other, PropagationNode):
            return self.callsite_id == other.callsite_id
        return False


@dataclass
class PropagationEdge:
    """传播边（调用关系）"""
    from_node: str                    # 调用者节点 ID
    to_node: str                      # 被调函数节点 ID
    param_binding: Dict[str, str] = field(default_factory=dict)  # 参数绑定
    state_transfer: Dict[str, str] = field(default_factory=dict)  # 对象状态传递 {caller_obj: callee_obj}
    
    def __hash__(self):
        return hash((self.from_node, self.to_node))
    
    def __eq__(self, other):
        if isinstance(other, PropagationEdge):
            return self.from_node == other.from_node and self.to_node == other.to_node
        return False


class PropagationGraph:
    """
    传播子图
    
    记录从敏感点向上的传播路径和状态
    """
    
    def __init__(self, sink_function: str, verbose: bool = False):
        """
        初始化传播图
        
        Args:
            sink_function: 敏感点函数名
            verbose: 是否输出详细信息
        """
        self.sink_function = sink_function
        self.verbose = verbose
        
        # 图结构
        self.nodes: Dict[str, PropagationNode] = {}  # {callsite_id: node}
        self.edges: Set[PropagationEdge] = set()
        
        # 索引
        self.sensitive_nodes: List[str] = []         # 敏感点节点
        self.pruned_nodes: List[str] = []            # 剪枝节点（SAT）
        self.suspect_nodes: List[str] = []           # 可疑节点（UNKNOWN）
        self.entry_nodes: List[str] = []             # 入口节点（无调用者）
        
        # 传播路径
        self.paths: List[List[str]] = []             # 所有传播路径
    
    def add_node(self, node: PropagationNode) -> None:
        """添加节点"""
        self.nodes[node.callsite_id] = node
        
        # 更新索引
        if node.status == NodeStatus.SENSITIVE:
            self.sensitive_nodes.append(node.callsite_id)
        elif node.status == NodeStatus.PRUNED:
            self.pruned_nodes.append(node.callsite_id)
        elif node.status == NodeStatus.SUSPECT:
            self.suspect_nodes.append(node.callsite_id)
        elif node.status == NodeStatus.ENTRY:
            self.entry_nodes.append(node.callsite_id)
    
    def add_edge(self, edge: PropagationEdge) -> None:
        """添加边"""
        self.edges.add(edge)
    
    def get_node(self, callsite_id: str) -> Optional[PropagationNode]:
        """获取节点"""
        return self.nodes.get(callsite_id)
    
    def get_callers(self, callsite_id: str) -> List[PropagationNode]:
        """获取调用者节点"""
        callers = []
        for edge in self.edges:
            if edge.to_node == callsite_id:
                caller_node = self.nodes.get(edge.from_node)
                if caller_node:
                    callers.append(caller_node)
        return callers
    
    def get_callees(self, callsite_id: str) -> List[PropagationNode]:
        """获取被调节点"""
        callees = []
        for edge in self.edges:
            if edge.from_node == callsite_id:
                callee_node = self.nodes.get(edge.to_node)
                if callee_node:
                    callees.append(callee_node)
        return callees
    
    def find_all_paths(self, from_node: str, to_node: str) -> List[List[str]]:
        """查找两个节点之间的所有路径（DFS）"""
        paths = []
        visited = set()
        
        def dfs(current: str, target: str, path: List[str]):
            if current == target:
                paths.append(path.copy())
                return
            
            visited.add(current)
            for callee in self.get_callees(current):
                if callee.callsite_id not in visited:
                    path.append(callee.callsite_id)
                    dfs(callee.callsite_id, target, path)
                    path.pop()
            visited.remove(current)
        
        dfs(from_node, to_node, [from_node])
        return paths
    
    def get_affected_functions(self) -> Set[str]:
        """获取所有受影响的函数（去重）"""
        return {node.function for node in self.nodes.values()}
    
    def get_reachable_callsites(self, from_node: str) -> Set[str]:
        """获取从指定节点可达的所有 callsite（BFS）"""
        reachable = set()
        queue = [from_node]
        visited = {from_node}
        
        while queue:
            current = queue.pop(0)
            reachable.add(current)
            
            for callee in self.get_callees(current):
                if callee.callsite_id not in visited:
                    visited.add(callee.callsite_id)
                    queue.append(callee.callsite_id)
        
        return reachable
    
    def to_dict(self) -> Dict[str, Any]:
        """导出为字典（用于序列化）"""
        return {
            "sink_function": self.sink_function,
            "nodes": [
                {
                    "id": node.callsite_id,
                    "function": node.function,
                    "line": node.line,
                    "file": node.file,
                    "status": node.status.value,
                    "depth": node.depth,
                    "sat_result": node.sat_result
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "from": edge.from_node,
                    "to": edge.to_node,
                    "param_binding": edge.param_binding
                }
                for edge in self.edges
            ],
            "statistics": {
                "total_nodes": len(self.nodes),
                "sensitive_nodes": len(self.sensitive_nodes),
                "pruned_nodes": len(self.pruned_nodes),
                "suspect_nodes": len(self.suspect_nodes),
                "entry_nodes": len(self.entry_nodes),
                "affected_functions": len(self.get_affected_functions())
            }
        }
    
    def print_summary(self) -> None:
        """打印摘要"""
        print(f"\n传播子图摘要（敏感点: {self.sink_function}）")
        print(f"{'=' * 70}")
        print(f"节点总数: {len(self.nodes)}")
        print(f"  - 敏感点: {len(self.sensitive_nodes)}")
        print(f"  - 剪枝节点: {len(self.pruned_nodes)}")
        print(f"  - 可疑节点: {len(self.suspect_nodes)}")
        print(f"  - 入口节点: {len(self.entry_nodes)}")
        print(f"边数: {len(self.edges)}")
        print(f"受影响函数: {len(self.get_affected_functions())}")


class PropagationGraphBuilder:
    """
    传播子图构建器
    
    从敏感点向上构建传播子图
    """
    
    def __init__(
        self,
        callers_index: CallersIndex,
        verbose: bool = False,
        max_depth: int = 10
    ):
        """
        初始化构建器
        
        Args:
            callers_index: 反向调用索引
            verbose: 是否输出详细信息
            max_depth: 最大传播深度
        """
        self.callers_index = callers_index
        self.verbose = verbose
        self.max_depth = max_depth
        self.param_extractor = ParameterBindingExtractor(verbose=verbose)
        self.state_tracker = ObjectStateTracker()  # 对象状态追踪器
    
    def build_from_sink(
        self,
        sink_function: str,
        sink_callsite: Optional[CallSite] = None,
        effect: Optional[Effect] = None,
        contract: Optional[Contract] = None
    ) -> PropagationGraph:
        """
        从敏感点构建传播子图
        
        Args:
            sink_function: 敏感点函数名
            sink_callsite: 敏感点调用位置（可选）
            effect: 关键输入归因结果（可选）
            contract: 派生的约束（可选）
        
        Returns:
            PropagationGraph: 传播子图
        """
        graph = PropagationGraph(sink_function, verbose=self.verbose)
        
        # 创建敏感点节点
        if sink_callsite:
            sink_node_id = f"{sink_function}@{sink_callsite.line}"
            sink_node = PropagationNode(
                callsite_id=sink_node_id,
                function=sink_function,
                line=sink_callsite.line,
                file=sink_callsite.file,
                status=NodeStatus.SENSITIVE,
                contract=contract,
                depth=0
            )
        else:
            # 如果没有 callsite，使用虚拟节点
            sink_node_id = f"{sink_function}@0"
            sink_node = PropagationNode(
                callsite_id=sink_node_id,
                function=sink_function,
                line=0,
                status=NodeStatus.SENSITIVE,
                contract=contract,
                depth=0
            )
        
        graph.add_node(sink_node)
        
        if self.verbose:
            print(f"\n[传播子图] 从敏感点开始: {sink_function}")
        
        # 向上构建
        self._build_upward(
            graph=graph,
            current_node_id=sink_node_id,
            current_contract=contract,
            depth=0,
            visited=set()
        )
        
        return graph
    
    def _build_upward(
        self,
        graph: PropagationGraph,
        current_node_id: str,
        current_contract: Optional[Contract],
        depth: int,
        visited: Set[str]
    ) -> None:
        """
        向上构建传播子图（递归）
        
        Args:
            graph: 传播图（修改）
            current_node_id: 当前节点 ID
            current_contract: 当前约束
            depth: 当前深度
            visited: 已访问的函数（避免循环）
        """
        # 深度限制
        if depth >= self.max_depth:
            if self.verbose:
                print(f"  [深度限制] 停止传播 {current_node_id} (depth={depth})")
            return
        
        current_node = graph.get_node(current_node_id)
        if not current_node:
            return
        
        current_function = current_node.function
        
        # 查找调用者
        callsites = self.callers_index.get_callers(current_function)
        if not callsites:
            # 入口节点
            current_node.status = NodeStatus.ENTRY
            graph.entry_nodes.append(current_node_id)
            if self.verbose:
                print(f"  [入口节点] {current_function}")
            return
        
        for callsite in callsites:
            caller = callsite.caller_fqname
            
            # 避免循环
            if caller in visited:
                continue
            
            # 创建调用者节点
            caller_node_id = f"{caller}@{callsite.line}"
            
            # 检查是否已存在
            if caller_node_id in graph.nodes:
                continue
            
            if self.verbose:
                print(f"  [向上] {current_function} <- {caller} @{callsite.line}")
            
            # 提取对象状态（用于 SAT 判定）
            object_states = self._extract_object_states(callsite)
            
            # SAT/UNSAT 判定（传递对象状态）
            sat_result = self._check_callsite_sat(
                callsite, 
                current_contract,
                object_states=object_states
            )
            
            # 创建节点
            if sat_result is True:
                # SAT: 剪枝节点
                status = NodeStatus.PRUNED
                if self.verbose:
                    print(f"    ✓ SAT - 剪枝")
            elif sat_result is False:
                # UNSAT: 传播节点
                status = NodeStatus.PROPAGATED
                if self.verbose:
                    print(f"    ✗ UNSAT - 继续传播")
            else:
                # UNKNOWN: 可疑节点
                status = NodeStatus.SUSPECT
                if self.verbose:
                    print(f"    ? UNKNOWN - suspect")
            
            caller_node = PropagationNode(
                callsite_id=caller_node_id,
                function=caller,
                line=callsite.line,
                file=callsite.file,
                status=status,
                args_repr=callsite.args_repr,
                object_states=object_states,  # 记录对象状态
                contract=current_contract,  # 临时使用相同约束
                sat_result=sat_result,
                depth=depth + 1,
                caller_node=current_node_id
            )
            
            graph.add_node(caller_node)
            
            # 提取参数绑定
            param_binding = self._extract_param_binding(
                callsite=callsite,
                callee_node=graph.nodes[current_node_id]
            )
            
            # 添加边
            edge = PropagationEdge(
                from_node=caller_node_id,
                to_node=current_node_id,
                param_binding=param_binding
            )
            graph.add_edge(edge)
            
            # 如果不是剪枝节点，继续向上
            if status != NodeStatus.PRUNED:
                visited_copy = visited.copy()
                visited_copy.add(caller)
                self._build_upward(
                    graph=graph,
                    current_node_id=caller_node_id,
                    current_contract=current_contract,
                    depth=depth + 1,
                    visited=visited_copy
                )
    
    def _check_callsite_sat(
        self,
        callsite: CallSite,
        contract: Optional[Contract],
        object_states: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Optional[bool]:
        """
        检查 callsite 是否满足约束
        
        Args:
            callsite: 调用点
            contract: 约束
            object_states: 对象状态 {obj_id: {field: value}}
        
        Returns:
            True: SAT（满足）
            False: UNSAT（不满足）
            None: UNKNOWN（不确定）
        """
        if not contract:
            return None
        
        # 提取参数值
        param_values = self._extract_param_values(callsite)
        
        # 使用传入的对象状态
        state_values = object_states or {}
        
        # 判定（同时检查参数约束和状态约束）
        return contract.is_sat(param_values, state_values)
    
    def _extract_param_values(self, callsite: CallSite) -> Dict[str, Any]:
        """
        从 callsite 提取参数值（增强版，使用表达式求值器）
        
        Args:
            callsite: 调用点
        
        Returns:
            {param_name: value}
        """
        param_values = {}
        
        # 使用表达式求值器解析每个参数
        for i, arg_repr in enumerate(callsite.args_repr):
            param_name = f'param_{i}'
            
            # 尝试求值表达式
            value = eval_expr(arg_repr, variables={})
            
            if value is not None:
                param_values[param_name] = value
        
        return param_values
    
    def _extract_param_binding(
        self,
        callsite: CallSite,
        callee_node: PropagationNode
    ) -> Dict[str, ParamBinding]:
        """
        从 callsite 提取参数绑定
        
        Args:
            callsite: 调用点
            callee_node: 被调节点
        
        Returns:
            {callee_param_name: ParamBinding}
        """
        if not callsite.args_repr:
            return {}
        
        # 尝试获取被调函数的参数名
        # 如果没有，使用默认参数名 param_0, param_1, ...
        callee_params = None
        if callee_node.contract and hasattr(callee_node.contract, 'param_names'):
            callee_params = callee_node.contract.param_names
        
        # 提取参数绑定
        try:
            bindings = self.param_extractor.extract_from_callsite(
                args_repr=callsite.args_repr,
                callee_params=callee_params
            )
            return bindings
        except Exception as e:
            if self.verbose:
                print(f"⚠️  参数绑定提取失败: {e}")
            return {}
    
    def _extract_object_states(
        self,
        callsite: CallSite
    ) -> Dict[str, Dict[str, Any]]:
        """
        从 callsite 提取对象状态
        
        Args:
            callsite: 调用点
        
        Returns:
            {obj_id: {field: value}}
        """
        # 简单实现：从 callsite.receiver 或参数中提取对象
        # 更完整的实现需要结合 AST 分析
        
        object_states = {}
        
        # 如果有 receiver（OO 语言），获取其状态
        if hasattr(callsite, 'receiver') and callsite.receiver:
            receiver_id = callsite.receiver
            if receiver_id in self.state_tracker.objects:
                object_states[receiver_id] = self.state_tracker.get_object_state(receiver_id) or {}
        
        # TODO: 从参数中识别对象（如 ctx 参数）
        # 这需要更复杂的分析，暂时简化处理
        
        return object_states


# ============================================================================
# 便利函数
# ============================================================================

def build_propagation_graph(
    sink_function: str,
    callers_index: CallersIndex,
    sink_callsite: Optional[CallSite] = None,
    effect: Optional[Effect] = None,
    contract: Optional[Contract] = None,
    verbose: bool = False,
    max_depth: int = 10
) -> PropagationGraph:
    """
    便利函数：构建传播子图
    
    Args:
        sink_function: 敏感点函数名
        callers_index: 反向调用索引
        sink_callsite: 敏感点调用位置（可选）
        effect: 关键输入归因结果（可选）
        contract: 派生的约束（可选）
        verbose: 是否输出详细信息
        max_depth: 最大传播深度
    
    Returns:
        PropagationGraph: 传播子图
    """
    builder = PropagationGraphBuilder(callers_index, verbose, max_depth)
    return builder.build_from_sink(sink_function, sink_callsite, effect, contract)
