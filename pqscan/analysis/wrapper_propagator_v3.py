#!/usr/bin/env python3
"""
封装传播器 v3 - 完整版

基于 PropagationGraph 的完整实现，支持：
1. 参数绑定提取和约束派生
2. 状态约束传播
3. 多层封装支持
4. 约束累积和简化
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

from pqscan.analysis.wrapper_summary import (
    CallersIndex, CallSite, Contract, Summary, Effect,
    ParamConstraint, StateConstraint, Predicate
)
from pqscan.analysis.propagation_graph import (
    PropagationGraph, PropagationGraphBuilder, PropagationNode, NodeStatus
)
from pqscan.analysis.param_eval import ParameterBindingExtractor, ParamBinding


@dataclass
class WrapperSummary:
    """封装函数摘要"""
    function: str
    effects: List[Effect] = field(default_factory=list)
    contract: Optional[Contract] = None
    param_bindings: Dict[str, ParamBinding] = field(default_factory=dict)
    confidence: str = "confirmed"


@dataclass
class PropagationResult:
    """传播结果"""
    wrapped_functions: Dict[str, WrapperSummary] = field(default_factory=dict)
    pruned_callsites: List[CallSite] = field(default_factory=list)
    suspect_callsites: List[CallSite] = field(default_factory=list)
    propagation_graph: Optional[PropagationGraph] = None
    entry_functions: List[str] = field(default_factory=list)


class WrapperPropagatorV3:
    """
    封装传播器 v3
    
    完全基于 PropagationGraph 实现，支持约束派生
    """
    
    def __init__(
        self,
        callers_index: CallersIndex,
        verbose: bool = False,
        max_depth: int = 10
    ):
        """
        初始化传播器
        
        Args:
            callers_index: 反向调用索引
            verbose: 是否输出详细信息
            max_depth: 最大传播深度
        """
        self.callers_index = callers_index
        self.verbose = verbose
        self.max_depth = max_depth
        self.param_extractor = ParameterBindingExtractor(verbose=verbose)
    
    def propagate_from_sink(
        self,
        sink_function: str,
        effect: Effect,
        contract: Contract,
        sink_callsite: Optional[CallSite] = None
    ) -> PropagationResult:
        """
        从敏感点开始传播约束
        
        Args:
            sink_function: 敏感点函数名
            effect: 关键输入归因结果
            contract: 派生的约束
            sink_callsite: 敏感点调用位置（可选）
        
        Returns:
            PropagationResult: 传播结果
        """
        result = PropagationResult()
        
        # 构建传播子图
        graph_builder = PropagationGraphBuilder(
            self.callers_index,
            verbose=self.verbose,
            max_depth=self.max_depth
        )
        
        graph = graph_builder.build_from_sink(
            sink_function=sink_function,
            sink_callsite=sink_callsite,
            effect=effect,
            contract=contract
        )
        
        result.propagation_graph = graph
        
        # 从图中提取封装函数摘要
        self._extract_wrappers_from_graph(graph, contract, result)
        
        # 提取剪枝和可疑 callsite
        self._extract_pruned_and_suspect(graph, result)
        
        # 提取入口函数
        result.entry_functions = [
            graph.nodes[node_id].function 
            for node_id in graph.entry_nodes
        ]
        
        return result
    
    def _extract_wrappers_from_graph(
        self,
        graph: PropagationGraph,
        contract: Contract,
        result: PropagationResult
    ):
        """
        从传播图提取封装函数摘要
        
        Args:
            graph: 传播图
            contract: 原始约束
            result: 传播结果（修改）
        """
        # 遍历所有非敏感点节点
        for node_id, node in graph.nodes.items():
            if node.status == NodeStatus.SENSITIVE:
                continue
            
            # 为每个节点派生约束
            derived_contract = self._derive_contract_for_node(node, graph, contract)
            
            # 创建摘要
            summary = WrapperSummary(
                function=node.function,
                contract=derived_contract,
                confidence="confirmed" if node.status == NodeStatus.PRUNED else "probable"
            )
            
            result.wrapped_functions[node.function] = summary
    
    def _derive_contract_for_node(
        self,
        node: PropagationNode,
        graph: PropagationGraph,
        original_contract: Contract
    ) -> Optional[Contract]:
        """
        为节点派生约束
        
        Args:
            node: 传播节点
            graph: 传播图
            original_contract: 原始约束
        
        Returns:
            派生的约束
        """
        if not original_contract:
            return None
        
        # 获取从该节点到敏感点的路径
        paths = self._find_path_to_sink(node.callsite_id, graph)
        if not paths:
            return None
        
        # 使用第一条路径进行约束派生
        path = paths[0]
        
        # 沿路径累积参数变换
        derived_constraints = []
        
        for param_constraint in original_contract.param_constraints:
            derived = self._derive_param_constraint_along_path(
                param_constraint,
                path,
                graph
            )
            if derived:
                derived_constraints.append(derived)
        
        # 状态约束直接传递（简化处理）
        state_constraints = original_contract.state_constraints.copy()
        
        if derived_constraints or state_constraints:
            return Contract(
                param_constraints=derived_constraints,
                state_constraints=state_constraints
            )
        
        return None
    
    def _find_path_to_sink(
        self,
        from_node: str,
        graph: PropagationGraph
    ) -> List[List[str]]:
        """
        查找从节点到敏感点的路径
        
        Args:
            from_node: 起始节点
            graph: 传播图
        
        Returns:
            路径列表
        """
        paths = []
        
        # 找到所有敏感点
        sink_nodes = [
            node_id for node_id in graph.sensitive_nodes
        ]
        
        if not sink_nodes:
            return []
        
        # 查找到第一个敏感点的路径
        # 注意：传播图是反向的（从敏感点向上），所以我们需要反向查找
        sink_node = sink_nodes[0]
        
        # DFS 查找路径
        visited = set()
        path = []
        
        def dfs(current: str, target: str):
            if current == target:
                paths.append(path.copy())
                return True
            
            visited.add(current)
            
            # 查找被调函数（向下走）
            callees = graph.get_callees(current)
            for callee in callees:
                if callee.callsite_id not in visited:
                    path.append(callee.callsite_id)
                    if dfs(callee.callsite_id, target):
                        return True
                    path.pop()
            
            return False
        
        path.append(from_node)
        dfs(from_node, sink_node)
        
        return paths
    
    def _derive_param_constraint_along_path(
        self,
        constraint: ParamConstraint,
        path: List[str],
        graph: PropagationGraph
    ) -> Optional[ParamConstraint]:
        """
        沿路径派生参数约束
        
        Args:
            constraint: 原始参数约束
            path: 传播路径
            graph: 传播图
        
        Returns:
            派生的约束
        """
        # 从路径的第一个节点开始
        if len(path) < 2:
            return constraint
        
        current_param = constraint.param
        current_value = constraint.value
        current_predicate = constraint.predicate
        
        # 沿路径反向传播约束
        for i in range(len(path) - 1):
            from_node_id = path[i]
            to_node_id = path[i + 1]
            
            # 查找边
            edge = None
            for e in graph.edges:
                if e.from_node == from_node_id and e.to_node == to_node_id:
                    edge = e
                    break
            
            if not edge or not edge.param_binding:
                continue
            
            # 查找参数绑定
            if current_param not in edge.param_binding:
                # 尝试通过索引查找
                param_idx = current_param.replace("param_", "")
                if param_idx.isdigit():
                    param_key = f"param_{param_idx}"
                    if param_key in edge.param_binding:
                        binding = edge.param_binding[param_key]
                    else:
                        continue
                else:
                    continue
            else:
                binding = edge.param_binding[current_param]
            
            # 应用反向变换
            if binding.is_constant:
                # 常量绑定，无法反向传播
                return None
            
            if not binding.transform:
                # 直接传递
                current_param = binding.source_param
            else:
                # 有变换，需要反向应用
                new_value = self._reverse_transform(
                    current_value,
                    binding.transform,
                    current_predicate
                )
                
                if new_value is None:
                    return None
                
                current_value = new_value
                current_param = binding.source_param
        
        # 返回派生的约束
        return ParamConstraint(
            param=current_param,
            predicate=current_predicate,
            value=current_value,
            confidence=constraint.confidence
        )
    
    def _reverse_transform(
        self,
        value: Any,
        transform: str,
        predicate: Predicate
    ) -> Optional[Any]:
        """
        反向应用变换
        
        Args:
            value: 原始值
            transform: 变换（如 "*8", "+10"）
            predicate: 谓词
        
        Returns:
            反向变换后的值
        """
        if not isinstance(value, (int, float)):
            return None
        
        # 解析变换
        if transform.startswith("*"):
            factor = int(transform[1:])
            # value >= x * factor  =>  x >= value / factor
            if predicate == Predicate.GEQ:
                # 向上取整
                return (value + factor - 1) // factor
            elif predicate == Predicate.LEQ:
                return value // factor
            else:
                return value // factor
        
        elif transform.startswith("+"):
            offset = int(transform[1:])
            # value >= x + offset  =>  x >= value - offset
            return value - offset
        
        elif transform.startswith("-"):
            offset = int(transform[1:])
            # value >= x - offset  =>  x >= value + offset
            return value + offset
        
        elif transform.startswith("/"):
            divisor = int(transform[1:])
            # value >= x / divisor  =>  x >= value * divisor
            return value * divisor
        
        # 复杂变换（如 "*8+10"）
        if "+" in transform or "-" in transform:
            # 简化处理：只考虑最外层运算
            # 更完整的实现需要解析整个表达式
            return None
        
        return None
    
    def _extract_pruned_and_suspect(
        self,
        graph: PropagationGraph,
        result: PropagationResult
    ):
        """
        提取剪枝和可疑 callsite
        
        Args:
            graph: 传播图
            result: 传播结果（修改）
        """
        # 提取剪枝节点
        for node_id in graph.pruned_nodes:
            node = graph.nodes[node_id]
            callsite = self._node_to_callsite(node, graph)
            if callsite:
                result.pruned_callsites.append(callsite)
        
        # 提取可疑节点
        for node_id in graph.suspect_nodes:
            node = graph.nodes[node_id]
            callsite = self._node_to_callsite(node, graph)
            if callsite:
                result.suspect_callsites.append(callsite)
    
    def _node_to_callsite(
        self,
        node: PropagationNode,
        graph: PropagationGraph
    ) -> Optional[CallSite]:
        """
        将节点转换为 CallSite
        
        Args:
            node: 传播节点
            graph: 传播图
        
        Returns:
            CallSite 或 None
        """
        callees = graph.get_callees(node.callsite_id)
        if not callees:
            return None
        
        callee = callees[0]
        
        return CallSite(
            caller_fqname=node.function,
            callee_fqname=callee.function,
            args_repr=node.args_repr,
            line=node.line,
            file=node.file or ""
        )


# 便利函数
def propagate_wrapper_constraints(
    sink_function: str,
    effect: Effect,
    contract: Contract,
    callers_index: CallersIndex,
    verbose: bool = False,
    max_depth: int = 10
) -> PropagationResult:
    """
    便利函数：从敏感点传播约束
    
    Args:
        sink_function: 敏感点函数名
        effect: 关键输入归因
        contract: 派生的约束
        callers_index: 反向调用索引
        verbose: 是否输出详细信息
        max_depth: 最大传播深度
    
    Returns:
        PropagationResult
    """
    propagator = WrapperPropagatorV3(callers_index, verbose, max_depth)
    return propagator.propagate_from_sink(sink_function, effect, contract)
