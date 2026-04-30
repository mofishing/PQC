#!/usr/bin/env python3
"""
过程间分析增强（Interprocedural Analysis Enhancement）

为 ValueGraph 添加完整的过程间分析支持：
1. 参数传递追踪
2. 返回值传播
3. 调用上下文敏感分析
4. 跨函数值流分析
"""

from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field

from pqscan.symbolic.value_graph import (
    ValueGraph, ValueNode, NodeType
)


@dataclass
class CallContext:
    """调用上下文"""
    caller_func: str                   # 调用者函数
    callee_func: str                   # 被调用函数
    call_site: ValueNode               # 调用点节点
    arg_mapping: Dict[int, ValueNode]  # 参数映射：{arg_idx: arg_value}
    return_value: Optional[ValueNode] = None
    
    def __hash__(self):
        return hash((self.caller_func, self.callee_func, id(self.call_site)))
    
    def __eq__(self, other):
        if not isinstance(other, CallContext):
            return False
        return (self.caller_func == other.caller_func and
                self.callee_func == other.callee_func and
                self.call_site is other.call_site)


@dataclass
class FunctionSummary:
    """函数摘要"""
    func_name: str
    params: List[str]                  # 参数名列表
    return_vars: List[str]             # 返回值变量
    side_effects: Set[str]             # 副作用（修改的全局变量/字段）
    value_flows: List[Tuple[str, str]] # 值流：[(from_param, to_return)]


class InterproceduralAnalyzer:
    """过程间分析器"""
    
    def __init__(self, value_graph: ValueGraph):
        self.graph = value_graph
        self.func_summaries: Dict[str, FunctionSummary] = {}
        self.call_contexts: List[CallContext] = []
    
    def analyze(self):
        """运行完整的过程间分析"""
        # 1. 构建函数摘要
        self._build_function_summaries()
        
        # 2. 分析调用上下文
        self._analyze_call_contexts()
        
        # 3. 追踪参数传递
        self._track_parameter_passing()
        
        # 4. 追踪返回值
        self._track_return_values()
    
    def _build_function_summaries(self):
        """构建函数摘要"""
        # 从调用图推断函数列表
        all_funcs = set(self.graph.call_graph.keys())
        for called_funcs in self.graph.call_graph.values():
            all_funcs.update(called_funcs)
        
        for func_name in all_funcs:
            summary = self._compute_function_summary(func_name)
            if summary:
                self.func_summaries[func_name] = summary
    
    def _compute_function_summary(self, func_name: str) -> Optional[FunctionSummary]:
        """计算函数摘要"""
        # 查找函数的所有节点
        func_nodes = [
            n for n in self.graph.nodes
            if n.metadata.get('function') == func_name
        ]
        
        if not func_nodes:
            return None
        
        # 提取参数
        params = []
        for node in func_nodes:
            if node.node_type == NodeType.VAR_DEF and \
               node.metadata.get('is_param'):
                params.append(node.name)
        
        # 提取返回值变量
        return_vars = []
        for node in func_nodes:
            if node.metadata.get('is_return'):
                return_vars.append(node.name)
        
        # 分析值流（参数 -> 返回值）
        value_flows = self._analyze_value_flows(func_nodes, params, return_vars)
        
        # 检测副作用
        side_effects = self._detect_side_effects(func_nodes)
        
        return FunctionSummary(
            func_name=func_name,
            params=params,
            return_vars=return_vars,
            side_effects=side_effects,
            value_flows=value_flows
        )
    
    def _analyze_value_flows(
        self, 
        func_nodes: List[ValueNode], 
        params: List[str], 
        return_vars: List[str]
    ) -> List[Tuple[str, str]]:
        """分析函数内的值流"""
        flows = []
        
        # 对每个返回值，回溯到参数
        for ret_var in return_vars:
            # 查找返回值的定义
            ret_nodes = [
                n for n in func_nodes
                if n.node_type == NodeType.VAR_DEF and n.name == ret_var
            ]
            
            for ret_node in ret_nodes:
                # 后向切片找依赖的参数
                slice_nodes = self.graph.backward_slice(
                    ret_node, 
                    max_depth=10, 
                    include_calls=False
                )
                
                # 检查切片中的参数
                for param in params:
                    param_nodes = [
                        n for n in slice_nodes
                        if n.node_type == NodeType.VAR_DEF and n.name == param
                    ]
                    if param_nodes:
                        flows.append((param, ret_var))
        
        return flows
    
    def _detect_side_effects(self, func_nodes: List[ValueNode]) -> Set[str]:
        """检测函数的副作用"""
        side_effects = set()
        
        for node in func_nodes:
            # 字段写入
            if node.node_type == NodeType.FIELD_WRITE:
                if node.metadata.get('is_global'):
                    side_effects.add(node.field_name or "unknown_field")
            
            # 数组/切片写入
            if node.node_type == NodeType.INDEX_WRITE:
                if node.metadata.get('is_global'):
                    side_effects.add(node.name)
        
        return side_effects
    
    def _analyze_call_contexts(self):
        """分析所有调用上下文"""
        for call_node in self.graph.call_sites:
            if not call_node.func_name:
                continue
            
            caller_func = call_node.metadata.get('caller_func')
            if not caller_func:
                continue
            
            # 构建参数映射
            arg_mapping = {}
            for i, arg_node in enumerate(call_node.args):
                arg_mapping[i] = arg_node
            
            context = CallContext(
                caller_func=caller_func,
                callee_func=call_node.func_name,
                call_site=call_node,
                arg_mapping=arg_mapping,
                return_value=call_node.ret_value
            )
            
            self.call_contexts.append(context)
    
    def _track_parameter_passing(self):
        """追踪参数传递"""
        for context in self.call_contexts:
            summary = self.func_summaries.get(context.callee_func)
            if not summary:
                continue
            
            # 为每个参数建立调用点实参到被调用函数形参的映射
            for arg_idx, arg_node in context.arg_mapping.items():
                if arg_idx < len(summary.params):
                    param_name = summary.params[arg_idx]
                    
                    # 记录元数据
                    context.call_site.metadata[f'arg_{arg_idx}_flows_to'] = param_name
    
    def _track_return_values(self):
        """追踪返回值"""
        for context in self.call_contexts:
            summary = self.func_summaries.get(context.callee_func)
            if not summary or not context.return_value:
                continue
            
            # 建立被调用函数返回值到调用点返回值的映射
            for ret_var in summary.return_vars:
                context.return_value.metadata['flows_from'] = ret_var
    
    def get_interprocedural_slice(
        self, 
        start_node: ValueNode, 
        max_depth: int = 10
    ) -> Set[ValueNode]:
        """
        过程间后向切片
        
        从 start_node 开始，追踪跨函数的依赖关系
        """
        slice_nodes = set()
        worklist = [(start_node, 0, None)]  # (node, depth, context)
        visited = set()
        
        while worklist:
            node, depth, context = worklist.pop(0)
            
            if (node, context) in visited or depth > max_depth:
                continue
            
            visited.add((node, context))
            slice_nodes.add(node)
            
            # 1. 函数内依赖（标准后向切片）
            intra_deps = self._get_intraprocedural_deps(node)
            for dep_node in intra_deps:
                worklist.append((dep_node, depth + 1, context))
            
            # 2. 跨函数依赖
            inter_deps = self._get_interprocedural_deps(node, context)
            for dep_node, new_context in inter_deps:
                worklist.append((dep_node, depth + 1, new_context))
        
        return slice_nodes
    
    def _get_intraprocedural_deps(self, node: ValueNode) -> List[ValueNode]:
        """获取函数内依赖"""
        deps = []
        
        # 直接依赖
        if node.rhs:
            deps.append(node.rhs)
        
        deps.extend(node.operands)
        
        if node.obj:
            deps.append(node.obj)
        
        deps.extend(node.args)
        
        # 变量定义
        if node.node_type == NodeType.VAR_DEF:
            for alias in self.graph.get_aliases(node.name):
                reaching_defs = self.graph.def_map.get(alias, [])
                for def_node in reaching_defs:
                    if def_node != node:
                        deps.append(def_node)
        
        return deps
    
    def _get_interprocedural_deps(
        self, 
        node: ValueNode, 
        context: Optional[CallContext]
    ) -> List[Tuple[ValueNode, Optional[CallContext]]]:
        """获取跨函数依赖"""
        deps = []
        
        # 场景 1：node 是函数参数，追踪到调用点
        if node.metadata.get('is_param'):
            func_name = node.metadata.get('function')
            param_name = node.name
            
            # 查找所有调用该函数的上下文
            for ctx in self.call_contexts:
                if ctx.callee_func == func_name:
                    summary = self.func_summaries.get(func_name)
                    if summary and param_name in summary.params:
                        param_idx = summary.params.index(param_name)
                        if param_idx in ctx.arg_mapping:
                            arg_node = ctx.arg_mapping[param_idx]
                            deps.append((arg_node, ctx))
        
        # 场景 2：node 是调用的返回值，追踪到被调用函数的返回
        if node.node_type == NodeType.CALL and node.ret_value:
            summary = self.func_summaries.get(node.func_name or "")
            if summary:
                # 查找被调用函数的返回值节点
                callee_nodes = [
                    n for n in self.graph.nodes
                    if n.metadata.get('function') == node.func_name and
                       n.metadata.get('is_return')
                ]
                for ret_node in callee_nodes:
                    deps.append((ret_node, None))
        
        return deps
    
    def print_summary(self):
        """打印分析摘要"""
        print(f"\n{'='*70}")
        print(f"过程间分析摘要")
        print(f"{'='*70}")
        
        print(f"\n函数数量: {len(self.func_summaries)}")
        print(f"调用上下文数量: {len(self.call_contexts)}")
        
        for func_name, summary in self.func_summaries.items():
            print(f"\n函数: {func_name}")
            print(f"  参数: {summary.params}")
            print(f"  返回值: {summary.return_vars}")
            print(f"  值流: {summary.value_flows}")
            if summary.side_effects:
                print(f"  副作用: {summary.side_effects}")


# 便捷函数
def enhance_value_graph_with_interprocedural(
    value_graph: ValueGraph
) -> InterproceduralAnalyzer:
    """
    增强 ValueGraph 的过程间分析能力
    
    Args:
        value_graph: 要增强的值图
    
    Returns:
        配置好的过程间分析器
    """
    analyzer = InterproceduralAnalyzer(value_graph)
    analyzer.analyze()
    return analyzer


if __name__ == '__main__':
    # 测试示例
    print("过程间分析增强模块")
    print("用法: analyzer = enhance_value_graph_with_interprocedural(value_graph)")
