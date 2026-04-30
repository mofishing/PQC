from typing import Any, Dict, List, Optional, Set
from ..analysis.candidate import Candidate
from .schema import (
    SSAFunction, SSABlock, SSAInstruction, SSAValue,
    SymbolicValue, PathConstraint, ExecutionPath,
    SymbolicExecutionResult, RefinedFinding,
    InstructionType
)
from .ir_builder import create_ir_builder


class SymbolicExecutor:
    """
    符号执行引擎
    
    核心能力：
    1. 路径探索（遍历所有可能的执行路径）
    2. 符号值传播（跟踪符号值的流动）
    3. 约束收集（记录路径条件）
    4. 约束求解（推导可能的参数值）
    """
    
    def __init__(self, max_paths: int = 100, max_depth: int = 50):
        """
        Args:
            max_paths: 最大探索路径数（防止路径爆炸）
            max_depth: 最大探索深度
        """
        self.max_paths = max_paths
        self.max_depth = max_depth
        
        # 路径计数器
        self.path_counter = 0
        
        # 结果缓存
        self.cache: Dict[str, SymbolicExecutionResult] = {}
    
    def analyze_candidate(self, candidate: Candidate) -> SymbolicExecutionResult:
        """
        分析单个候选点
        
        流程：
        1. 提取候选点所在函数
        2. 构建 SSA/IR
        3. 符号执行
        4. 约束求解
        5. 推导算法和参数
        """
        # 缓存检查
        cache_key = f"{candidate.location.file}:{candidate.location.line}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        result = SymbolicExecutionResult(candidate=candidate)
        
        try:
            # 1. 构建 SSA/IR
            ssa_function = self._build_ssa_for_candidate(candidate)
            if not ssa_function:
                return result
            
            # 2. 符号执行：探索所有路径
            paths = self._explore_paths(ssa_function, candidate)
            result.paths = paths
            
            # 3. 对每条路径进行分析
            for path in paths:
                # 求解约束
                solutions = self._solve_constraints(path)
                
                # 推导算法和参数
                for solution in solutions:
                    algorithm = self._infer_algorithm(candidate, solution, path)
                    parameters = self._extract_parameters(solution)
                    
                    if algorithm:
                        result.add_inference(
                            algorithm=algorithm,
                            parameters=parameters,
                            path_id=path.path_id
                        )
            
            # 缓存结果
            self.cache[cache_key] = result
            
        except Exception as e:
            print(f"Symbolic execution failed for {candidate}: {e}", file=sys.stderr)
        
        return result
    
    def _build_ssa_for_candidate(self, candidate: Candidate) -> Optional[SSAFunction]:
        """
        为候选点构建 SSA
        
        步骤：
        1. 找到候选点所在函数
        2. 使用 IR Builder 构建 SSA
        """
        # 获取函数 AST
        func_ast = self._find_enclosing_function(candidate)
        if not func_ast:
            return None
        
        # 构建 SSA
        builder = create_ir_builder(candidate.language)
        func_name = candidate.scope.function_name or "anonymous"
        ssa_function = builder.build_function(func_ast, func_name)
        
        return ssa_function
    
    def _find_enclosing_function(self, candidate: Candidate) -> Optional[Any]:
        """查找候选点所在的函数 AST 节点"""
        # 从候选点的 AST 节点向上遍历，找到函数定义
        node = candidate.ast_node
        while node:
            if node.type in ['function_definition', 'function_declaration', 
                           'method_declaration', 'function']:
                return node
            node = node.parent if hasattr(node, 'parent') else None
        return None
    
    def _explore_paths(self, ssa_function: SSAFunction, candidate: Candidate) -> List[ExecutionPath]:
        """
        路径探索：从入口块开始，遍历所有可能的执行路径
        
        使用深度优先搜索（DFS）
        """
        paths: List[ExecutionPath] = []
        
        # 工作队列：(当前块, 已访问块, 约束列表, 符号状态)
        worklist = [(
            ssa_function.entry_block,
            [],
            [],
            {}  # 初始符号状态
        )]
        
        while worklist and len(paths) < self.max_paths:
            current_block, visited, constraints, sym_state = worklist.pop()
            
            # 检查深度限制
            if len(visited) > self.max_depth:
                continue
            
            # 避免无限循环（简化版：限制重复访问）
            if visited.count(current_block) > 2:
                continue
            
            # 更新路径
            new_visited = visited + [current_block]
            
            # 执行当前块的指令
            new_sym_state = sym_state.copy()
            new_constraints = constraints.copy()
            
            self._execute_block(current_block, new_sym_state, new_constraints)
            
            # 处理后继块
            if not current_block.successors:
                # 到达终点，保存路径
                path = ExecutionPath(
                    path_id=self.path_counter,
                    blocks=new_visited,
                    constraints=new_constraints,
                    symbolic_state=new_sym_state
                )
                self.path_counter += 1
                paths.append(path)
            else:
                # 继续探索后继块
                for successor in current_block.successors:
                    worklist.append((
                        successor,
                        new_visited,
                        new_constraints,
                        new_sym_state.copy()
                    ))
        
        return paths
    
    def _execute_block(self, block: SSABlock, sym_state: Dict, constraints: List[PathConstraint]):
        """
        执行基本块的所有指令
        
        更新符号状态和约束
        """
        # 执行 Phi 节点
        for phi in block.phi_nodes:
            # 简化：取第一个操作数
            if phi.operands:
                sym_state[phi.result.name] = self._get_symbolic_value(phi.operands[0], sym_state)
        
        # 执行普通指令
        for inst in block.instructions:
            if inst.type == InstructionType.ASSIGN:
                # 赋值：result = operand
                if inst.operands:
                    sym_state[inst.result.name] = self._get_symbolic_value(inst.operands[0], sym_state)
            
            elif inst.type == InstructionType.BINARY_OP:
                # 二元运算：result = operand1 op operand2
                left = self._get_symbolic_value(inst.operands[0], sym_state)
                right = self._get_symbolic_value(inst.operands[1], sym_state)
                
                # 尝试常量折叠
                if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    result = self._eval_binary_op(left, inst.operator, right)
                    sym_state[inst.result.name] = result
                else:
                    # 创建符号表达式
                    sym_state[inst.result.name] = f"({left} {inst.operator} {right})"
            
            elif inst.type == InstructionType.CALL:
                # 函数调用：result = func(args...)
                # 简化：记录调用，但不展开（除非是已知的 wrapper）
                sym_state[inst.result.name] = f"call_{inst.function_name}"
            
            elif inst.type == InstructionType.BRANCH:
                # 分支：收集路径约束
                if inst.operands:
                    condition = self._get_symbolic_value(inst.operands[0], sym_state)
                    constraint = PathConstraint(
                        condition=str(condition),
                        location=inst.location
                    )
                    constraints.append(constraint)
    
    def _get_symbolic_value(self, ssa_value: SSAValue, sym_state: Dict) -> Any:
        """获取 SSA 值的符号或具体值"""
        if ssa_value.is_constant:
            return ssa_value.constant_value
        
        return sym_state.get(ssa_value.name, SymbolicValue(ssa_value.name))
    
    def _eval_binary_op(self, left: Any, operator: str, right: Any) -> Any:
        """常量二元运算求值"""
        try:
            if operator == '+':
                return left + right
            elif operator == '-':
                return left - right
            elif operator == '*':
                return left * right
            elif operator == '/':
                return left / right if right != 0 else None
            elif operator == '==':
                return left == right
            elif operator == '!=':
                return left != right
            elif operator == '<':
                return left < right
            elif operator == '<=':
                return left <= right
            elif operator == '>':
                return left > right
            elif operator == '>=':
                return left >= right
            else:
                return None
        except:
            return None
    
    def _solve_constraints(self, path: ExecutionPath) -> List[Dict[str, Any]]:
        """
        约束求解
        
        简化版：从符号状态中提取具体值
        完整版应使用 Z3 等 SMT 求解器
        """
        solutions = []
        
        # 简化：直接使用 concrete_state（如果有的话）
        if path.concrete_state:
            solutions.append(path.concrete_state)
        else:
            # 从符号状态推导
            solution = {}
            for var, value in path.symbolic_state.items():
                if isinstance(value, (int, float, str)) and not isinstance(value, bool):
                    solution[var] = value
            
            if solution:
                solutions.append(solution)
        
        return solutions if solutions else [{}]
    
    def _infer_algorithm(self, candidate: Candidate, solution: Dict[str, Any], 
                        path: ExecutionPath) -> Optional[str]:
        """
        推导算法
        
        基于候选点的符号和路径约束
        """
        symbol = candidate.symbol
        
        # 从符号推导算法（简化版）
        # 例如：EVP_aes_128_cbc → AES-128-CBC
        
        if 'aes' in symbol.lower():
            # 推导 AES 变体
            if '128' in symbol or solution.get('key_bits') == 128:
                key_size = 128
            elif '192' in symbol or solution.get('key_bits') == 192:
                key_size = 192
            elif '256' in symbol or solution.get('key_bits') == 256:
                key_size = 256
            else:
                key_size = None
            
            # 推导模式
            if 'cbc' in symbol.lower():
                mode = 'CBC'
            elif 'ecb' in symbol.lower():
                mode = 'ECB'
            elif 'gcm' in symbol.lower():
                mode = 'GCM'
            elif 'ctr' in symbol.lower():
                mode = 'CTR'
            else:
                mode = None
            
            if key_size and mode:
                return f"AES-{key_size}-{mode}"
            elif key_size:
                return f"AES-{key_size}"
            else:
                return "AES"
        
        elif 'rsa' in symbol.lower():
            key_bits = solution.get('key_bits') or solution.get('bits')
            if key_bits:
                return f"RSA-{key_bits}"
            return "RSA"
        
        # 默认返回符号名
        return symbol
    
    def _extract_parameters(self, solution: Dict[str, Any]) -> Dict[str, Any]:
        """提取算法参数"""
        params = {}
        
        # 提取关键参数
        for key in ['key_bits', 'key_size', 'bits', 'mode', 'iv']:
            if key in solution:
                params[key] = solution[key]
        
        return params


import sys
