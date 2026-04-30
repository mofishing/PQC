"""
Symbolic Execution Core Data Structures
符号执行核心数据结构
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union
from enum import Enum


# ============================================================
# SSA/IR 数据结构
# ============================================================

class InstructionType(Enum):
    """SSA 指令类型"""
    # 赋值
    ASSIGN = "assign"           # v0 = expr
    PHI = "phi"                 # v0 = phi(v1, v2)  路径合并
    
    # 运算
    BINARY_OP = "binary_op"     # v0 = v1 + v2
    UNARY_OP = "unary_op"       # v0 = -v1
    
    # 函数调用
    CALL = "call"               # v0 = func(args...)
    RETURN = "return"           # return v0
    
    # 控制流
    BRANCH = "branch"           # br cond, label_true, label_false
    JUMP = "jump"               # goto label
    
    # 内存
    LOAD = "load"               # v0 = *ptr
    STORE = "store"             # *ptr = v0
    
    # 其他
    NOP = "nop"


@dataclass
class SSAValue:
    """SSA 值（符号或常量）"""
    name: str                   # v0, v1, ... 或符号名
    type: Optional[str] = None  # 类型（int, str, ...）
    is_constant: bool = False
    constant_value: Any = None
    
    def __str__(self) -> str:
        if self.is_constant:
            return f"{self.name}={self.constant_value}"
        return self.name
    
    def __hash__(self):
        return hash(self.name)
    
    def __eq__(self, other):
        if isinstance(other, SSAValue):
            return self.name == other.name
        return False


@dataclass
class SSAInstruction:
    """SSA 指令"""
    type: InstructionType
    result: Optional[SSAValue] = None      # 结果变量
    operands: List[SSAValue] = field(default_factory=list)  # 操作数
    
    # 额外信息
    operator: Optional[str] = None         # 运算符 (+, -, ==, ...)
    function_name: Optional[str] = None    # 函数名（CALL 指令）
    target_label: Optional[str] = None     # 跳转目标（BRANCH/JUMP）
    
    # 源码位置
    location: Optional[Any] = None
    
    def __str__(self) -> str:
        if self.type == InstructionType.ASSIGN:
            return f"{self.result} = {self.operands[0]}"
        elif self.type == InstructionType.PHI:
            ops = ', '.join(str(op) for op in self.operands)
            return f"{self.result} = phi({ops})"
        elif self.type == InstructionType.BINARY_OP:
            return f"{self.result} = {self.operands[0]} {self.operator} {self.operands[1]}"
        elif self.type == InstructionType.CALL:
            args = ', '.join(str(op) for op in self.operands)
            return f"{self.result} = call {self.function_name}({args})"
        elif self.type == InstructionType.BRANCH:
            return f"br {self.operands[0]}, {self.target_label}"
        else:
            return f"{self.type.value}"


@dataclass
class SSABlock:
    """SSA 基本块"""
    label: str                             # 块标签
    instructions: List[SSAInstruction] = field(default_factory=list)
    
    # 控制流
    predecessors: List['SSABlock'] = field(default_factory=list)
    successors: List['SSABlock'] = field(default_factory=list)
    
    # Phi 节点（在块开头）
    phi_nodes: List[SSAInstruction] = field(default_factory=list)
    
    def add_instruction(self, inst: SSAInstruction):
        """添加指令"""
        if inst.type == InstructionType.PHI:
            self.phi_nodes.append(inst)
        else:
            self.instructions.append(inst)
    
    def __str__(self) -> str:
        lines = [f"{self.label}:"]
        for phi in self.phi_nodes:
            lines.append(f"  {phi}")
        for inst in self.instructions:
            lines.append(f"  {inst}")
        return '\n'.join(lines)


@dataclass
class SSAFunction:
    """SSA 函数表示"""
    name: str
    parameters: List[SSAValue] = field(default_factory=list)
    blocks: List[SSABlock] = field(default_factory=list)
    entry_block: Optional[SSABlock] = None
    
    # 符号表（变量名 → SSAValue）
    symbol_table: Dict[str, SSAValue] = field(default_factory=dict)
    
    # 版本计数器（用于生成 SSA 变量名）
    version_counter: int = 0
    
    # def-use 缓存（延迟构建）
    _def_use_map: Optional[Dict[str, List[SSAInstruction]]] = None
    
    def new_value(self, base_name: str = "v") -> SSAValue:
        """生成新的 SSA 值"""
        value = SSAValue(f"{base_name}{self.version_counter}")
        self.version_counter += 1
        return value
    
    def add_block(self, label: str) -> SSABlock:
        """添加基本块"""
        block = SSABlock(label)
        self.blocks.append(block)
        if self.entry_block is None:
            self.entry_block = block
        return block
    
    def build_def_use_map(self) -> Dict[str, List[SSAInstruction]]:
        """
        构建 def-use 映射：变量名 → 定义该变量的指令列表
        
        Returns:
            {var_name: [instruction1, instruction2, ...]}
        """
        if self._def_use_map is not None:
            return self._def_use_map
        
        def_use_map = {}
        
        for block in self.blocks:
            # 处理 PHI 节点
            for phi in block.phi_nodes:
                if phi.result:
                    var_name = phi.result.name
                    if var_name not in def_use_map:
                        def_use_map[var_name] = []
                    def_use_map[var_name].append(phi)
            
            # 处理普通指令
            for inst in block.instructions:
                if inst.result:
                    var_name = inst.result.name
                    if var_name not in def_use_map:
                        def_use_map[var_name] = []
                    def_use_map[var_name].append(inst)
        
        self._def_use_map = def_use_map
        return def_use_map
    
    def find_reaching_definition(
        self, 
        var_name: str, 
        target_line: Optional[int] = None
    ) -> Optional[SSAInstruction]:
        """
        查找变量在指定行的到达定义（reaching definition）
        
        Args:
            var_name: 变量名（原始名，非 SSA 版本名）
            target_line: 目标行号（如果为 None，返回最后一个定义）
        
        Returns:
            定义该变量的 SSA 指令，如果没有则返回 None
        """
        def_use_map = self.build_def_use_map()
        
        # 查找所有可能的 SSA 版本（例如 key0, key1, key2）
        matching_defs = []
        for ssa_var_name, instructions in def_use_map.items():
            # 匹配原始变量名（去掉 SSA 版本号）
            base_name = ssa_var_name.rstrip('0123456789')
            if base_name == var_name or ssa_var_name == var_name:
                matching_defs.extend(instructions)
        
        if not matching_defs:
            return None
        
        # 如果没有指定目标行，返回最后一个定义
        if target_line is None:
            return matching_defs[-1]
        
        # 查找目标行之前的最后一个定义
        valid_defs = [
            inst for inst in matching_defs
            if inst.location and hasattr(inst.location, 'line') and inst.location.line <= target_line
        ]
        
        if valid_defs:
            # 返回最接近目标行的定义
            return max(valid_defs, key=lambda inst: inst.location.line if inst.location else 0)
        
        # 如果没有找到目标行之前的定义，返回最后一个定义（可能是参数）
        return matching_defs[-1] if matching_defs else None
    
    def get_constant_value(self, var_name: str, target_line: Optional[int] = None) -> Optional[Any]:
        """
        获取变量的常量值（如果是常量）
        
        Args:
            var_name: 变量名
            target_line: 目标行号
        
        Returns:
            常量值，如果不是常量则返回 None
        """
        definition = self.find_reaching_definition(var_name, target_line)
        
        if not definition:
            return None
        
        # 从 ASSIGN 指令提取常量
        if definition.type == InstructionType.ASSIGN:
            if definition.operands and len(definition.operands) > 0:
                operand = definition.operands[0]
                if operand.is_constant:
                    return operand.constant_value
        
        # 从 PHI 节点提取（如果所有分支都是同一个常量）
        elif definition.type == InstructionType.PHI:
            values = set()
            for operand in definition.operands:
                if operand.is_constant:
                    values.add(operand.constant_value)
                else:
                    return None  # 有非常量操作数，无法确定
            
            if len(values) == 1:
                return values.pop()
        
        return None
    
    def __str__(self) -> str:
        lines = [f"function {self.name}({', '.join(str(p) for p in self.parameters)}):"]
        for block in self.blocks:
            lines.append(str(block))
        return '\n'.join(lines)


# ============================================================
# 符号执行数据结构
# ============================================================

@dataclass
class SymbolicValue:
    """符号值"""
    name: str                          # 符号名
    type: Optional[str] = None         # 类型
    constraints: List[str] = field(default_factory=list)  # 约束条件
    
    # 可能的具体值（如果能推导出来）
    possible_values: Set[Any] = field(default_factory=set)
    
    def __str__(self) -> str:
        if self.possible_values:
            return f"Symbol({self.name} ∈ {self.possible_values})"
        return f"Symbol({self.name})"


@dataclass
class PathConstraint:
    """路径约束"""
    condition: str                     # 约束表达式（如 "key_size == 128"）
    location: Optional[Any] = None     # 约束来源位置
    
    def __str__(self) -> str:
        return self.condition


@dataclass
class ExecutionPath:
    """执行路径"""
    path_id: int
    blocks: List[SSABlock] = field(default_factory=list)
    constraints: List[PathConstraint] = field(default_factory=list)
    
    # 符号状态（变量 → 符号值）
    symbolic_state: Dict[str, SymbolicValue] = field(default_factory=dict)
    
    # 具体值状态（变量 → 具体值）
    concrete_state: Dict[str, Any] = field(default_factory=dict)
    
    def add_constraint(self, constraint: PathConstraint):
        """添加路径约束"""
        self.constraints.append(constraint)
    
    def is_feasible(self) -> bool:
        """路径是否可行（通过约束求解判断）"""
        # TODO: 集成 Z3 或简化约束求解
        return True  # 暂时返回 True
    
    def __str__(self) -> str:
        path_str = ' → '.join(b.label for b in self.blocks)
        constraints_str = ' ∧ '.join(str(c) for c in self.constraints)
        return f"Path {self.path_id}: {path_str}\n  Constraints: {constraints_str}"


@dataclass
class SymbolicExecutionResult:
    """符号执行结果"""
    candidate: Any  # Candidate 对象（避免循环导入）
    
    # 所有可行路径
    paths: List[ExecutionPath] = field(default_factory=list)
    
    # 推导出的算法和参数
    inferred_algorithms: List[Dict[str, Any]] = field(default_factory=list)
    # 例如: [{'algorithm': 'AES-128-CBC', 'key_size': 128, 'path_id': 0}]
    
    # Wrapper 展开信息
    wrapper_calls: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_inference(self, algorithm: str, parameters: Dict[str, Any], path_id: int):
        """添加推导结果"""
        self.inferred_algorithms.append({
            'algorithm': algorithm,
            'parameters': parameters,
            'path_id': path_id
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化"""
        return {
            'paths': [
                {
                    'path_id': p.path_id,
                    'blocks': [b.label for b in p.blocks],
                    'constraints': [str(c) for c in p.constraints],
                    'concrete_state': p.concrete_state
                }
                for p in self.paths
            ],
            'inferred_algorithms': self.inferred_algorithms,
            'wrapper_calls': self.wrapper_calls
        }


# ============================================================
# 精确结果数据结构
# ============================================================

@dataclass
class RefinedFinding:
    """
    精确分析结果（Phase 2 输出）
    """
    # 原始候选点
    candidate: Any  # Candidate 对象
    
    # 推导出的算法和参数
    algorithm: Optional[str] = None         # 如 "AES-128-CBC"
    parameters: Dict[str, Any] = field(default_factory=dict)  # 如 {'key_size': 128}
    
    # 路径条件
    path_condition: Optional[str] = None    # 如 "mode == 'weak'"
    
    # 风险评估
    severity: str = "UNKNOWN"               # SAFE/HIGH/CRITICAL
    risk_score: float = 0.0                 # 风险分数 0-100
    
    # 符号执行结果
    symbolic_result: Optional[SymbolicExecutionResult] = None
    
    # 置信度（结合 Phase 1 和 Phase 2）
    confidence: float = 1.0
    
    # 影响面
    affected_paths: List[str] = field(default_factory=list)  # 受影响的代码路径
    
    # 建议
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化"""
        result = {
            'location': {
                'file': self.candidate.location.file,
                'line': self.candidate.location.line,
            },
            'symbol': self.candidate.symbol,
            'algorithm': self.algorithm,
            'parameters': self.parameters,
            'path_condition': self.path_condition,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'affected_paths': self.affected_paths,
            'recommendation': self.recommendation,
        }
        
        if self.symbolic_result:
            result['symbolic_result'] = self.symbolic_result.to_dict()
        
        return result
