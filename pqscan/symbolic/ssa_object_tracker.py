from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ObjectLifecycleEvent(Enum):
    """对象生命周期事件"""
    CREATE = "create"      # 对象创建
    ASSIGN = "assign"      # 变量赋值
    ALIAS = "alias"        # 别名创建
    WRITE = "write"        # 状态写入
    READ = "read"          # 状态读取
    DESTROY = "destroy"    # 对象销毁


@dataclass
class SSAVariable:
    """SSA 变量（变量的特定版本）"""
    name: str              # 原始变量名（如 "ctx"）
    version: int           # SSA 版本号（如 0, 1, 2...）
    line: int              # 定义行号
    
    def __str__(self):
        return f"{self.name}_v{self.version}"
    
    def __hash__(self):
        return hash((self.name, self.version))
    
    def __eq__(self, other):
        return isinstance(other, SSAVariable) and \
               self.name == other.name and self.version == other.version


@dataclass
class SSAObject:
    """SSA 对象（实际的运行时对象）"""
    object_id: str         # 唯一对象 ID（如 "obj_0", "obj_1"）
    object_type: str       # 对象类型（如 "EVP_CIPHER_CTX"）
    created_at: int        # 创建行号
    state: Dict[str, Any] = field(default_factory=dict)  # 对象状态
    
    # 追踪信息
    created_by: Optional[SSAVariable] = None  # 创建该对象的变量
    aliases: Set[SSAVariable] = field(default_factory=set)  # 所有指向该对象的变量


@dataclass
class SSAStateEvent:
    """SSA 状态事件（历史记录）"""
    event: ObjectLifecycleEvent
    line: int
    variable: Optional[SSAVariable] = None
    object_id: Optional[str] = None
    field: Optional[str] = None
    value: Any = None


class SSAObjectTracker:
    """
    SSA-based Object State Tracker
    
    核心思想：
    1. 使用 SSA 变量（name_v{version}）作为变量标识符
    2. 维护 SSA 变量 → 对象 ID 的映射（处理别名）
    3. 维护对象 ID → 对象状态的映射（追踪状态）
    
    优势：
    - 精确追踪变量别名（ctx = ctx1）
    - 精确追踪变量重新赋值（ctx = new_object()）
    - 支持跨函数分析（通过 SSA 参数传递）
    - 多语言通用（只依赖 SSA 表示）
    
    使用示例：
        tracker = SSAObjectTracker()
        
        # ctx_v0 = EVP_CIPHER_CTX_new()
        ctx_v0 = SSAVariable("ctx", 0, line=10)
        tracker.track_object_creation(ctx_v0, "EVP_CIPHER_CTX", line=10)
        
        # EVP_EncryptInit_ex(ctx_v0, EVP_aes_256_gcm(), ...)
        tracker.write_object_state(ctx_v0, "algorithm", "EVP_aes_256_gcm", line=11)
        
        # ctx_v1 = ctx_v0  (别名)
        ctx_v1 = SSAVariable("ctx", 1, line=12)
        tracker.track_alias(ctx_v1, ctx_v0, line=12)
        
        # ctx_v2 = EVP_CIPHER_CTX_new()  (新对象)
        ctx_v2 = SSAVariable("ctx", 2, line=15)
        tracker.track_object_creation(ctx_v2, "EVP_CIPHER_CTX", line=15)
    """
    
    def __init__(self):
        # 核心映射
        self.var_to_object: Dict[SSAVariable, str] = {}  # SSA 变量 → 对象 ID
        self.objects: Dict[str, SSAObject] = {}           # 对象 ID → 对象
        
        # 计数器
        self.next_object_id = 0
        
        # 历史记录
        self.events: List[SSAStateEvent] = []
    
    def track_object_creation(
        self,
        variable: SSAVariable,
        object_type: str,
        line: int
    ) -> str:
        """
        追踪对象创建
        
        Args:
            variable: 被赋值的 SSA 变量
            object_type: 对象类型
            line: 行号
        
        Returns:
            object_id: 新创建的对象 ID
        """
        # 生成唯一对象 ID
        object_id = f"obj_{self.next_object_id}"
        self.next_object_id += 1
        
        # 创建对象
        obj = SSAObject(
            object_id=object_id,
            object_type=object_type,
            created_at=line,
            created_by=variable
        )
        obj.aliases.add(variable)
        
        # 注册映射
        self.objects[object_id] = obj
        self.var_to_object[variable] = object_id
        
        # 记录事件
        self.events.append(SSAStateEvent(
            event=ObjectLifecycleEvent.CREATE,
            line=line,
            variable=variable,
            object_id=object_id
        ))
        
        return object_id
    
    def track_alias(
        self,
        new_variable: SSAVariable,
        source_variable: SSAVariable,
        line: int
    ):
        """
        追踪别名创建（例如：ctx_v1 = ctx_v0）
        
        Args:
            new_variable: 新的 SSA 变量（左值）
            source_variable: 源 SSA 变量（右值）
            line: 行号
        """
        # 获取源变量指向的对象
        object_id = self.var_to_object.get(source_variable)
        if not object_id:
            # 源变量未追踪，忽略
            return
        
        # 新变量指向同一对象
        self.var_to_object[new_variable] = object_id
        
        # 更新对象的别名集合
        if object_id in self.objects:
            self.objects[object_id].aliases.add(new_variable)
        
        # 记录事件
        self.events.append(SSAStateEvent(
            event=ObjectLifecycleEvent.ALIAS,
            line=line,
            variable=new_variable,
            object_id=object_id
        ))
    
    def write_object_state(
        self,
        variable: SSAVariable,
        field: str,
        value: Any,
        line: int
    ):
        """
        写入对象状态
        
        Args:
            variable: SSA 变量（指向对象）
            field: 状态字段名
            value: 字段值
            line: 行号
        """
        # 获取变量指向的对象
        object_id = self.var_to_object.get(variable)
        if not object_id or object_id not in self.objects:
            # 对象未追踪，忽略
            return
        
        # 写入状态
        self.objects[object_id].state[field] = value
        
        # 记录事件
        self.events.append(SSAStateEvent(
            event=ObjectLifecycleEvent.WRITE,
            line=line,
            variable=variable,
            object_id=object_id,
            field=field,
            value=value
        ))
    
    def read_object_state(
        self,
        variable: SSAVariable,
        field: Optional[str] = None
    ) -> Any:
        """
        读取对象状态
        
        Args:
            variable: SSA 变量
            field: 可选的字段名（None 表示读取整个状态）
        
        Returns:
            字段值或整个状态字典
        """
        object_id = self.var_to_object.get(variable)
        if not object_id or object_id not in self.objects:
            return None
        
        obj = self.objects[object_id]
        
        if field:
            return obj.state.get(field)
        else:
            return obj.state.copy()
    
    def get_object_for_variable(self, variable: SSAVariable) -> Optional[SSAObject]:
        """获取变量指向的对象"""
        object_id = self.var_to_object.get(variable)
        if object_id:
            return self.objects.get(object_id)
        return None
    
    def get_all_aliases(self, variable: SSAVariable) -> Set[SSAVariable]:
        """获取变量的所有别名（指向同一对象的所有变量）"""
        object_id = self.var_to_object.get(variable)
        if object_id and object_id in self.objects:
            return self.objects[object_id].aliases.copy()
        return set()
    
    def track_object_destruction(self, variable: SSAVariable, line: int):
        """追踪对象销毁"""
        object_id = self.var_to_object.get(variable)
        if object_id:
            self.events.append(SSAStateEvent(
                event=ObjectLifecycleEvent.DESTROY,
                line=line,
                variable=variable,
                object_id=object_id
            ))
    
    def get_events_for_object(self, object_id: str) -> List[SSAStateEvent]:
        """获取特定对象的所有事件"""
        return [e for e in self.events if e.object_id == object_id]
    
    def get_events_for_variable(self, variable: SSAVariable) -> List[SSAStateEvent]:
        """获取特定变量的所有事件"""
        return [e for e in self.events if e.variable == variable]
    
    def summary(self) -> Dict[str, Any]:
        """生成追踪摘要"""
        return {
            "total_objects": len(self.objects),
            "total_events": len(self.events),
            "objects": {
                obj_id: {
                    "type": obj.object_type,
                    "created_at": obj.created_at,
                    "created_by": str(obj.created_by),
                    "aliases": [str(v) for v in obj.aliases],
                    "state": obj.state
                }
                for obj_id, obj in self.objects.items()
            }
        }
    
    def reset(self):
        """重置追踪器"""
        self.var_to_object.clear()
        self.objects.clear()
        self.events.clear()
        self.next_object_id = 0


class SSAVariableNamer:
    """
    SSA 变量命名器
    
    负责将原始变量名转换为 SSA 版本
    
    使用示例：
        namer = SSAVariableNamer()
        
        # 第一次赋值: ctx = ...
        ctx_v0 = namer.get_next_version("ctx", line=10)  # SSAVariable("ctx", 0, 10)
        
        # 第二次赋值: ctx = ...
        ctx_v1 = namer.get_next_version("ctx", line=15)  # SSAVariable("ctx", 1, 15)
        
        # 获取当前版本（无副作用）
        current = namer.get_current_version("ctx")  # SSAVariable("ctx", 1, 15)
    """
    
    def __init__(self):
        self.versions: Dict[str, int] = {}          # 变量名 → 当前版本号
        self.version_lines: Dict[Tuple[str, int], int] = {}  # (变量名, 版本) → 行号
    
    def get_next_version(self, var_name: str, line: int) -> SSAVariable:
        """
        获取变量的下一个 SSA 版本（用于赋值语句）
        
        Args:
            var_name: 原始变量名
            line: 赋值行号
        
        Returns:
            新的 SSA 变量
        """
        current_version = self.versions.get(var_name, -1)
        new_version = current_version + 1
        self.versions[var_name] = new_version
        self.version_lines[(var_name, new_version)] = line
        
        return SSAVariable(var_name, new_version, line)
    
    def get_current_version(self, var_name: str) -> Optional[SSAVariable]:
        """
        获取变量的当前 SSA 版本（用于使用语句）
        
        Args:
            var_name: 原始变量名
        
        Returns:
            当前 SSA 变量，如果未定义则返回 None
        """
        version = self.versions.get(var_name)
        if version is None:
            return None
        
        line = self.version_lines.get((var_name, version), -1)
        return SSAVariable(var_name, version, line)
    
    def reset(self):
        """重置命名器"""
        self.versions.clear()
        self.version_lines.clear()
