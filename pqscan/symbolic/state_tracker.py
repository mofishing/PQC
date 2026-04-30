#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
对象状态追踪器 - 跟踪对象/上下文的生命周期和状态变化

设计目标：
1. 支持结构体字段赋值追踪 (config.key_bits = 2048)
2. 支持对象方法调用状态追踪 (ctx = init(); ctx.set_key(256))
3. 支持条件分支的状态分叉和合并
4. 支持指针/引用的别名分析

核心概念：
- ObjectState: 对象的状态快照（字段值、方法调用历史）
- StateSnapshot: 程序点的全局状态快照
- PathConstraint: 路径条件约束

应用场景：
```c
// 场景1: EVP上下文状态追踪
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);  // ctx.algorithm = AES-256-GCM
EVP_EncryptUpdate(ctx, ...);  // 使用ctx的状态

// 场景2: 结构体配置对象
struct crypto_config config;
config.key_bits = 2048;
config.algorithm = "RSA";
init_crypto(&config);  // 追踪config的字段值

// 场景3: 条件分支状态
if (secure_mode) {
    ctx.key_size = 256;
} else {
    ctx.key_size = 128;
}
encrypt(ctx);  // ctx.key_size = {256, 128} (多路径)
```

@File    :   state_tracker.py
@Contact :   mypandamail@163.com
@Author  :   mooo
@Version :   1.0
@Date    :   2026/1/26
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ObjectType(Enum):
    """对象类型"""
    CONTEXT = "context"           # EVP_CIPHER_CTX*, EVP_MD_CTX* 等上下文
    STRUCT = "struct"             # 结构体对象
    POINTER = "pointer"           # 指针变量
    REFERENCE = "reference"       # 引用变量
    PRIMITIVE = "primitive"       # 基本类型变量
    UNKNOWN = "unknown"


@dataclass
class FieldValue:
    """字段值"""
    name: str                     # 字段名
    value: Any                    # 值（可以是常量、变量名、表达式）
    type: str                     # 类型（int, str, etc.）
    line: int                     # 赋值行号
    confidence: float = 1.0       # 置信度 (0.0-1.0)


@dataclass
class MethodCall:
    """方法调用记录"""
    method: str                   # 方法名（如 "EVP_EncryptInit_ex"）
    args: List[Any]               # 参数列表
    line: int                     # 调用行号
    effects: Dict[str, Any] = field(default_factory=dict)  # 副作用（字段修改）


@dataclass
class ObjectState:
    """
    对象状态 - 追踪单个对象的完整状态
    
    Attributes:
        obj_id: 对象唯一标识（变量名、内存地址等）
        obj_type: 对象类型
        fields: 字段值映射 {field_name: FieldValue}
        methods: 方法调用历史 [MethodCall]
        aliases: 别名集合（指针/引用指向同一对象）
        parent: 父对象ID（用于嵌套结构体）
    """
    obj_id: str
    obj_type: ObjectType
    fields: Dict[str, FieldValue] = field(default_factory=dict)
    methods: List[MethodCall] = field(default_factory=list)
    aliases: Set[str] = field(default_factory=set)
    parent: Optional[str] = None
    
    def set_field(self, name: str, value: Any, type_str: str, line: int, confidence: float = 1.0):
        """设置字段值"""
        self.fields[name] = FieldValue(name, value, type_str, line, confidence)
    
    def get_field(self, name: str) -> Optional[FieldValue]:
        """获取字段值"""
        return self.fields.get(name)
    
    def add_method(self, method: str, args: List[Any], line: int, effects: Dict[str, Any] = None):
        """记录方法调用"""
        self.methods.append(MethodCall(method, args, line, effects or {}))
    
    def add_alias(self, alias: str):
        """添加别名"""
        self.aliases.add(alias)
        
    def merge_from(self, other: 'ObjectState', confidence: float = 0.5):
        """
        合并另一个状态（用于路径合并）
        
        策略：保留两个状态的字段，但降低置信度
        """
        for field_name, field_value in other.fields.items():
            if field_name not in self.fields:
                # 新字段，添加但降低置信度
                self.fields[field_name] = FieldValue(
                    field_value.name,
                    field_value.value,
                    field_value.type,
                    field_value.line,
                    confidence
                )
            else:
                # 冲突字段，创建多值
                existing = self.fields[field_name]
                if existing.value != field_value.value:
                    # 标记为多路径值
                    self.fields[field_name].value = {existing.value, field_value.value}
                    self.fields[field_name].confidence = min(existing.confidence, confidence)


@dataclass
class PathConstraint:
    """路径约束条件"""
    condition: str                # 条件表达式（如 "secure_mode == true"）
    line: int                     # 条件所在行号
    is_true_branch: bool          # True分支还是False分支


class StateSnapshot:
    """
    状态快照 - 程序点的全局状态
    
    包含所有对象的状态和路径约束
    """
    
    def __init__(self):
        self.objects: Dict[str, ObjectState] = {}
        self.constraints: List[PathConstraint] = []
        self.line: int = 0
    
    def get_or_create_object(self, obj_id: str, obj_type: ObjectType) -> ObjectState:
        """获取或创建对象状态"""
        if obj_id not in self.objects:
            self.objects[obj_id] = ObjectState(obj_id, obj_type)
        return self.objects[obj_id]
    
    def get_object(self, obj_id: str) -> Optional[ObjectState]:
        """获取对象状态"""
        # 直接查找
        if obj_id in self.objects:
            return self.objects[obj_id]
        
        # 通过别名查找
        for obj in self.objects.values():
            if obj_id in obj.aliases:
                return obj
        
        return None
    
    def add_constraint(self, condition: str, line: int, is_true_branch: bool):
        """添加路径约束"""
        self.constraints.append(PathConstraint(condition, line, is_true_branch))
    
    def clone(self) -> 'StateSnapshot':
        """克隆状态（用于路径分叉）"""
        import copy
        return copy.deepcopy(self)
    
    def merge(self, other: 'StateSnapshot', confidence: float = 0.5) -> 'StateSnapshot':
        """
        合并两个状态（用于路径汇合）
        
        策略：
        1. 合并对象状态（冲突字段标记为多值）
        2. 约束条件取交集（共同约束）
        """
        merged = StateSnapshot()
        merged.line = max(self.line, other.line)
        
        # 合并对象
        all_obj_ids = set(self.objects.keys()) | set(other.objects.keys())
        for obj_id in all_obj_ids:
            if obj_id in self.objects and obj_id in other.objects:
                # 两个状态都有，合并
                merged_obj = ObjectState(obj_id, self.objects[obj_id].obj_type)
                merged_obj.merge_from(self.objects[obj_id], confidence=1.0)
                merged_obj.merge_from(other.objects[obj_id], confidence=confidence)
                merged.objects[obj_id] = merged_obj
            elif obj_id in self.objects:
                # 只在当前状态，保留但降低置信度
                obj = self.objects[obj_id]
                for field in obj.fields.values():
                    field.confidence *= confidence
                merged.objects[obj_id] = obj
            else:
                # 只在other状态，保留但降低置信度
                obj = other.objects[obj_id]
                for field in obj.fields.values():
                    field.confidence *= confidence
                merged.objects[obj_id] = obj
        
        return merged


class StateTracker:
    """
    状态追踪器 - 管理程序执行过程中的状态变化
    
    功能：
    1. 追踪对象创建、赋值、方法调用
    2. 处理指针别名（a = &b, *a = 10）
    3. 处理条件分支（状态分叉和合并）
    4. 提取特定对象的字段值
    
    使用示例：
    ```python
    tracker = StateTracker()
    
    # 对象创建
    tracker.create_object("ctx", ObjectType.CONTEXT, line=10)
    
    # 方法调用（带副作用）
    tracker.record_method_call(
        "ctx", 
        "EVP_EncryptInit_ex",
        [None, "EVP_aes_256_gcm()", None, "key", "iv"],
        line=11,
        effects={"algorithm": "AES-256-GCM", "key_bits": 256}
    )
    
    # 字段赋值
    tracker.set_field("config", "key_bits", 2048, "int", line=15)
    
    # 获取字段值
    key_bits = tracker.get_field_value("config", "key_bits")  # 2048
    ```
    """
    
    def __init__(self):
        self.current_state = StateSnapshot()
        self.state_history: List[Tuple[int, StateSnapshot]] = []
        self.branch_stack: List[StateSnapshot] = []  # 用于处理分支
    
    def create_object(self, obj_id: str, obj_type: ObjectType, line: int):
        """创建对象"""
        obj = self.current_state.get_or_create_object(obj_id, obj_type)
        self.current_state.line = line
    
    def set_field(
        self,
        obj_id: str,
        field_name: str,
        value: Any,
        type_str: str,
        line: int,
        confidence: float = 1.0
    ):
        """设置对象字段"""
        obj = self.current_state.get_object(obj_id)
        if not obj:
            # 自动创建（假设为结构体）
            obj = self.current_state.get_or_create_object(obj_id, ObjectType.STRUCT)
        
        obj.set_field(field_name, value, type_str, line, confidence)
        self.current_state.line = line
    
    def get_field_value(self, obj_id: str, field_name: str) -> Optional[Any]:
        """获取对象字段值"""
        obj = self.current_state.get_object(obj_id)
        if obj:
            field = obj.get_field(field_name)
            if field:
                return field.value
        return None
    
    def record_method_call(
        self,
        obj_id: str,
        method: str,
        args: List[Any],
        line: int,
        effects: Dict[str, Any] = None
    ):
        """记录方法调用"""
        obj = self.current_state.get_object(obj_id)
        if not obj:
            obj = self.current_state.get_or_create_object(obj_id, ObjectType.CONTEXT)
        
        obj.add_method(method, args, line, effects or {})
        
        # 应用副作用（方法调用修改了对象状态）
        if effects:
            for field_name, value in effects.items():
                obj.set_field(field_name, value, "inferred", line)
        
        self.current_state.line = line
    
    def add_alias(self, target: str, alias: str):
        """添加别名（指针/引用）"""
        obj = self.current_state.get_object(target)
        if obj:
            obj.add_alias(alias)
    
    def branch_start(self, condition: str, line: int, is_true_branch: bool):
        """
        开始条件分支
        
        Args:
            condition: 条件表达式
            line: 分支所在行号
            is_true_branch: True分支还是False分支
        """
        # 保存当前状态
        self.branch_stack.append(self.current_state.clone())
        
        # 添加路径约束
        self.current_state.add_constraint(condition, line, is_true_branch)
    
    def branch_merge(self):
        """合并分支（if-else汇合）"""
        if not self.branch_stack:
            return
        
        # 弹出分支点状态
        branch_state = self.branch_stack.pop()
        
        # 合并当前状态和分支状态
        self.current_state = branch_state.merge(self.current_state)
    
    def save_snapshot(self, line: int):
        """保存状态快照"""
        self.state_history.append((line, self.current_state.clone()))
    
    def get_object_state(self, obj_id: str) -> Optional[ObjectState]:
        """获取对象的完整状态"""
        return self.current_state.get_object(obj_id)
    
    def extract_parameter_info(
        self,
        obj_id: str,
        param_name: str,
        func_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        提取参数信息（供参数追踪使用）
        
        Args:
            obj_id: 对象ID（可以是简单名或 scope-aware 名）
            param_name: 参数名
            func_name: 可选的函数作用域（用于 scope-aware 查找）
        
        Returns:
            {
                'value': 参数值,
                'line': 赋值行号,
                'confidence': 置信度,
                'source': 来源（'field', 'method', 'alias'）
            }
        """
        # 1. 尝试直接查找（完整 scope-aware ID）
        obj = self.current_state.get_object(obj_id)
        
        # 2. 如果未找到且提供了 func_name，尝试构建 scope-aware ID
        if not obj and func_name:
            scoped_id = f"{func_name}::{obj_id}"
            obj = self.current_state.get_object(scoped_id)
        
        # 3. 如果还是未找到，尝试查找所有匹配的对象（兼容旧代码）
        if not obj:
            # 尝试查找所有以 ::obj_id 结尾的对象
            for full_id, obj_state in self.current_state.objects.items():
                if full_id == obj_id or full_id.endswith(f"::{obj_id}"):
                    obj = obj_state
                    break
        
        if not obj:
            return None
        
        # 1. 从字段查找
        field = obj.get_field(param_name)
        if field:
            return {
                'value': field.value,
                'line': field.line,
                'confidence': field.confidence,
                'source': 'field'
            }
        
        # 2. 从方法调用副作用查找
        for method_call in reversed(obj.methods):
            if param_name in method_call.effects:
                return {
                    'value': method_call.effects[param_name],
                    'line': method_call.line,
                    'confidence': 0.8,  # 方法副作用置信度稍低
                    'source': 'method'
                }
        
        return None
