#!/usr/bin/env python3
"""
Object State Tracker: Track hidden state in ctx/receiver objects

用于追踪面向对象和上下文对象中的隐藏状态，解决如下场景：
1. Java: KeyGenerator keyGen = KeyGenerator.getInstance("AES"); keyGen.init(128);
2. C: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), ...);
3. Python: cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
"""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class StateOperation(Enum):
    """状态操作类型"""
    WRITE = "write"  # 写入状态
    READ = "read"    # 读取状态
    INIT = "init"    # 初始化对象


@dataclass
class ObjectState:
    """
    对象状态
    
    追踪单个对象（ctx、receiver、变量）的状态
    """
    object_id: str  # 对象标识（变量名、临时ID等）
    object_type: str  # 对象类型（如 "EVP_CIPHER_CTX"、"KeyGenerator"）
    
    # 状态字段
    state: Dict[str, Any] = field(default_factory=dict)
    
    # 来源追踪
    created_at: Optional[int] = None  # 创建行号
    last_modified: Optional[int] = None  # 最后修改行号
    
    def write_field(self, field_name: str, value: Any, line: Optional[int] = None):
        """写入字段"""
        self.state[field_name] = value
        self.last_modified = line
    
    def read_field(self, field_name: str) -> Optional[Any]:
        """读取字段"""
        return self.state.get(field_name)
    
    def has_field(self, field_name: str) -> bool:
        """检查字段是否存在"""
        return field_name in self.state
    
    def get_all_fields(self) -> Dict[str, Any]:
        """获取所有字段"""
        return self.state.copy()


class ObjectStateTracker:
    """
    对象状态追踪器
    
    维护所有对象的状态表，支持跨函数调用的状态传播
    
    使用示例:
        tracker = ObjectStateTracker()
        
        # Java 示例
        tracker.track_object_creation("keyGen1", "KeyGenerator", 
                                     {"algorithm": "AES"}, line=8)
        tracker.write_state("keyGen1", "key_bits", 128, line=9)
        
        state = tracker.get_object_state("keyGen1")
        # → {"algorithm": "AES", "key_bits": 128}
    """
    
    def __init__(self):
        # 对象状态表: object_id → ObjectState
        self.objects: Dict[str, ObjectState] = {}
        
        # 返回值追踪: call_id → object_id (用于追踪返回值)
        self.return_values: Dict[str, str] = {}
        
        # 调用历史（用于调试）
        self.call_history: List[Dict[str, Any]] = []
    
    def track_object_creation(
        self,
        object_id: str,
        object_type: str,
        initial_state: Optional[Dict[str, Any]] = None,
        line: Optional[int] = None
    ) -> ObjectState:
        """
        追踪对象创建
        
        Args:
            object_id: 对象标识（变量名）
            object_type: 对象类型
            initial_state: 初始状态
            line: 创建行号
        
        Returns:
            ObjectState
        """
        obj = ObjectState(
            object_id=object_id,
            object_type=object_type,
            state=initial_state or {},
            created_at=line,
            last_modified=line
        )
        self.objects[object_id] = obj
        return obj
    
    def write_state(
        self,
        object_id: str,
        field_name: str,
        value: Any,
        line: Optional[int] = None
    ):
        """
        写入对象状态
        
        Args:
            object_id: 对象标识
            field_name: 字段名
            value: 值
            line: 行号
        """
        if object_id not in self.objects:
            # 自动创建对象（如果不存在）
            self.track_object_creation(object_id, "unknown", line=line)
        
        self.objects[object_id].write_field(field_name, value, line)
        
        # 记录历史
        self.call_history.append({
            "operation": "write",
            "object_id": object_id,
            "field": field_name,
            "value": value,
            "line": line
        })
    
    def read_state(
        self,
        object_id: str,
        field_name: str
    ) -> Optional[Any]:
        """
        读取对象状态
        
        Args:
            object_id: 对象标识
            field_name: 字段名
        
        Returns:
            字段值或 None
        """
        if object_id not in self.objects:
            return None
        
        return self.objects[object_id].read_field(field_name)
    
    def get_object_state(self, object_id: str) -> Optional[Dict[str, Any]]:
        """
        获取对象的完整状态
        
        Args:
            object_id: 对象标识
        
        Returns:
            状态字典或 None
        """
        if object_id not in self.objects:
            return None
        
        return self.objects[object_id].get_all_fields()
    
    def track_return_value(
        self,
        call_id: str,
        returned_object_id: str
    ):
        """
        追踪函数返回值
        
        Args:
            call_id: 调用标识（如 "line_8_getInstance"）
            returned_object_id: 返回的对象ID
        """
        self.return_values[call_id] = returned_object_id
    
    def get_returned_object(self, call_id: str) -> Optional[str]:
        """获取调用返回的对象ID"""
        return self.return_values.get(call_id)
    
    def merge_states(
        self,
        target_id: str,
        source_id: str
    ):
        """
        合并对象状态（用于赋值、参数传递等）
        
        Args:
            target_id: 目标对象
            source_id: 源对象
        """
        if source_id not in self.objects:
            return
        
        source_state = self.objects[source_id].get_all_fields()
        
        if target_id not in self.objects:
            self.track_object_creation(
                target_id,
                self.objects[source_id].object_type,
                initial_state=source_state
            )
        else:
            # 合并状态
            for field, value in source_state.items():
                self.objects[target_id].write_field(field, value)
    
    def list_objects(self) -> List[str]:
        """列出所有追踪的对象"""
        return list(self.objects.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_objects": len(self.objects),
            "total_operations": len(self.call_history),
            "object_types": list(set(obj.object_type for obj in self.objects.values()))
        }
    
    def reset(self):
        """重置追踪器"""
        self.objects.clear()
        self.return_values.clear()
        self.call_history.clear()


def process_context_writes(
    tracker: ObjectStateTracker,
    object_id: str,
    context_writes: List[Dict[str, Any]],
    call_params: Dict[str, Any],
    line: Optional[int] = None
):
    """
    处理 context_writes（从 API 元数据）
    
    Args:
        tracker: 状态追踪器
        object_id: 对象ID（ctx或receiver）
        context_writes: API元数据中的 context_writes
        call_params: 调用参数
        line: 行号
    
    示例:
        context_writes = [
            {"object": "ctx", "field": "algorithm", "from": {"param": "cipher"}},
            {"object": "ctx", "field": "key_bits", "from": {"param": "key", "index": 3}, 
             "unit": "bytes", "transform": "bytes_to_bits"}
        ]
    """
    for write_spec in context_writes:
        field_name = write_spec.get("field")
        from_spec = write_spec.get("from", {})
        
        # 提取值
        value = None
        if "param" in from_spec:
            param_name = from_spec["param"]
            value = call_params.get(param_name)
            
            # 处理索引（如果是数组参数）
            if "index" in from_spec and isinstance(value, (list, tuple)):
                value = value[from_spec["index"]]
        
        # 转换（如果需要）
        transform = write_spec.get("transform")
        if transform == "bytes_to_bits" and value is not None:
            value = value * 8
        elif transform == "bits_to_bytes" and value is not None:
            value = value // 8
        
        # 写入状态
        if value is not None:
            tracker.write_state(object_id, field_name, value, line)


def process_context_reads(
    tracker: ObjectStateTracker,
    object_id: str,
    context_reads: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    处理 context_reads（从 API 元数据）
    
    Args:
        tracker: 状态追踪器
        object_id: 对象ID
        context_reads: API元数据中的 context_reads
    
    Returns:
        读取的状态字典
    """
    result = {}
    for read_spec in context_reads:
        field_name = read_spec.get("field")
        value = tracker.read_state(object_id, field_name)
        if value is not None:
            result[field_name] = value
    
    return result


if __name__ == "__main__":
    # 测试
    tracker = ObjectStateTracker()
    
    print("Object State Tracker Test")
    print("="*80)
    
    # 场景1: Java KeyGenerator
    print("\n场景1: Java KeyGenerator")
    print("-"*80)
    
    # Line 8: KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    tracker.track_object_creation("keyGen", "KeyGenerator", 
                                 {"algorithm": "AES"}, line=8)
    print("Line 8: Created keyGen with algorithm=AES")
    
    # Line 9: keyGen.init(128);
    tracker.write_state("keyGen", "key_bits", 128, line=9)
    print("Line 9: Set key_bits=128")
    
    state = tracker.get_object_state("keyGen")
    print(f"Final state: {state}")
    
    # 场景2: C EVP_CIPHER_CTX
    print("\n场景2: C EVP_CIPHER_CTX")
    print("-"*80)
    
    # Line 10: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    tracker.track_object_creation("ctx", "EVP_CIPHER_CTX", line=10)
    print("Line 10: Created ctx")
    
    # Line 11: EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    tracker.write_state("ctx", "algorithm", "AES", line=11)
    tracker.write_state("ctx", "key_bits", 256, line=11)
    tracker.write_state("ctx", "mode", "GCM", line=11)
    print("Line 11: Initialized with AES-256-GCM")
    
    state = tracker.get_object_state("ctx")
    print(f"Final state: {state}")
    
    # 统计
    print("\n" + "="*80)
    print("Statistics:")
    stats = tracker.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
