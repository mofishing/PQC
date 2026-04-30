"""
Candidate Data Structures
候选漏洞点数据结构
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


class APIType(Enum):
    """API 类型枚举"""
    CIPHER = "cipher"           # 对称加密
    ASYMMETRIC = "asymmetric"   # 非对称加密
    HASH = "hash"               # 哈希
    MAC = "mac"                 # 消息认证码
    KDF = "kdf"                 # 密钥派生
    RANDOM = "random"           # 随机数生成
    SIGNATURE = "signature"     # 数字签名
    UNKNOWN = "unknown"


@dataclass
class Location:
    """源代码位置"""
    file: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    
    def __str__(self) -> str:
        if self.end_line:
            return f"{self.file}:{self.line}:{self.column}-{self.end_line}:{self.end_column}"
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class Scope:
    """作用域信息"""
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    module_name: Optional[str] = None
    
    # 作用域层次
    scope_level: int = 0  # 0=global, 1=function, 2=block...
    
    # 父作用域
    parent: Optional['Scope'] = None


@dataclass
class CallContext:
    """调用上下文"""
    # 调用表达式
    call_expr: str
    
    # 参数（位置参数和关键字参数）
    positional_args: List[str] = field(default_factory=list)
    keyword_args: Dict[str, str] = field(default_factory=dict)
    
    # 返回值使用情况
    assigned_to: Optional[str] = None  # 如: cipher = AES.new(...)
    
    # 调用链
    caller: Optional[str] = None  # 调用者函数


@dataclass
class Candidate:
    """
    候选漏洞点
    
    Phase 1 (AST) 输出的候选集元素，包含：
    - 基本位置信息
    - API 类型和符号
    - AST 上下文（为 Phase 2 保留）
    - 初步提取的字面量参数
    """
    
    # ===== 基本信息 =====
    location: Location
    symbol: str              # API 名称，如 EVP_EncryptInit_ex
    api_type: APIType       # API 类型
    language: str           # 语言 (c/python/go/java)
    
    # ===== AST 上下文（为 Phase 2 保留）=====
    ast_node: Any           # Tree-sitter 节点（保留原始 AST）
    scope: Scope           # 作用域信息
    call_context: CallContext  # 调用上下文
    
    # 周边代码（用于符号执行）
    context_lines: List[Tuple[int, str]] = field(default_factory=list)  # [(行号, 代码)]
    
    # ===== Phase 1 初步提取的信息 =====
    literal_args: Dict[str, Any] = field(default_factory=dict)  # 字面量参数
    # 例如: {'key_size': 128, 'mode': 'CBC'}
    
    assigned_to: Optional[str] = None  # ★ 新增：赋值目标（如 ctx = EVP_CIPHER_CTX_new()）
    
    # 置信度（Phase 1 模式匹配的可信度）
    confidence: float = 1.0  # 0.0 - 1.0
    
    # ===== 元数据 =====
    profile_id: Optional[str] = None  # KB 中的 profile ID
    matched_rules: List[Dict[str, Any]] = field(default_factory=list)  # Phase 1 matched KB rules
    tags: List[str] = field(default_factory=list)  # 标签，如 ['weak_key', 'deprecated']
    
    def __str__(self) -> str:
        return f"Candidate({self.symbol} at {self.location}, confidence={self.confidence:.2f})"
    
    @property
    def function(self) -> str:
        """Alias for symbol (backward compatibility)."""
        return self.symbol
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于序列化）"""
        return {
            'location': {
                'file': self.location.file,
                'line': self.location.line,
                'column': self.location.column,
            },
            'symbol': self.symbol,
            'api_type': self.api_type.value,
            'language': self.language,
            'literal_args': self.literal_args,
            'confidence': self.confidence,
            'profile_id': self.profile_id,
            'tags': self.tags,
        }


@dataclass
class CandidateSet:
    """
    候选集合（Phase 1 输出）
    """
    file: str
    language: str
    candidates: List[Candidate] = field(default_factory=list)
    
    # 统计信息
    total_apis_found: int = 0  # 找到的 API 总数
    
    def add(self, candidate: Candidate):
        """添加候选点"""
        self.candidates.append(candidate)
        self.total_apis_found += 1
    
    def filter_by_type(self, api_type: APIType) -> List[Candidate]:
        """按类型过滤"""
        return [c for c in self.candidates if c.api_type == api_type]
    
    def filter_by_confidence(self, min_confidence: float) -> List[Candidate]:
        """按置信度过滤"""
        return [c for c in self.candidates if c.confidence >= min_confidence]
    
    def __len__(self) -> int:
        return len(self.candidates)
    
    def __iter__(self):
        return iter(self.candidates)
    
    def to_dict(self) -> Dict[str, Any]:
        """序列化"""
        return {
            'file': self.file,
            'language': self.language,
            'total_apis_found': self.total_apis_found,
            'candidates': [c.to_dict() for c in self.candidates]
        }
