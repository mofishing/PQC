"""
SSA Call Analyzer
将 AST 调用转换为 SSA 形式，支持多语言
"""

from typing import Dict, List, Optional, Any
from ..symbolic.ssa_object_tracker import (
    SSAObjectTracker, SSAVariableNamer, SSAVariable
)
from ..abstract_syntax_tree.extractor import extract_calls
from ..abstract_syntax_tree.parser import get_parser


class SSACallAnalyzer:
    """
    SSA 调用分析器
    
    将 AST 级别的调用信息转换为 SSA 形式
    
    职责：
    1. 追踪变量的赋值和使用
    2. 为每次赋值创建新的 SSA 版本
    3. 识别对象创建、别名、状态写入
    
    支持场景：
    - C: ctx = EVP_CIPHER_CTX_new()
    - Java: Cipher cipher = Cipher.getInstance(...)
    - Python: ctx = hashlib.sha256()
    - Go: ctx := sha256.New()
    """
    
    def __init__(self, language: str):
        self.language = language
        self.ssa_namer = SSAVariableNamer()
        self.ssa_tracker = SSAObjectTracker()
    
    def analyze_file(self, code: str) -> SSAObjectTracker:
        """
        分析整个文件
        
        Args:
            code: 源代码
        
        Returns:
            SSA 对象追踪器
        """
        # 重置
        self.ssa_namer.reset()
        self.ssa_tracker.reset()
        
        # 解析 AST
        parser = get_parser(self.language)
        if not parser:
            return self.ssa_tracker
        
        tree = parser.parse(bytes(code, 'utf-8'))
        root = tree.root_node
        
        # 提取所有调用
        calls = extract_calls(root, code, self.language)
        
        # 按行号排序（模拟执行顺序）
        calls = sorted(calls, key=lambda c: c.get('line', 0))
        
        # 分析每个调用
        for call in calls:
            self._analyze_call(call, code)
        
        return self.ssa_tracker
    
    def _analyze_call(self, call: Dict[str, Any], code: str):
        """
        分析单个调用
        
        识别：
        1. 对象创建：assigned_to 存在，且调用是构造函数
        2. 别名：assigned_to 存在，且右值是变量
        3. 状态写入：通过 API metadata 的 context_writes
        """
        symbol = call.get('symbol') or call.get('name', '')
        line = call.get('line', -1)
        assigned_to = call.get('assigned_to')  # 左值变量名
        args = call.get('args', [])
        
        # 检查是否是对象创建调用
        is_object_creation = self._is_object_creation_call(symbol, self.language)
        
        if assigned_to and is_object_creation:
            # 场景 1: ctx = EVP_CIPHER_CTX_new()
            self._handle_object_creation(assigned_to, symbol, line)
        
        elif assigned_to and not is_object_creation:
            # 场景 2: ctx = other_ctx  (可能是别名)
            # 检查右值是否是变量
            if self._is_simple_assignment(call):
                source_var = self._extract_source_variable(call)
                if source_var:
                    self._handle_alias(assigned_to, source_var, line)
                else:
                    # 未知类型的赋值，作为新对象处理
                    self._handle_object_creation(assigned_to, "Unknown", line)
        
        else:
            # 场景 3: 使用现有对象（如 EVP_EncryptInit_ex(ctx, ...)）
            # 检查第一个参数是否是 context 对象
            if args:
                ctx_arg = args[0]
                ctx_var_name = ctx_arg.get('text')
                
                if ctx_var_name and self._looks_like_context_variable(ctx_var_name):
                    # 获取当前 SSA 版本
                    ssa_var = self.ssa_namer.get_current_version(ctx_var_name)
                    
                    if ssa_var:
                        # 这是一个状态写入（稍后会通过 API metadata 详细处理）
                        # 这里先记录使用事件
                        pass
    
    def _is_object_creation_call(self, symbol: str, language: str) -> bool:
        """
        判断是否是对象创建调用
        
        规则：
        - C: *_new(), *_create(), *_init()
        - Java: getInstance(), new *()
        - Python: *() (类构造函数)
        - Go: New*(), Make*()
        """
        symbol_lower = symbol.lower()
        
        if language == 'c':
            return (
                '_new' in symbol_lower or
                '_create' in symbol_lower or
                '_init' in symbol_lower or
                'EVP_CIPHER_CTX' in symbol or
                'EVP_MD_CTX' in symbol
            )
        
        elif language == 'java':
            return (
                'getInstance' in symbol or
                'new ' in symbol or
                '.create' in symbol_lower
            )
        
        elif language == 'python':
            # Python 中很难判断，需要更多上下文
            return (
                symbol.istitle() or  # 首字母大写（类名）
                '.new' in symbol_lower or
                'hashlib.' in symbol
            )
        
        elif language == 'go':
            return (
                symbol.startswith('New') or
                symbol.startswith('Make')
            )
        
        return False
    
    def _is_simple_assignment(self, call: Dict[str, Any]) -> bool:
        """判断是否是简单的变量赋值（ctx = other_ctx）"""
        args = call.get('args', [])
        
        # 如果没有调用符号，或者符号为空，可能是简单赋值
        symbol = call.get('symbol') or call.get('name', '')
        
        # 简单赋值没有函数调用
        return not symbol or len(args) == 0
    
    def _extract_source_variable(self, call: Dict[str, Any]) -> Optional[str]:
        """从赋值中提取源变量名"""
        # 这需要更详细的 AST 分析
        # 暂时返回 None
        return None
    
    def _looks_like_context_variable(self, var_name: str) -> bool:
        """判断变量名是否看起来像 context 变量"""
        var_lower = var_name.lower()
        return (
            'ctx' in var_lower or
            'context' in var_lower or
            'cipher' in var_lower or
            'hash' in var_lower or
            'md' in var_lower or
            'evp' in var_lower
        )
    
    def _handle_object_creation(self, var_name: str, object_type: str, line: int):
        """处理对象创建"""
        # 创建新的 SSA 版本
        ssa_var = self.ssa_namer.get_next_version(var_name, line)
        
        # 追踪对象创建
        self.ssa_tracker.track_object_creation(ssa_var, object_type, line)
    
    def _handle_alias(self, new_var_name: str, source_var_name: str, line: int):
        """处理别名创建"""
        # 为新变量创建 SSA 版本
        new_ssa_var = self.ssa_namer.get_next_version(new_var_name, line)
        
        # 获取源变量的当前 SSA 版本
        source_ssa_var = self.ssa_namer.get_current_version(source_var_name)
        
        if source_ssa_var:
            # 追踪别名
            self.ssa_tracker.track_alias(new_ssa_var, source_ssa_var, line)
    
    def write_object_state(
        self,
        var_name: str,
        field: str,
        value: Any,
        line: int
    ):
        """
        写入对象状态（供外部调用）
        
        这个方法会被 Scanner 调用，基于 API metadata 的 context_writes
        """
        # 获取变量的当前 SSA 版本
        ssa_var = self.ssa_namer.get_current_version(var_name)
        
        if ssa_var:
            self.ssa_tracker.write_object_state(ssa_var, field, value, line)
    
    def read_object_state(
        self,
        var_name: str,
        field: Optional[str] = None
    ) -> Any:
        """
        读取对象状态（供外部调用）
        """
        ssa_var = self.ssa_namer.get_current_version(var_name)
        
        if ssa_var:
            return self.ssa_tracker.read_object_state(ssa_var, field)
        
        return None
    
    def get_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        return self.ssa_tracker.summary()


def analyze_with_ssa(code: str, language: str) -> Dict[str, Any]:
    """
    便捷函数：使用 SSA 分析代码
    
    Args:
        code: 源代码
        language: 语言（'c', 'java', 'python', 'go'）
    
    Returns:
        分析摘要
    """
    analyzer = SSACallAnalyzer(language)
    tracker = analyzer.analyze_file(code)
    return tracker.summary()
