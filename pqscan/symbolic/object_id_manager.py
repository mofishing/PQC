"""
对象ID管理器：基于分配点（alloc site）的版本化对象追踪

核心思想：
- ObjectID = (alloc_site, version)
- 新对象：分配新ID（基于行号/AST节点）
- 别名：解析到同一对象ID
- 跨函数：参数绑定到调用者的对象ID

这是 SSA-like 的轻量级实现，不需要完整的 SSA IR。

扩展功能（P0+P1）：
- 对象状态存储：ObjectID -> state dict
- 赋值事件处理：process_assignment()
- 状态读写：write_state(), read_state()
"""

from typing import Dict, Optional, Set, Tuple, Any, List, Union
from dataclasses import dataclass, field
from enum import Enum


class AssignmentKind(Enum):
    """赋值类型"""
    ALLOCATOR = "allocator"  # 新对象分配：ctx = new()
    ALIAS = "alias"          # 别名赋值：ctx = ctx1
    UNKNOWN = "unknown"      # 未知类型


@dataclass
class AssignmentEvent:
    """赋值事件（从 AST 提取）"""
    line: int               # 行号
    lhs: str                # 左值变量名
    rhs_kind: str           # "call", "var", "literal"
    rhs: str                # 右值（函数名、变量名、字面量）
    scope: str = "global"   # 作用域（函数名）


@dataclass
class ObjectInfo:
    """对象信息"""
    object_id: str  # 唯一标识符，如 "obj#17"
    alloc_site: str  # 分配位置：行号或AST节点ID
    version: int  # 版本号（同一分配点的第N次分配）
    object_type: Optional[str] = None  # 对象类型（如 EVP_CIPHER_CTX）
    created_at: Optional[int] = None  # 创建行号
    state: Dict[str, Any] = field(default_factory=dict)  # 对象状态（新增）
    

class ObjectIDManager:
    """
    对象ID管理器（轻量级别名追踪 + 版本化 + 状态追踪）
    
    功能：
    1. 新对象分配：基于 alloc_site 生成唯一 object_id
    2. 别名追踪：ctx = ctx1 → ctx 指向 ctx1 的对象（带作用域隔离）
    3. 版本管理：同一变量重新赋值创建新对象
    4. 跨函数绑定：参数传递时绑定到调用者的对象
    5. 对象状态管理：write_state(), read_state()
    6. 赋值事件处理：process_assignment()
    
    关键改进（修复版本）：
    - ✅ 作用域隔离：var_to_object 使用 (scope, var_name) 作为 key
    - ✅ ObjectID 格式：{alloc_site}@v{version}（可读，可追溯）
    - ✅ C 语言 allocator 使用严格白名单（禁用模糊匹配）
    - ✅ alias RHS 未绑定时返回 None（不创建虚假对象）
    - ✅ param_bindings 使用直接索引（O(1) 查找）
    
    使用示例：
        manager = ObjectIDManager()
        
        # 新对象分配
        obj_id = manager.allocate_object('ctx', 'line_10_EVP_CIPHER_CTX_new', 'EVP_CIPHER_CTX', scope='main')
        # → "line_10_EVP_CIPHER_CTX_new@v1"
        
        # 别名赋值
        manager.bind_alias('ctx2', 'ctx', scope='main')
        # ctx2 → line_10_EVP_CIPHER_CTX_new@v1
        
        # 解析对象ID（带作用域）
        obj_id = manager.resolve('ctx2', scope='main')
        # → "line_10_EVP_CIPHER_CTX_new@v1"
        
        # 写入对象状态
        manager.write_state('line_10_EVP_CIPHER_CTX_new@v1', 'algorithm', 'AES-256-GCM')
        
        # 读取对象状态
        algo = manager.read_state('line_10_EVP_CIPHER_CTX_new@v1', 'algorithm')
        # → "AES-256-GCM"
    """
    
    def __init__(self):
        # ★ 修改1：作用域隔离 - 变量名 → 对象ID 映射（使用 (scope, var_name) 作为 key）
        self.var_to_object: Dict[Tuple[str, str], str] = {}
        
        # 对象ID → 对象信息
        self.objects: Dict[str, ObjectInfo] = {}
        
        # alloc_site → 版本计数
        self.alloc_site_versions: Dict[str, int] = {}
        
        # ★ 修改4：跨函数参数绑定 - 使用直接索引（O(1) 查找）
        # 结构：(callee_func, param_name) -> {callsite_id: ObjectID}
        self.param_bindings: Dict[Tuple[str, str], Dict[str, str]] = {}
        
        # 已知的对象分配函数（allocators）- 按语言严格分类
        self.allocators = self._init_allocators()
        
        # 当前作用域（用于跨函数分析）
        self.current_scope = "global"
    
    def _init_allocators(self) -> Dict[str, Set[str]]:
        """
        初始化已知的对象分配函数列表（按语言分类）
        
        ★ 修改2：C 语言使用严格白名单，禁用模糊匹配
        
        返回格式：{language: {allocator_functions}}
        """
        return {
            'c': {
                # OpenSSL EVP - 严格白名单
                'EVP_CIPHER_CTX_new',
                'EVP_MD_CTX_new', 
                'EVP_PKEY_CTX_new',
                'EVP_PKEY_new',
                'EVP_MAC_CTX_new',
                'EVP_ENCODE_CTX_new',
                'EVP_KDF_CTX_new',
                
                # OpenSSL 其他
                'BN_new',
                'BIO_new',
                'RSA_new',
                'DSA_new',
                'DH_new',
                'EC_KEY_new',
                'X509_new',
                'PKCS12_new',
                
                # 通用分配（只保留标准库）
                'malloc',
                'calloc',
                'realloc',
            },
            
            'java': {
                # JCA - 需要结合 receiver 判断
                # 单独 getInstance 不算，必须是 Cipher.getInstance 等
            },
            
            'python': {
                # Cryptography.io
                # 需要结合模块/类名判断
            },
            
            'go': {
                # crypto/cipher 包
                # 格式：cipher.NewGCM, cipher.NewCBCEncrypter
                # 需要检查包路径
            }
        }
    
    def is_allocator(self, func_name: str, language: Optional[str] = None, 
                     receiver: Optional[str] = None, module: Optional[str] = None) -> bool:
        """
        判断函数是否是对象分配函数（严格版本）
        
        ★ 修改2：C 语言只用白名单，禁用模糊匹配
        
        Args:
            func_name: 函数名（如 "getInstance", "EVP_CIPHER_CTX_new"）
            language: 语言（c/java/python/go）
            receiver: 接收者/类名（Java: "Cipher", Python: "AES"）
            module: 模块/包（Python: "Crypto.Cipher", Go: "crypto/cipher"）
        
        Returns:
            bool: 是否是对象分配函数
        """
        if not func_name:
            return False
        
        # 策略1: C 语言 - 只用严格白名单（禁用模糊匹配）
        if language == 'c' or (language is None and '_' in func_name):
            # 严格匹配白名单
            c_allocators = self.allocators.get('c', set())
            return func_name in c_allocators
        
        # 策略2: Java - 需要上下文（receiver）
        if language == 'java':
            # 只有加密相关类的 getInstance 才算
            if func_name == 'getInstance' and receiver:
                crypto_classes = {
                    'Cipher', 'KeyGenerator', 'KeyAgreement', 
                    'Mac', 'MessageDigest', 'Signature',
                    'KeyFactory', 'KeyPairGenerator', 'SecretKeyFactory'
                }
                return receiver in crypto_classes
            return False
        
        # 策略3: Python - 需要上下文（module）+ 函数名
        if language == 'python':
            if module and func_name:
                crypto_modules = {
                    'Crypto.Cipher', 'Crypto.Hash', 'Crypto.PublicKey',
                    'cryptography.hazmat.primitives.ciphers',
                    'cryptography.hazmat.primitives.hashes',
                }
                # 模块匹配 + 函数名像是构造函数（new/New）
                if any(module.startswith(m) for m in crypto_modules):
                    return func_name in {'new', 'New', 'AES', 'DES', 'RSA'}
            return False
        
        # 策略4: Go - 需要上下文（module）+ 函数名
        if language == 'go':
            if module and func_name:
                crypto_packages = {
                    'crypto/cipher', 'crypto/aes', 'crypto/des',
                    'crypto/rsa', 'crypto/ecdsa', 'crypto/hmac',
                }
                # 包匹配 + 函数名像是构造函数（New*/Create*）
                if module in crypto_packages:
                    return func_name.startswith('New') or func_name.startswith('Create')
            return False
        
        # 策略5: 未知语言 - 只匹配白名单（不做模糊匹配）
        for lang_allocators in self.allocators.values():
            if func_name in lang_allocators:
                return True
        
        return False
    
    def allocate_object(
        self, 
        var_name: str, 
        alloc_site: str,
        scope: str,
        object_type: Optional[str] = None,
        line: Optional[int] = None
    ) -> str:
        """
        分配新对象
        
        ★ 修改：
        1. 添加 scope 参数（作用域隔离）
        2. ObjectID 格式改为 {alloc_site}@v{version}（可追溯）
        3. 删除冗余的 object_state 赋值
        
        Args:
            var_name: 变量名
            alloc_site: 分配位置（函数名或行号，如 "EVP_CIPHER_CTX_new", "line_42"）
            scope: 作用域（函数名，如 "main", "encrypt"）
            object_type: 对象类型
            line: 行号
        
        Returns:
            object_id: 对象ID（如 "EVP_CIPHER_CTX_new@v1"）
        """
        # 生成版本号
        version = self.alloc_site_versions.get(alloc_site, 0) + 1
        self.alloc_site_versions[alloc_site] = version
        
        # 生成新格式 ObjectID: {alloc_site}@v{version}
        object_id = f"{alloc_site}@v{version}"
        
        # 创建对象信息
        obj_info = ObjectInfo(
            object_id=object_id,
            alloc_site=alloc_site,
            version=version,
            object_type=object_type,
            created_at=line,
            state={}  # 状态只在这里维护
        )
        self.objects[object_id] = obj_info
        
        # 绑定变量到对象（使用作用域）
        self.var_to_object[(scope, var_name)] = object_id
        
        return object_id
    
    def bind_alias(self, lhs: str, rhs: str, scope: str) -> Optional[str]:
        """
        绑定别名：lhs = rhs
        
        ★ 修改3：RHS 未绑定时返回 None（不创建虚假对象）
        ★ 修改1：使用 scope 参数（作用域隔离）
        
        Args:
            lhs: 左值变量名
            rhs: 右值变量名
            scope: 作用域（函数名）
        
        Returns:
            object_id: lhs 绑定的对象ID，如果 rhs 未绑定则返回 None
        """
        rhs_object_id = self.resolve(rhs, scope)
        
        if rhs_object_id:
            self.var_to_object[(scope, lhs)] = rhs_object_id
            return rhs_object_id
        
        # ★ 关键修改：RHS 未绑定时返回 None，不创建虚假对象
        return None
    
    def resolve(self, var_name: str, scope: str) -> Optional[str]:
        """
        解析变量名到对象ID
        
        ★ 修改1：使用 scope 参数（作用域隔离）
        ★ 修改4：添加 global fallback（支持 C 语言函数名错误）
        
        Args:
            var_name: 变量名
            scope: 作用域（函数名）
        
        Returns:
            object_id: 对象ID，如果未绑定则返回 None
        """
        # 1. 优先在指定 scope 查找
        result = self.var_to_object.get((scope, var_name))
        if result:
            return result
        
        # 2. Fallback: 在 'global' scope 查找
        # 解决 C 语言函数名提取错误（'void' vs 实际函数名）
        if scope != 'global':
            result = self.var_to_object.get(('global', var_name))
            if result:
                return result
        
        return None
    
    def bind_parameter(self, caller_func: str, callee_func: str, 
                      param_name: str, arg_var_name: str) -> Optional[str]:
        """
        跨函数参数绑定：caller_func 调用 callee_func(arg_var) → param_name 绑定到 arg_var 的对象
        
        ★ 修改4：使用新的 param_bindings 结构（O(1) 查找）
        
        Args:
            caller_func: 调用方函数名
            callee_func: 被调用方函数名
            param_name: 函数参数名
            arg_var_name: 调用处的实参变量名
        
        Returns:
            object_id: 绑定的对象ID
        """
        # 先解析 arg_var 在 caller_func 作用域的对象
        arg_object_id = self.resolve(arg_var_name, caller_func)
        
        if arg_object_id:
            # 使用新结构存储：(callee_func, param_name) -> {caller_func: arg_object_id}
            key = (callee_func, param_name)
            if key not in self.param_bindings:
                self.param_bindings[key] = {}
            self.param_bindings[key][caller_func] = arg_object_id
            
            # 同时在 callee_func 作用域绑定 param_name
            self.var_to_object[(callee_func, param_name)] = arg_object_id
            
            return arg_object_id
        
        return None
    
    def get_object_info(self, object_id: str) -> Optional[ObjectInfo]:
        """获取对象信息"""
        return self.objects.get(object_id)
    
    def list_objects(self) -> list:
        """列出所有对象ID"""
        return list(self.objects.keys())
    
    def reset(self):
        """重置所有状态"""
        self.var_to_object.clear()
        self.objects.clear()
        self.alloc_site_versions.clear()
        self.param_bindings.clear()
        self.current_scope = "global"
    
    # ============ 新增方法（P0+P1）============
    
    def process_assignment(self, event: AssignmentEvent, language: Optional[str] = None,
                          receiver: Optional[str] = None, module: Optional[str] = None) -> Optional[str]:
        """
        处理赋值事件（核心逻辑）
        
        ★ 修改：使用 event.scope + 新的 allocator 判定 + 修复虚假对象问题
        
        规则：
        1. allocator: ctx = new() → 分配新 ObjectID（version++）
        2. alias: ctx = ctx1 → var_to_object[ctx] = var_to_object[ctx1]
        3. unknown: 保留旧绑定（不创建虚假对象）
        
        Args:
            event: 赋值事件（包含 scope）
            language: 语言（c/java/python/go）
            receiver: 接收者/类名
            module: 模块/包名
        
        Returns:
            ObjectID: 分配的对象ID（如果是新对象）
        """
        lhs = event.lhs
        scope = event.scope or "global"
        
        # 判断赋值类型
        if event.rhs_kind == "call" and self.is_allocator(event.rhs, language, receiver, module):
            # allocator: ctx = EVP_CIPHER_CTX_new()
            alloc_site = event.rhs  # 使用函数名作为 alloc_site
            object_id = self.allocate_object(
                lhs, alloc_site, scope, event.rhs, event.line
            )
            return object_id
        
        elif event.rhs_kind == "var":
            # alias: ctx = ctx1
            rhs_var = event.rhs
            rhs_object_id = self.resolve(rhs_var, scope)
            
            if rhs_object_id:
                # 别名绑定到同一对象
                self.var_to_object[(scope, lhs)] = rhs_object_id
                return rhs_object_id
            else:
                # ★ 关键修改：RHS 未绑定时返回 None（不创建虚假对象）
                return None
        
        # unknown: 保留旧绑定或忽略
        return None
    
    def write_state(
        self, 
        object_id: str, 
        field: str, 
        value: Any,
        line: Optional[int] = None
    ):
        """
        写入对象状态
        
        ★ 修改：删除冗余的 object_state 操作（只用 ObjectInfo.state）
        
        Args:
            object_id: 对象ID
            field: 字段名
            value: 值
            line: 行号
        """
        if object_id in self.objects:
            self.objects[object_id].state[field] = value
    
    def read_state(
        self, 
        object_id: str, 
        field: str
    ) -> Optional[Any]:
        """
        读取对象状态
        
        ★ 修改：删除冗余的 object_state 操作（只用 ObjectInfo.state）
        
        Args:
            object_id: 对象ID
            field: 字段名
        
        Returns:
            字段值或 None
        """
        if object_id in self.objects:
            return self.objects[object_id].state.get(field)
        return None
    
    def get_all_state(self, object_id: str) -> Dict[str, Any]:
        """
        获取对象的所有状态
        
        ★ 修改：删除冗余的 object_state 操作（只用 ObjectInfo.state）
        """
        if object_id in self.objects:
            return self.objects[object_id].state
        return {}

    
    def set_scope(self, scope: str):
        """设置当前作用域"""
        self.current_scope = scope
    
    # ============ 已废弃方法（保留兼容性）============
    
    def bind_parameter_enhanced(
        self, 
        callee_func: str,
        param_name: str,
        arg_var_name: str,
        callsite_id: str,
        caller_func: Optional[str] = None
    ) -> Optional[str]:
        """
        跨函数参数绑定（增强版）
        
        ⚠️ 已废弃：请使用 bind_parameter(caller_func, callee_func, param_name, arg_var_name)
        保留此方法仅用于向后兼容
        
        Args:
            callee_func: 被调用函数名
            param_name: 参数名
            arg_var_name: 实参变量名
            callsite_id: 调用点ID（如 "line_25"）
            caller_func: 调用方函数名（可选）
        
        Returns:
            ObjectID
        """
        caller = caller_func or self.current_scope
        return self.bind_parameter(caller, callee_func, param_name, arg_var_name)
    
    def resolve_with_scope(
        self, 
        var_name: str, 
        scope: Optional[str] = None
    ) -> Optional[str]:
        """
        解析变量名到对象ID（带作用域支持）
        
        ⚠️ 已废弃：请直接使用 resolve(var_name, scope)
        保留此方法仅用于向后兼容
        
        Args:
            var_name: 变量名
            scope: 作用域
        
        Returns:
            ObjectID 或 None
        """
        target_scope = scope or self.current_scope
        return self.resolve(var_name, target_scope)

    
    # ============ P1: 统一 ctx 解析入口 ============
    
    def resolve_ctx_arg(
        self,
        arg: Union[str, Dict[str, Any]],
        scope: str,
        language: str = 'c'
    ) -> Optional[str]:
        """
        统一解析 ctx 参数（支持变量/指针/字段/函数调用）
        
        ★ P1 优先级：ctx 参数的统一入口
        
        支持的 ctx 形式：
        1. 简单变量：ctx → resolve(ctx, scope)
        2. 指针解引用：*ctx → resolve(ctx, scope)
        3. 字段访问：obj->ctx, obj.ctx → resolve(obj, scope) + 字段
        4. 函数调用：get_ctx() → 需要追踪返回值
        5. 数组元素：ctx[0] → resolve(ctx, scope)
        
        Args:
            arg: 参数（字符串或字典）
                - str: "ctx", "*ctx", "obj->field"
                - dict: {"text": "ctx", "type": "identifier"}
            scope: 作用域（函数名）
            language: 语言（c/java/python/go）
        
        Returns:
            ObjectID 或 None
        
        Examples:
            >>> resolve_ctx_arg("ctx", "main", "c")
            'EVP_CIPHER_CTX_new@v1'
            
            >>> resolve_ctx_arg("*ctx", "main", "c")
            'EVP_CIPHER_CTX_new@v1'
            
            >>> resolve_ctx_arg({"text": "obj->ctx", "type": "field_access"}, "main", "c")
            'EVP_CIPHER_CTX_new@v1'
        """
        # 1. 统一格式：转为字符串
        if isinstance(arg, dict):
            arg_text = arg.get('text', '')
            arg_type = arg.get('type', 'identifier')
            
            # 处理嵌套调用
            if 'nested_call' in arg:
                # get_ctx() → 需要追踪函数返回值（暂不支持）
                return None
        else:
            arg_text = str(arg)
            arg_type = 'identifier'
        
        if not arg_text:
            return None
        
        # 2. 去除空白
        arg_text = arg_text.strip()
        
        # 3. 处理指针解引用：*ctx → ctx
        if arg_text.startswith('*'):
            arg_text = arg_text[1:].strip()
        
        # 4. 处理字段访问
        if '->' in arg_text:
            # C: obj->field
            parts = arg_text.split('->')
            base_var = parts[0].strip()
            # 暂时只解析 base_var（字段访问需要更复杂的追踪）
            return self.resolve(base_var, scope)
        
        if '.' in arg_text and language in ['java', 'python', 'go']:
            # Java/Python/Go: obj.field
            parts = arg_text.split('.')
            base_var = parts[0].strip()
            return self.resolve(base_var, scope)
        
        # 5. 处理数组访问：ctx[0] → ctx
        if '[' in arg_text:
            base_var = arg_text.split('[')[0].strip()
            return self.resolve(base_var, scope)
        
        # 6. 处理取地址：&ctx → ctx
        if arg_text.startswith('&'):
            arg_text = arg_text[1:].strip()
        
        # 7. 简单变量：直接解析
        return self.resolve(arg_text, scope)
    
    def __repr__(self):
        return (
            f"ObjectIDManager(\n"
            f"  objects={len(self.objects)},\n"
            f"  bindings={len(self.var_to_object)},\n"
            f"  param_bindings={len(self.param_bindings)}\n"
            f")"
        )
