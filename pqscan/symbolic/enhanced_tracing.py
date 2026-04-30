#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
增强的参数追踪模块 - 支持复杂场景

新增支持：
1. 结构体字段追踪
2. 对象状态追踪（ctx/config 等）
3. 条件分支的参数选择
4. 指针/引用间接访问

@File    :   enhanced_tracing.py
@Contact :   mypandamail@163.com
@Author  :   mooo
@Version :   1.0
@Date    :   2026/1/26
"""

from typing import Dict, List, Optional, Any
from pqscan.symbolic.state_tracker import StateTracker, ObjectType
from pqscan.analysis.candidate import Candidate


class EnhancedParameterTracer:
    """
    增强的参数追踪器
    
    核心功能：
    1. 对象状态追踪（EVP_CIPHER_CTX, config 等）
    2. 结构体字段赋值追踪
    3. 条件分支参数选择
    4. 指针别名分析
    
    示例场景：
    ```c
    // 场景1: 对象状态追踪
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    // 从 ctx 中提取 algorithm=AES-256-GCM, key_bits=256
    
    // 场景2: 结构体配置对象
    struct crypto_config config;
    config.key_bits = 2048;
    config.algorithm = "RSA";
    init_crypto(&config);
    // 从 config 中提取 key_bits=2048
    
    // 场景3: 条件分支
    if (secure_mode) {
        key_size = 256;
    } else {
        key_size = 128;
    }
    encrypt(..., key_size, ...);
    // 提取 key_size={256, 128}
    ```
    """
    
    def __init__(self, kb: Dict[str, Any]):
        self.kb = kb
        self.state_tracker = StateTracker()
        self._initialized = False
    
    def initialize(self):
        """初始化状态追踪器（扫描整个代码）"""
        if self._initialized:
            return
        
        features = self.kb.get('features')
        code = self.kb.get('code', '')
        
        if not features:
            return
        
        # 1. 扫描对象创建（变量声明、内存分配）
        self._scan_object_creation(features, code)
        
        # 2. 扫描字段赋值（结构体字段、对象属性）
        self._scan_field_assignments(features, code)
        
        # 3. 扫描方法调用（EVP_EncryptInit_ex 等）
        self._scan_method_calls(features, code)
        
        # 4. 扫描指针别名（p = &a, *p = 10）
        self._scan_pointer_aliases(features, code)
        
        self._initialized = True
    
    def trace_parameter_with_state(
        self,
        candidate: Candidate,
        param_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        使用状态追踪的参数追踪
        
        优先级：
        1. 直接字段访问（config.key_bits）
        2. 对象状态（ctx 的方法调用副作用）
        3. 传统变量追踪（向后兼容）
        
        Args:
            candidate: 候选点
            param_name: 参数名
        
        Returns:
            {
                'value': 参数值,
                'line': 赋值行号,
                'confidence': 置信度,
                'source': 来源（'field', 'method', 'variable', 'branch'）,
                'alternatives': 多路径值（条件分支）
            }
        """
        self.initialize()
        
        # 1. 检查是否为字段访问（如 config.key_bits）
        if '.' in param_name:
            result = self._trace_field_access(param_name, candidate)
            if result:
                return result
        
        # 2. 检查是否为对象参数（查找对象状态）
        # 例如：EVP_EncryptUpdate(ctx, ...) -> 从 ctx 的状态提取 algorithm
        call_args = candidate.literal_args or {}
        for arg_name, arg_value in call_args.items():
            if isinstance(arg_value, str) and arg_value.isidentifier():
                # 可能是对象引用
                obj_info = self.state_tracker.extract_parameter_info(arg_value, param_name)
                if obj_info:
                    return obj_info
        
        # 3. 传统变量追踪（向后兼容）
        return None  # 回退到原有的 _trace_parameter
    
    def _scan_object_creation(self, features: Dict, code: str):
        """
        扫描对象创建
        
        识别模式：
        - C: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new()
        - C: struct crypto_config config
        - Python: ctx = AES.new(...)
        - Go: ctx, _ := aes.NewCipher(key)
        
        Note: 现在只通过 _scan_method_calls 创建对象，不在此重复创建
        """
        # 注释掉旧的实现，避免创建重复的空对象
        # 现在对象创建由 _scan_method_calls 处理（scope-aware）
        pass
    
    def _scan_field_assignments(self, features: Dict, code: str):
        """
        扫描字段赋值 - 使用 AST features，不用正则表达式
        
        识别模式：
        - config.key_bits = 2048
        - ctx->algorithm = AES
        - obj["key_size"] = 256
        
        优先级：
        1. 从 features['field_assignments'] 提取（AST 提供，无正则）✅
        2. 从 features 的其他字段推断
        3. 不再使用正则表达式扫描原始代码 ❌
        """
        # 方法1: 从 features 的 field_assignments 提取（纯 AST）
        field_assignments = features.get('field_assignments', [])
        
        for assign in field_assignments:
            if not isinstance(assign, dict):
                continue
            
            # 确认是字段赋值
            if not assign.get('is_field_assignment'):
                continue
            
            obj_id = assign.get('object')
            field_name = assign.get('field')
            value = assign.get('value')
            line = assign.get('line', 0)
            
            if obj_id and field_name and value is not None:
                # 解析值
                parsed_value = self._parse_value_from_features(value)
                if parsed_value is not None:
                    self.state_tracker.set_field(
                        obj_id, field_name, parsed_value,
                        self._infer_type(parsed_value),
                        line
                    )
        
        # 方法2: 从 variable_assignments 推断结构体创建（可选）
        # 注意：var_assignments 是变量赋值，不是字段赋值
        # 但可以用来识别结构体类型，便于后续追踪
    
    def _scan_method_calls(self, features: Dict, code: str):
        """
        扫描方法调用并记录副作用
        
        特殊处理：
        - EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), ...) 
          -> ctx.algorithm = AES-256-GCM, ctx.key_bits = 256
        
        新增：Scope-aware 对象ID
        - 同一变量名在不同函数中不会冲突
        - 使用 function_name::var_name 格式
        """
        calls = features.get('calls', [])
        functions = features.get('functions', [])
        
        # 构建 line -> function_name 的映射
        line_to_func = {}
        for func in functions:
            func_name = func.get('name', '')
            start_line = func.get('start_line', 0)
            end_line = func.get('end_line', 0)
            for line in range(start_line, end_line + 1):
                line_to_func[line] = func_name
        
        for call in calls:
            symbol = call.get('symbol', '')
            args = call.get('args', [])
            line = call.get('line', 0)
            
            # 识别对象参数（通常是第一个参数）
            if not args:
                continue
            
            first_arg = args[0]
            obj_name = None
            
            if isinstance(first_arg, dict):
                obj_name = first_arg.get('text', '')
            elif isinstance(first_arg, str):
                obj_name = first_arg
            
            if not obj_name or not obj_name.isidentifier():
                continue
            
            # 构建 scope-aware ID
            func_name = line_to_func.get(line, 'global')
            scoped_id = f"{func_name}::{obj_name}" if func_name != 'global' else obj_name
            
            # 确保对象存在（如果不存在则创建）
            obj_type = self._infer_object_type(obj_name, '')
            if obj_type and not self.state_tracker.current_state.get_object(scoped_id):
                self.state_tracker.create_object(scoped_id, obj_type, line)
            
            # 分析方法调用的副作用
            effects = self._analyze_method_effects(symbol, args, call)
            
            if effects:
                self.state_tracker.record_method_call(
                    scoped_id, symbol, args, line, effects
                )
    
    def _scan_pointer_aliases(self, features: Dict, code: str):
        """
        扫描指针别名 - 使用 AST features，不用正则
        
        模式：
        - int *p = &a;
        - config_t *cfg = &global_config;
        
        等待 extractor 提供 pointer_assignments 信息
        或使用 SSA 的 def-use 链
        """
        # 方法1: 从 features 提取（待实现）
        pointer_assigns = features.get('pointer_assignments', [])
        for assign in pointer_assigns:
            if isinstance(assign, dict):
                pointer_var = assign.get('pointer')
                target_var = assign.get('target')
                if pointer_var and target_var:
                    # 注册别名
                    obj = self.state_tracker.current_state.get_object(target_var)
                    if obj:
                        obj.aliases.add(pointer_var)
        
        # 方法2: 暂时跳过，等 SSA 实现
        pass
    
    def _parse_value_from_features(self, value: Any) -> Optional[Any]:
        """从 features 提供的值中解析实际值"""
        if isinstance(value, dict):
            # features 可能提供 {'type': 'number', 'value': 2048}
            if 'value' in value:
                return value['value']
            if 'text' in value:
                return self._parse_simple_value(value['text'])
        return value
    
    def _trace_field_access(
        self,
        field_path: str,
        candidate: Candidate
    ) -> Optional[Dict[str, Any]]:
        """
        追踪字段访问（obj.field 或 obj->field）
        
        Args:
            field_path: 字段路径（如 "config.key_bits"）
            candidate: 候选点
        
        Returns:
            字段信息
        """
        parts = field_path.split('.')
        if len(parts) < 2:
            return None
        
        obj_id = parts[0]
        field_name = parts[-1]
        
        # 从状态追踪器提取
        result = self.state_tracker.extract_parameter_info(obj_id, field_name)
        return result
    
    def _infer_object_type(self, var_name: str, value_text: str) -> Optional[ObjectType]:
        """推断对象类型"""
        var_lower = var_name.lower()
        value_lower = value_text.lower()
        
        # 上下文对象
        if 'ctx' in var_lower or 'context' in var_lower:
            return ObjectType.CONTEXT
        
        if 'new' in value_lower or 'create' in value_lower or 'init' in value_lower:
            return ObjectType.CONTEXT
        
        # 结构体/配置对象
        if 'config' in var_lower or 'struct' in value_lower:
            return ObjectType.STRUCT
        
        # 指针
        if '*' in value_text:
            return ObjectType.POINTER
        
        return None
    
    def _analyze_method_effects(
        self,
        symbol: str,
        args: List[Any],
        call: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        分析方法调用的副作用
        
        示例：
        - EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), ...) 
          -> {'algorithm': 'AES-256-GCM', 'key_bits': 256}
        """
        effects = {}
        
        # EVP_EncryptInit_ex 系列
        if 'EVP_EncryptInit' in symbol or 'EVP_DecryptInit' in symbol:
            # 第二个参数通常是算法
            if len(args) >= 2:
                algo_arg = args[1]
                algo_text = ''
                
                if isinstance(algo_arg, dict):
                    algo_text = algo_arg.get('text', '')
                elif isinstance(algo_arg, str):
                    algo_text = algo_arg
                
                # 解析算法名（如 EVP_aes_256_gcm()）
                algo = self._parse_evp_algorithm(algo_text)
                if algo:
                    effects['algorithm'] = algo['name']
                    if algo.get('key_bits'):
                        effects['key_bits'] = algo['key_bits']
        
        # AES.new() 系列（Python）
        elif 'AES.new' in symbol or 'DES.new' in symbol or 'DES3.new' in symbol:
            # 第一个参数通常是密钥
            if len(args) >= 1:
                key_arg = args[0]
                key_len = self._estimate_key_length(key_arg)
                if key_len:
                    effects['key_bits'] = key_len * 8
        
        return effects if effects else None
    
    def _parse_evp_algorithm(self, algo_text: str) -> Optional[Dict[str, Any]]:
        """解析 EVP 算法名（如 EVP_aes_256_gcm）"""
        if not algo_text:
            return None
        
        algo_lower = algo_text.lower()
        
        # 提取算法类型
        algo_type = None
        if 'aes' in algo_lower:
            algo_type = 'AES'
        elif 'des3' in algo_lower or 'des_ede3' in algo_lower:
            algo_type = 'DES3'
        elif 'des' in algo_lower:
            algo_type = 'DES'
        elif 'sm4' in algo_lower:
            algo_type = 'SM4'
        elif 'camellia' in algo_lower:
            algo_type = 'Camellia'
        
        if not algo_type:
            return None
        
        # 提取密钥长度
        key_bits = None
        for bits in ['128', '192', '256']:
            if bits in algo_text:
                key_bits = int(bits)
                break
        
        # 特殊处理：DES 和 DES3 有固定密钥长度
        if not key_bits:
            if algo_type == 'DES':
                key_bits = 56  # DES 是 56-bit（实际64-bit含parity）
            elif algo_type == 'DES3':
                key_bits = 168  # 3DES 是 168-bit（实际192-bit含parity）
        
        # 提取模式
        mode = None
        for m in ['cbc', 'ecb', 'gcm', 'ctr', 'cfb', 'ofb', 'xts', 'ccm']:
            if m in algo_lower:
                mode = m.upper()
                break
        
        # 组合算法名
        name = algo_type
        if key_bits:
            name = f'{algo_type}-{key_bits}'
        if mode:
            name = f'{name}-{mode}'
        
        return {
            'name': name,
            'type': algo_type,
            'key_bits': key_bits,
            'mode': mode
        }
    
    def _estimate_key_length(self, key_arg: Any) -> Optional[int]:
        """估算密钥长度（字节）"""
        if isinstance(key_arg, dict):
            # 字节串字面量
            text = key_arg.get('text', '')
            if text.startswith('b"') or text.startswith("b'"):
                # 去除前缀和引号
                content = text[2:-1]
                return len(content)
            
            # os.urandom(32) 等
            if 'urandom' in text or 'randbytes' in text:
                import re
                match = re.search(r'(\d+)', text)
                if match:
                    return int(match.group(1))
        
        return None
    
    def _parse_simple_value(self, text: str) -> Optional[Any]:
        """解析简单值（整数、字符串）"""
        text = text.strip()
        
        # 整数
        if text.isdigit():
            return int(text)
        
        # 字符串
        if (text.startswith('"') and text.endswith('"')) or \
           (text.startswith("'") and text.endswith("'")):
            return text[1:-1]
        
        return None
    
    def _infer_type(self, value: Any) -> str:
        """推断类型"""
        if isinstance(value, int):
            return 'int'
        elif isinstance(value, str):
            return 'string'
        elif isinstance(value, float):
            return 'float'
        elif isinstance(value, bool):
            return 'bool'
        else:
            return 'unknown'
