#!/usr/bin/env python3
"""
Parameter Tracer: Extract and infer parameters from API calls

负责从 AST 提取的候选调用中推断参数：
- 从字面量参数中提取 (key_bits, mode, digest_bits)
- 从符号名称中语义推断 (EVP_aes_128_cbc → key_bits=128, mode=CBC)
- Java 特殊处理: 解析 transformation 字符串 ("AES/CBC/PKCS5Padding")
- 变量追踪: 解析变量引用和表达式 (keySize → 128)
"""

from typing import Dict, Any, List, Optional
from .variable_tracker import VariableTracker
import re


class ParameterTracer:
    """
    参数追踪器（支持变量追踪）
    
    使用示例:
        tracer = ParameterTracer()
        
        # 设置变量追踪器
        var_tracker = VariableTracker()
        var_tracker.build_from_assignments([
            {'name': 'keySize', 'value': '128', 'line': 10}
        ])
        tracer.set_variable_tracker(var_tracker)
        
        # 追踪参数（支持变量引用）
        params = tracer.trace(
            symbol="AES_set_encrypt_key",
            literal_args=['key', 'keySize', '&aes_key'],  # keySize 是变量
            language="c"
        )
        # → {'key_bits': 128}  # keySize 被解析为 128
    """
    
    def __init__(self):
        # 已知的模式关键字
        self.mode_keywords = {
            'ECB': 'ECB', 'CBC': 'CBC', 'CTR': 'CTR', 'GCM': 'GCM',
            'CFB': 'CFB', 'OFB': 'OFB', 'CCM': 'CCM', 'XTS': 'XTS',
            'EAX': 'EAX', 'OCB': 'OCB', 'SIV': 'SIV'
        }
        
        # 哈希函数的 digest_bits
        self.digest_bits_map = {
            'MD5': 128, 'MD4': 128, 'MD2': 128,
            'SHA1': 160, 'SHA-1': 160,
            'SHA224': 224, 'SHA-224': 224,
            'SHA256': 256, 'SHA-256': 256,
            'SHA384': 384, 'SHA-384': 384,
            'SHA512': 512, 'SHA-512': 512,
            'SHA3-224': 224, 'SHA3-256': 256, 'SHA3-384': 384, 'SHA3-512': 512,
            'BLAKE2B': 512, 'BLAKE2S': 256,
        }
        
        # 变量追踪器（需要外部设置）
        self.variable_tracker: Optional[VariableTracker] = None
    
    def set_variable_tracker(self, tracker: VariableTracker):
        """设置变量追踪器"""
        self.variable_tracker = tracker
    
    def trace(
        self,
        symbol: str,
        literal_args: List[Any],
        language: str,
        code_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        追踪参数
        
        Args:
            symbol: API 符号名称 (e.g., "EVP_aes_128_cbc", "getInstance")
            literal_args: 字面量参数列表
            language: 编程语言
            code_context: 可选的代码上下文
        
        Returns:
            参数字典 {'key_bits': 128, 'mode': 'CBC', ...}
        """
        params = {}
        
        # 1. 从字面量参数提取
        params.update(self._extract_from_literals(literal_args))
        
        # 2. Java 特殊处理: transformation 字符串
        if language == 'java' and 'getInstance' in symbol:
            java_params = self._parse_java_transformation(literal_args)
            params.update(java_params)
        
        # 3. 从符号名称推断 (语义推断)
        semantic_params = self._infer_from_symbol(symbol)
        # 只添加不冲突的参数
        for key, value in semantic_params.items():
            if key not in params:
                params[key] = value
        
        return params
    
    def _extract_from_literals(self, literal_args: List[Any]) -> Dict[str, Any]:
        """从字面量参数中提取（支持变量引用）"""
        params = {}
        
        for arg in literal_args:
            # Case 1: 整数字面量
            if isinstance(arg, int):
                # 可能是密钥长度
                if 8 <= arg <= 8192:
                    if 'key_bits' not in params:
                        params['key_bits'] = arg
            
            # Case 2: 字符串（可能是变量名）
            elif isinstance(arg, str) and self.variable_tracker:
                # 尝试从变量追踪器解析
                value = self.variable_tracker.get_value(arg)
                if value is not None and isinstance(value, int):
                    if 8 <= value <= 8192:
                        if 'key_bits' not in params:
                            params['key_bits'] = value
        
        return params
    
    def _parse_java_transformation(self, literal_args: List[Any]) -> Dict[str, Any]:
        """
        解析 Java transformation 字符串
        
        例如: "AES/CBC/PKCS5Padding" → algorithm=AES, mode=CBC, padding=PKCS5Padding
        """
        params = {}
        
        for arg in literal_args:
            if isinstance(arg, str):
                # 分割 transformation 字符串
                parts = arg.split('/')
                
                if len(parts) >= 1:
                    params['java_algorithm'] = parts[0].strip()
                
                if len(parts) >= 2:
                    mode_or_padding = parts[1].strip().upper()
                    # 判断是否是已知模式
                    if mode_or_padding in self.mode_keywords:
                        params['mode'] = mode_or_padding
                
                if len(parts) >= 3:
                    params['java_padding'] = parts[2].strip()
                
                break
        
        return params
    
    def _infer_from_symbol(self, symbol: str) -> Dict[str, Any]:
        """从符号名称推断参数 (语义推断)"""
        params = {}
        symbol_upper = symbol.upper()
        
        # 1. 提取密钥长度 (从符号名称中的数字)
        # 例如: EVP_aes_128_cbc → 128
        key_bits_match = re.search(r'_(\d{2,4})_', symbol)
        if key_bits_match:
            value = int(key_bits_match.group(1))
            if 8 <= value <= 8192:
                params['key_bits'] = value
        elif re.search(r'(\d{2,4})', symbol):
            # 尝试任何数字
            match = re.search(r'(\d{2,4})', symbol)
            if match:
                value = int(match.group(1))
                if 8 <= value <= 8192:
                    params['key_bits'] = value
        
        # 2. 提取模式 (从符号名称中的关键字)
        for keyword, mode in self.mode_keywords.items():
            if keyword in symbol_upper:
                params['mode'] = mode
                break
        
        # 3. 提取哈希函数的 digest_bits
        for hash_name, bits in self.digest_bits_map.items():
            if hash_name.upper() in symbol_upper or hash_name.replace('-', '_').upper() in symbol_upper:
                params['digest_bits'] = bits
                break
        
        return params


# 便捷函数
def trace_parameters(
    symbol: str,
    literal_args: List[Any],
    language: str,
    code_context: Optional[str] = None
) -> Dict[str, Any]:
    """
    便捷函数: 追踪参数
    
    示例:
        >>> from pqscan.symbolic.parameter_tracer import trace_parameters
        >>> params = trace_parameters("EVP_aes_128_cbc", [128], "c")
        >>> print(params)  # {'key_bits': 128, 'mode': 'CBC'}
    """
    tracer = ParameterTracer()
    return tracer.trace(symbol, literal_args, language, code_context)


if __name__ == "__main__":
    # 测试
    tracer = ParameterTracer()
    
    test_cases = [
        ("EVP_aes_128_cbc", [], "c"),
        ("EVP_aes_256_gcm", [], "c"),
        ("SHA256_Init", [], "c"),
        ("getInstance", ["AES/CBC/PKCS5Padding"], "java"),
        ("getInstance", ["AES/GCM/NoPadding"], "java"),
        ("keyGen.init", [128], "java"),
    ]
    
    print("Parameter Tracer Test")
    print("=" * 80)
    
    for symbol, literal_args, language in test_cases:
        params = tracer.trace(symbol, literal_args, language)
        print(f"\nSymbol: {symbol}")
        print(f"  Literal args: {literal_args}")
        print(f"  Language: {language}")
        print(f"  Extracted params: {params}")
