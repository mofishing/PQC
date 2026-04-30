#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   algorithm_mapper.py
@Contact :   mypandamail@163.com
@Author  :   moo
@Modify Time      @Version    @Description
------------      --------    -----------
2026/1/4 15:00    1.0         KB-driven algorithm detection (no regex)
"""

import json
import pathlib
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

@dataclass
class AlgorithmInfo:
    """算法信息"""
    family: str              # 算法族 (e.g., "AES", "RSA")
    key_bits: Optional[int] = None  # 密钥位数 (e.g., 128, 256)
    mode: Optional[str] = None      # 模式 (e.g., "GCM", "CBC")
    profile_id: Optional[str] = None  # Profile ID (e.g., "ALG.AES")
    
    def to_string(self) -> str:
        """转换为字符串表示 (e.g., "AES-128-GCM")"""
        parts = [self.family]
        if self.key_bits:
            parts.append(str(self.key_bits))
        if self.mode:
            parts.append(self.mode)
        return "-".join(parts)


class AlgorithmMapper:
    """
    KB-driven algorithm mapper (无正则表达式)
    
    功能:
    1. 从KB JSON文件加载算法映射
    2. 提供快速算法查询 (O(1))
    3. 支持多语言/多库 (OpenSSL, Go std, Python cryptography, etc.)
    4. 缓存查询结果
    
    使用示例:
        mapper = AlgorithmMapper(kb_dir)
        algo = mapper.get_algorithm("EVP_aes_128_gcm")
        # -> AlgorithmInfo(family="AES", key_bits=128, mode="GCM")
    """
    
    def __init__(self, kb_dir: pathlib.Path):
        self.kb_dir = pathlib.Path(kb_dir)
        self.algorithm_maps: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.cache: Dict[str, Optional[AlgorithmInfo]] = {}
        self._load_all_mappings()
    
    def _load_all_mappings(self):
        """加载所有算法映射文件"""
        apis_dir = self.kb_dir / "apis_v2"
        if not apis_dir.exists():
            apis_dir = self.kb_dir / "apis"
        if not apis_dir.exists():
            return
        
        # 1. 加载 *_alg_map.json 文件 (OpenSSL格式)
        for map_file in apis_dir.glob("*_alg_map.json"):
            self._load_algorithm_map(map_file)
        
        # 2. 加载标准API映射文件 (v2格式)
        for api_file in apis_dir.glob("*.json"):
            if "alg_map" not in api_file.name:
                self._load_api_mappings(api_file)
    
    def _load_algorithm_map(self, map_file: pathlib.Path):
        """加载 *_alg_map.json 文件 (OpenSSL EVP格式)"""
        try:
            with open(map_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # OpenSSL格式: {"openssl_evp_cipher_map": {"EVP_aes_128_gcm": {...}}}
            for table_name, mappings in data.items():
                if not isinstance(mappings, dict):
                    continue
                
                lib_name = map_file.stem  # e.g., "c_openssl_alg_map"
                if lib_name not in self.algorithm_maps:
                    self.algorithm_maps[lib_name] = {}
                
                # 存储映射: api_name -> algorithm_info
                for api_name, algo_info in mappings.items():
                    self.algorithm_maps[lib_name][api_name.lower()] = algo_info
        
        except Exception as e:
            print(f"Warning: Failed to load {map_file.name}: {e}")
    
    def _load_api_mappings(self, api_file: pathlib.Path):
        """加载标准API映射文件 (v2格式)"""
        try:
            with open(api_file, "r", encoding="utf-8") as f:
                content = f.read()
                # 移除JSON注释 (使用现有的工具函数)
                from pqscan.loader.loader_v2 import strip_json_comments
                content = strip_json_comments(content)
                data = json.loads(content)
            
            mappings = data.get("mappings", [])
            if not mappings:
                return
            
            lib_name = api_file.stem  # e.g., "go_std_crypto"
            if lib_name not in self.algorithm_maps:
                self.algorithm_maps[lib_name] = {}
            
            # 提取算法信息
            for mapping in mappings:
                if not isinstance(mapping, dict):
                    continue
                
                function = mapping.get("function", "")
                semantic = mapping.get("semantic", {})
                profile_id = semantic.get("profile_id")
                
                if not function or not profile_id:
                    continue
                
                # 从profile_id推断算法族 (e.g., "ALG.AES" -> "AES")
                if isinstance(profile_id, str) and profile_id.startswith("ALG."):
                    family = profile_id.split(".")[1]  # "ALG.AES" -> "AES"
                    
                    # 提取密钥和模式信息
                    key_info = semantic.get("key", {})
                    mode = semantic.get("mode")
                    
                    # 构建算法信息
                    algo_info = {
                        "family": family,
                        "profile_id": profile_id
                    }
                    if mode:
                        algo_info["mode"] = mode
                    
                    # 存储映射 (使用函数名和简化名)
                    func_lower = function.lower()
                    self.algorithm_maps[lib_name][func_lower] = algo_info
                    
                    # 同时存储简化形式 (e.g., "aes.NewCipher" -> "newcipher")
                    # 但跳过极其通用的方法尾名，避免把 digest/update/doFinal
                    # 这类普通成员方法污染成全局算法映射。
                    generic_simple_names = {
                        'digest', 'update', 'dofinal', 'final', 'init',
                        'initialize', 'getinstance', 'generatekeypair',
                        'generatekey', 'generatesecret', 'encrypt', 'decrypt',
                        'sign', 'verify', 'wrap', 'unwrap',
                    }
                    if "." in func_lower:
                        simple_name = func_lower.split(".")[-1]
                        # 只在不冲突时存储简化名
                        if (
                            simple_name not in generic_simple_names
                            and simple_name not in self.algorithm_maps[lib_name]
                        ):
                            self.algorithm_maps[lib_name][simple_name] = algo_info
        
        except Exception as e:
            print(f"Warning: Failed to load {api_file.name}: {e}")
    
    def get_algorithm(self, api_name: str, library: Optional[str] = None) -> Optional[AlgorithmInfo]:
        """
        根据API名称查询算法信息
        
        Args:
            api_name: API函数名 (e.g., "EVP_aes_128_gcm", "aes.NewCipher")
            library: 可选的库名过滤 (e.g., "c_openssl_alg_map", "go_std_crypto")
        
        Returns:
            AlgorithmInfo 或 None
        """
        # 检查缓存
        cache_key = f"{library}:{api_name}" if library else api_name
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        api_name_lower = api_name.lower()
        
        # 如果指定了库,只在该库中查询
        if library:
            if library in self.algorithm_maps:
                algo_dict = self.algorithm_maps[library].get(api_name_lower)
                if algo_dict:
                    result = self._dict_to_algorithm_info(algo_dict)
                    self.cache[cache_key] = result
                    return result
        else:
            # 在所有库中查询
            for lib_name, mappings in self.algorithm_maps.items():
                algo_dict = mappings.get(api_name_lower)
                if algo_dict:
                    result = self._dict_to_algorithm_info(algo_dict)
                    self.cache[cache_key] = result
                    return result
        
        # 未找到映射
        self.cache[cache_key] = None
        return None
    
    def get_algorithm_by_name(self, algorithm_name: str) -> Optional[AlgorithmInfo]:
        """
        通过算法名称直接查询 (用于 Java getInstance 等动态API)
        
        Args:
            algorithm_name: 算法名称 (e.g., "AES", "RSA", "DES")
        
        Returns:
            AlgorithmInfo 或 None
        
        示例:
            >>> mapper.get_algorithm_by_name("AES")
            AlgorithmInfo(family="AES", profile_id="ALG.AES")
        """
        if not algorithm_name:
            return None
        
        algo_upper = algorithm_name.upper().strip()
        
        # 算法名称到 profile_id 的映射
        algo_to_profile = {
            'AES': 'ALG.AES',
            'DES': 'ALG.DES',
            'IDEA': 'ALG.IDEA',
            'BLOWFISH': 'ALG.BLOWFISH',
            'DES3': 'ALG.3DES',
            'DESEDE': 'ALG.3DES',
            'TRIPLEDES': 'ALG.3DES',
            '3DES': 'ALG.3DES',
            'RSA': 'ALG.RSA',
            'DSA': 'ALG.DSA',
            'DH': 'ALG.DH',
            'DIFFIEHELLMAN': 'ALG.DH',
            'ECDSA': 'ALG.ECDSA',
            'ECDH': 'ALG.ECDH',
            'EC': 'ALG.EC',
            'ECC': 'ALG.EC',
            'RC4': 'ALG.RC4',
            'RC2': 'ALG.RC2',
            'MD2': 'ALG.MD2',
            'MD4': 'ALG.MD4',
            'CHACHA20': 'ALG.CHACHA20',
            'CHACHA20-POLY1305': 'ALG.CHACHA20_POLY1305',
            'MD5': 'ALG.MD5',
            'SHA1': 'ALG.SHA1',
            'SHA-1': 'ALG.SHA1',
            'SHA224': 'ALG.SHA224',
            'SHA-224': 'ALG.SHA224',
            'SHA256': 'ALG.SHA256',
            'SHA-256': 'ALG.SHA256',
            'SHA384': 'ALG.SHA384',
            'SHA-384': 'ALG.SHA384',
            'SHA512': 'ALG.SHA512',
            'SHA-512': 'ALG.SHA512',
        }
        
        profile_id = algo_to_profile.get(algo_upper)
        if profile_id:
            return AlgorithmInfo(
                family=algo_upper,
                profile_id=profile_id
            )
        
        return None
    
    def _dict_to_algorithm_info(self, algo_dict: Dict[str, Any]) -> AlgorithmInfo:
        """将字典转换为 AlgorithmInfo 对象"""
        return AlgorithmInfo(
            family=algo_dict.get("family", "UNKNOWN"),
            key_bits=algo_dict.get("key_bits"),
            mode=algo_dict.get("mode"),
            profile_id=algo_dict.get("profile_id")
        )
    
    def query_by_profile(self, profile_id: str) -> List[str]:
        """
        根据profile_id查询所有对应的API名称
        
        Args:
            profile_id: Profile ID (e.g., "ALG.AES")
        
        Returns:
            API名称列表
        """
        result = []
        for lib_name, mappings in self.algorithm_maps.items():
            for api_name, algo_dict in mappings.items():
                if algo_dict.get("profile_id") == profile_id:
                    result.append(api_name)
        return result
    
    def get_library_apis(self, library: str) -> set:
        """
        获取某个库中的所有 API 名称（小写）
        
        用途：白名单验证 - 只有库中实际存在的API才被认为是有效的
        
        Args:
            library: 库名 (e.g., "go_std_crypto", "c_openssl", "python_cryptography")
        
        Returns:
            API名称集合（已小写）
        
        示例:
            >>> mapper.get_library_apis("go_std_crypto")
            {'aes.newcipher', 'cipher.newgcm', 'rsa.generatekey', ...}
        """
        if library in self.algorithm_maps:
            return set(self.algorithm_maps[library].keys())
        return set()
    
    def get_all_libraries(self) -> List[str]:
        """
        获取所有已加载的库名列表
        
        Returns:
            库名列表
        """
        return list(self.algorithm_maps.keys())
    
    def get_statistics(self) -> Dict[str, int]:
        """获取统计信息"""
        total_apis = sum(len(mappings) for mappings in self.algorithm_maps.values())
        return {
            "total_libraries": len(self.algorithm_maps),
            "total_apis": total_apis,
            "cache_size": len(self.cache)
        }


# 全局单例 (延迟初始化)
_global_mapper: Optional[AlgorithmMapper] = None

def get_global_mapper(kb_dir: Optional[pathlib.Path] = None) -> AlgorithmMapper:
    """获取全局算法映射器单例"""
    global _global_mapper
    
    if _global_mapper is None:
        if kb_dir is None:
            # 默认使用当前文件所在目录的 ../kb
            kb_dir = pathlib.Path(__file__).parent.parent / "kb"
        _global_mapper = AlgorithmMapper(kb_dir)
    
    return _global_mapper


def get_algorithm(api_name: str, library: Optional[str] = None, 
                  kb_dir: Optional[pathlib.Path] = None) -> Optional[AlgorithmInfo]:
    """
    便捷函数: 查询算法信息
    
    Args:
        api_name: API函数名
        library: 可选的库名过滤
        kb_dir: 可选的KB目录 (首次调用时设置)
    
    Returns:
        AlgorithmInfo 或 None
    
    示例:
        >>> from pqscan.loader.algorithm_mapper import get_algorithm
        >>> algo = get_algorithm("EVP_aes_128_gcm")
        >>> print(algo.to_string())  # "AES-128-GCM"
    """
    mapper = get_global_mapper(kb_dir)
    return mapper.get_algorithm(api_name, library)


if __name__ == "__main__":
    # 测试代码
    kb_dir = pathlib.Path(__file__).parent.parent / "kb"
    mapper = AlgorithmMapper(kb_dir)
    
    print("Algorithm Mapper Test")
    print("=" * 50)
    
    # 测试OpenSSL EVP函数
    test_cases = [
        ("EVP_aes_128_gcm", None),
        ("EVP_aes_256_cbc", None),
        ("aes.NewCipher", "go_std_crypto"),
        ("cipher.NewGCM", "go_std_crypto"),
        ("rsa.GenerateKey", "go_std_crypto"),
    ]
    
    for api_name, lib in test_cases:
        algo = mapper.get_algorithm(api_name, lib)
        if algo:
            print(f"✓ {api_name:30} -> {algo.to_string()}")
        else:
            print(f"✗ {api_name:30} -> Not found")
    
    print("\nStatistics:", mapper.get_statistics())
