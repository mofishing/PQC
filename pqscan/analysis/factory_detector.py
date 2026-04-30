"""
工厂函数检测器

基于 profile_id + 规则库(common_profiles, apis_v2) 自动判断 API 类型：
- 具体算法（ALG.AES, ALG.RSA）→ 工厂函数
- 抽象类型（ALG.CIPHER, ALG.HASH）→ 操作函数
"""

import json
import re
from pathlib import Path

from pqscan.loader.utils import strip_json_comments
from typing import Optional, Dict, Set


class FactoryDetector:
    """
    工厂函数检测器
    
    使用启发式规则判断 API 是否为工厂函数：
    1. 具体 profile_id（如 ALG.AES）→ 工厂函数
    2. 抽象 profile_id（如 ALG.CIPHER）→ 操作函数
    """
    
    # 抽象类型（操作函数）
    ABSTRACT_PROFILES = {
        'ALG.CIPHER',      # 抽象加密操作
        'ALG.HASH',        # 抽象哈希操作
        'ALG.SIGNATURE',   # 抽象签名操作
        'ALG.MAC',         # 抽象MAC操作
        'ALG.KDF',         # 抽象密钥派生
        'ALG.KEY_EXCHANGE' # 抽象密钥交换
    }
    
    # 具体算法（工厂函数）
    CONCRETE_PROFILES = {
        'ALG.AES',
        'ALG.DES',
        'ALG.RSA',
        'ALG.ECDH',
        'ALG.ECDSA',
        'ALG.SHA256',
        'ALG.SHA384',
        'ALG.SHA512',
        'ALG.MD5',
        'ALG.SM2',
        'ALG.SM3',
        'ALG.SM4'
    }

    _initialized = False
    _alias_map: Dict[str, str] = {}
    _concrete_profiles_from_rules: Set[str] = set()
    _concrete_profiles_from_apis: Set[str] = set()

    @classmethod
    @classmethod
    def _normalize_profile_id(cls, profile_id: str) -> str:
        current = profile_id
        seen = set()
        while current in cls._alias_map and current not in seen:
            seen.add(current)
            current = cls._alias_map[current]
        return current

    @classmethod
    def _load_common_profiles(cls, kb_root: Path) -> None:
        path = kb_root / "common" / "common_profiles.json"
        if not path.exists():
            return
        data = json.loads(strip_json_comments(path.read_text(encoding="utf-8")))
        cls._alias_map = data.get("id_aliases", {}) or {}
        rules = data.get("rules") or []
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict):
                    rule_id = rule.get("id")
                    if isinstance(rule_id, str):
                        cls._concrete_profiles_from_rules.add(rule_id)

    @classmethod
    def _load_api_profiles(cls, kb_root: Path) -> None:
        apis_dir = kb_root / "apis_v2"
        if not apis_dir.exists():
            return
        for api_file in apis_dir.glob("*.json"):
            try:
                content = strip_json_comments(api_file.read_text(encoding="utf-8"))
                data = json.loads(content)
            except Exception:
                continue

            mappings = data.get("mappings", [])
            if isinstance(mappings, dict):
                mappings = mappings.get("apis", [])
            if not isinstance(mappings, list):
                mappings = data.get("apis", [])
            if not isinstance(mappings, list):
                continue

            for mapping in mappings:
                if not isinstance(mapping, dict):
                    continue
                semantic = mapping.get("semantic") or {}
                profile_id = semantic.get("profile_id")
                if not isinstance(profile_id, str):
                    continue
                profile_id = cls._normalize_profile_id(profile_id)
                func_params = mapping.get("func_params") or []
                operation = (semantic.get("operation") or "").lower()
                if not func_params:
                    cls._concrete_profiles_from_apis.add(profile_id)
                    continue
                if operation.startswith("get_") or operation in {"fetch_algorithm", "get_cipher_method", "get_digest_method"}:
                    cls._concrete_profiles_from_apis.add(profile_id)

    @classmethod
    def _ensure_initialized(cls) -> None:
        if cls._initialized:
            return
        kb_root = Path(__file__).resolve().parents[1] / "kb"
        cls._load_common_profiles(kb_root)
        cls._load_api_profiles(kb_root)
        cls._initialized = True
    
    @classmethod
    def is_factory_function(cls, profile_id: Optional[str]) -> bool:
        """
        判断是否为工厂函数
        
        Args:
            profile_id: Profile ID (如 "ALG.AES", "ALG.CIPHER")
        
        Returns:
            True: 工厂函数（具体算法）
            False: 操作函数（抽象类型）
        """
        if not profile_id:
            return False

        cls._ensure_initialized()
        profile_id = cls._normalize_profile_id(profile_id)
        
        # 1. 显式检查抽象类型
        if profile_id in cls.ABSTRACT_PROFILES:
            return False
        
        # 2. 显式检查具体算法
        if profile_id in cls.CONCRETE_PROFILES:
            return True

        # 3. common_profiles 规则库
        if profile_id in cls._concrete_profiles_from_rules:
            return True

        # 4. apis_v2 工厂函数集合
        if profile_id in cls._concrete_profiles_from_apis:
            return True
        
        # 5. 启发式规则：检查是否以已知具体算法开头
        # 例如：ALG.AES_128_GCM → True（具体的 AES 变体）
        for concrete in cls.CONCRETE_PROFILES:
            if profile_id.startswith(concrete):
                return True
        
        # 6. 默认：未知的 profile 视为操作函数（保守策略）
        return False
    
    @classmethod
    def is_operation_function(cls, profile_id: Optional[str]) -> bool:
        """
        判断是否为操作函数
        
        Args:
            profile_id: Profile ID
        
        Returns:
            True: 操作函数（抽象类型）
            False: 工厂函数（具体算法）
        """
        return not cls.is_factory_function(profile_id)
    
    @classmethod
    def get_api_category(cls, profile_id: Optional[str]) -> str:
        """
        获取 API 分类
        
        Args:
            profile_id: Profile ID
        
        Returns:
            "factory": 工厂函数
            "operation": 操作函数
            "unknown": 未知
        """
        if not profile_id:
            return "unknown"
        
        if cls.is_factory_function(profile_id):
            return "factory"
        else:
            return "operation"


# 便捷函数
def is_factory_function(profile_id: Optional[str]) -> bool:
    """判断是否为工厂函数"""
    return FactoryDetector.is_factory_function(profile_id)


def is_operation_function(profile_id: Optional[str]) -> bool:
    """判断是否为操作函数"""
    return FactoryDetector.is_operation_function(profile_id)
