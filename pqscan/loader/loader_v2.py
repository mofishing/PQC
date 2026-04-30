# pqscan/knowledge/loader_v2.py

import json
import pathlib
import re
from typing import Dict, Any, List, Optional, Tuple

from .utils import strip_json_comments


# [配置] 公钥算法API自动分类规则表
# 格式: (parent_profile_id, function_pattern, target_profile_id)
# 优先级：从上到下匹配，第一个匹配的规则生效
PUBLIC_KEY_CLASSIFICATION_RULES = [
    # RSA: 根据函数名区分PKE和SIG
    ("ALG.RSA", r"encrypt|decrypt", "ALG.RSA.PKE"),
    ("ALG.RSA", r"sign|verify", "ALG.RSA.SIG"),
    ("ALG.RSA", r"generate", "ALG.RSA.PKE"),  # GenerateKey默认归PKE（可配置）
    
    # DSA: 仅用于签名
    ("ALG.DSA", r"sign|verify|generate", "ALG.DSA.SIG"),
    
    # ECDSA: 仅用于签名
    ("ALG.ECDSA", r"sign|verify|generate", "ALG.ECDSA.SIG"),
    
    # EdDSA: 仅用于签名
    ("ALG.EDDSA", r"sign|verify|generate", "ALG.EDDSA.SIG"),
    ("ALG.ED25519", r"sign|verify|generate", "ALG.ED25519.SIG"),
    
    # ECDH: 密钥交换，保持原profile（如果有.KEYEX子类则使用）
    ("ALG.ECDH", r"generate|newprivatekey|ecdh", "ALG.ECDH"),
    
    # DH: 密钥交换
    ("ALG.DH", r"generate|computekey", "ALG.DH"),
    
    # ElGamal: 同时支持加密和签名（少见）
    ("ALG.ELGAMAL", r"encrypt|decrypt", "ALG.ELGAMAL.PKE"),
    ("ALG.ELGAMAL", r"sign|verify", "ALG.ELGAMAL.SIG"),
]


def classify_public_key_api(parent_profile_id: str, function_name: str) -> str:
    """
    根据配置规则自动分类公钥算法API。
    
    Args:
        parent_profile_id: 原始profile_id（如"ALG.RSA"）
        function_name: API函数名（如"rsa.EncryptOAEP"）
    
    Returns:
        分类后的profile_id（如"ALG.RSA.PKE"）或原profile_id（如果无匹配）
    """
    func_lower = function_name.lower()
    
    for parent, pattern, target in PUBLIC_KEY_CLASSIFICATION_RULES:
        if parent_profile_id == parent:
            if re.search(pattern, func_lower):
                return target
    
    # 无匹配规则，返回原profile_id
    return parent_profile_id


def _inject_legacy_semantic_fields(semantic: Any) -> Any:
    """Inject legacy v1 fields (from_param, key_size, digest_size, etc.) for backward compatibility."""
    if not isinstance(semantic, dict):
        return semantic

    def augment_param_obj(obj: Dict[str, Any]) -> None:
        source = obj.get("source")
        param = obj.get("param")
        field = obj.get("field")

        if source == "param" and isinstance(param, str):
            obj.setdefault("from_param", param)
        elif source == "return":
            obj.setdefault("from_return", True)
            if "return_index" in obj:
                obj.setdefault("from_return_index", obj["return_index"])
        elif source == "receiver":
            obj.setdefault("from_receiver", True)
        elif source == "ctx":
            obj.setdefault("from_ctx", field if field else True)
        elif source == "field":
            if param == "$receiver" and field:
                obj.setdefault("from_receiver_attr", field)
            elif isinstance(param, str) and field:
                obj.setdefault("from_field_of_param", f"{param}.{field}")
        elif source == "signature_key":
            obj.setdefault("from_signature_key", True)
        elif source == "mac_key":
            obj.setdefault("from_mac_key", True)
        elif source == "agreement_key":
            obj.setdefault("from_agreement_key", True)
        elif source == "profile":
            obj.setdefault("from_profile", True)

        if "bits_param" in obj and "nbits_param" not in obj:
            obj.setdefault("nbits_param", obj["bits_param"])
        if "bits_index" in obj and "nbits_index" not in obj:
            obj.setdefault("nbits_index", obj["bits_index"])
        if "length_param" in obj:
            obj.setdefault("bytes_param", obj["length_param"])
            obj.setdefault("len_param", obj["length_param"])
        if "length_index" in obj:
            obj.setdefault("bytes_index", obj["length_index"])
            obj.setdefault("len_index", obj["length_index"])
        if "length_bytes" in obj:
            obj.setdefault("bytes", obj["length_bytes"])

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if any(k in obj for k in ("param", "source", "index", "bits_param", "length_param", "length_bytes")):
                augment_param_obj(obj)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    def add_size_aliases(root: Dict[str, Any]) -> None:
        key_bits = root.get("key_bits")
        if isinstance(key_bits, int):
            if "key_size" not in root and key_bits % 8 == 0:
                root["key_size"] = key_bits // 8
        elif isinstance(key_bits, dict):
            if "key_size" not in root and isinstance(key_bits.get("param"), str) and key_bits.get("source") == "param":
                root["key_size"] = {"from_param": key_bits["param"]}
            if "key_bits_param" not in root:
                if isinstance(key_bits.get("param"), str) and key_bits.get("source") == "param":
                    root["key_bits_param"] = {"from_param": key_bits["param"]}
                elif isinstance(key_bits.get("bits_param"), str):
                    root["key_bits_param"] = {"from_param": key_bits["bits_param"]}

        digest_bits = root.get("digest_bits")
        if isinstance(digest_bits, int):
            if "digest_size" not in root and digest_bits % 8 == 0:
                root["digest_size"] = digest_bits // 8
        elif isinstance(digest_bits, dict):
            if "digest_size" not in root and isinstance(digest_bits.get("param"), str) and digest_bits.get("source") == "param":
                root["digest_size"] = {"from_param": digest_bits["param"]}

        block_bits = root.get("block_bits")
        if isinstance(block_bits, int):
            if "block_size" not in root and block_bits % 8 == 0:
                root["block_size"] = block_bits // 8
        elif isinstance(block_bits, dict):
            if "block_size" not in root and isinstance(block_bits.get("param"), str) and block_bits.get("source") == "param":
                root["block_size"] = {"from_param": block_bits["param"]}

        tag_bits = root.get("tag_bits")
        if isinstance(tag_bits, int):
            if "tag_bytes" not in root and tag_bits % 8 == 0:
                root["tag_bytes"] = tag_bits // 8

    walk(semantic)
    add_size_aliases(semantic)
    return semantic



def _resolve_apis_dir(kb_dir: pathlib.Path) -> pathlib.Path:
    apis_v2_dir = kb_dir / "apis_v2"
    if apis_v2_dir.exists():
        return apis_v2_dir
    return kb_dir / "apis"

def load_api_mappings(kb_dir: pathlib.Path, language: str) -> List[Dict[str, Any]]:
    """加载指定语言的 API 映射配置。

    优先尝试 apis/<language>_std_crypto.json，其次尝试 apis/<language>.json，
    最后尝试 apis/<language>_*.json 合并所有文件。
    找不到时返回空列表。
    """
    apis_dir = _resolve_apis_dir(kb_dir)

    # 尝试1: language_std_crypto.json
    api_file = apis_dir / f"{language}_std_crypto.json"
    if api_file.exists():
        with open(api_file, "r", encoding="utf-8") as f:
            content = f.read()
            content = strip_json_comments(content)
            data = json.loads(content)
        return data.get("mappings", [])
    
    # 尝试2: language.json
    api_file = apis_dir / f"{language}.json"
    if api_file.exists():
        with open(api_file, "r", encoding="utf-8") as f:
            content = f.read()
            content = strip_json_comments(content)
            data = json.loads(content)
        return data.get("mappings", [])
    
    # 尝试3: 合并所有 language_*.json 文件
    apis_dir = _resolve_apis_dir(kb_dir)
    if apis_dir.exists():
        pattern = f"{language}_*.json"
        matching_files = sorted(list(apis_dir.glob(pattern)))  # 排序保证一致性
        
        if matching_files:
            all_mappings = []
            all_algid_tables = {}  # 收集所有 algid_tables
            loaded_files = []
            for api_file in matching_files:
                try:
                    # 跳过旧格式的映射表文件 (如 c_openssl_alg_map.json)
                    if "alg_map" in api_file.name.lower():
                        continue
                    
                    with open(api_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        content = strip_json_comments(content)
                        data = json.loads(content)
                        
                        # [OpenHiTLS 支持] 检查是否 apis 在顶层（与 mappings 同级）
                        if "apis" in data and isinstance(data["apis"], list):
                            # OpenHiTLS 格式: {apis: [...], mappings: {algid_tables: {...}}}
                            api_list = data["apis"]
                            algid_tables = data.get("mappings", {}).get("algid_tables", {})
                            
                            if algid_tables:
                                # 合并 algid_tables 到全局字典
                                for table_name, table_data in algid_tables.items():
                                    if table_name in all_algid_tables:
                                        all_algid_tables[table_name].update(table_data)
                                    else:
                                        all_algid_tables[table_name] = table_data.copy()
                                
                                # 将 algid_tables 附加到每个 API 的元数据中
                                for api in api_list:
                                    if isinstance(api, dict) and "_algid_tables" not in api:
                                        api["_algid_tables"] = algid_tables
                            
                            all_mappings.extend(api_list)
                            loaded_files.append(api_file.name)
                            continue
                        
                        # 标准格式或旧的 OpenHiTLS 格式
                        mappings = data.get("mappings", [])
                        
                        # [标准格式] 检查顶层是否有 algid_tables
                        if "algid_tables" in data and isinstance(data["algid_tables"], dict):
                            algid_tables = data["algid_tables"]
                            # 合并到全局字典
                            for table_name, table_data in algid_tables.items():
                                if table_name in all_algid_tables:
                                    all_algid_tables[table_name].update(table_data)
                                else:
                                    all_algid_tables[table_name] = table_data.copy()
                        
                        # [OpenHiTLS 支持] 处理包含 algid_tables 的新格式
                        # 旧 OpenHiTLS 格式: mappings = {"algid_tables": {...}, "apis": [...]}
                        if isinstance(mappings, dict):
                            # 提取 algid_tables
                            algid_tables = mappings.get("algid_tables", {})
                            if algid_tables:
                                # 合并 algid_tables 到全局字典
                                for table_name, table_data in algid_tables.items():
                                    if table_name in all_algid_tables:
                                        # 合并同名表
                                        all_algid_tables[table_name].update(table_data)
                                    else:
                                        all_algid_tables[table_name] = table_data.copy()
                            
                            # 提取 API 列表
                            api_list = mappings.get("apis", [])
                            if not api_list:
                                print(f"Warning: {api_file.name} has dict format but no 'apis' key found, skipping")
                                continue
                            
                            # 将 algid_tables 附加到每个 API 的元数据中
                            if algid_tables:
                                for api in api_list:
                                    if isinstance(api, dict) and "_algid_tables" not in api:
                                        api["_algid_tables"] = algid_tables
                            
                            all_mappings.extend(api_list)
                            loaded_files.append(api_file.name)
                        
                        # 确保mappings是列表（标准格式）
                        elif isinstance(mappings, list):
                            all_mappings.extend(mappings)
                            loaded_files.append(api_file.name)
                        else:
                            print(f"Warning: {api_file.name} has invalid mappings format (not a list or dict), skipping")
                            continue
                        
                except Exception as e:
                    print(f"Warning: Failed to load {api_file.name}: {e}")
            
            if all_mappings:
                print(f"Loaded {len(all_mappings)} API mappings from {len(loaded_files)} files for {language}:")
                for fname in loaded_files:
                    print(f"  - {fname}")
                # 将 algid_tables 附加到结果中
                if all_algid_tables:
                    # 注意：这里我们返回的是列表，需要在调用者处理 algid_tables
                    # 我们将 algid_tables 存储在一个特殊的元素中
                    all_mappings.append({
                        "_meta_algid_tables": all_algid_tables
                    })
                    print(f"Loaded {len(all_algid_tables)} algid_tables")
                return all_mappings

    print(f"Warning: API mapping file not found for {language}")
    return []


def load_common_profiles(kb_dir: pathlib.Path) -> Dict[str, Any]:
    """加载通用算法配置 common/common_profiles.json。"""
    common_file = kb_dir / "common" / "common_profiles.json"
    if not common_file.exists():
        raise FileNotFoundError(f"Common profiles not found: {common_file}")

    with open(common_file, "r", encoding="utf-8") as f:
        content = f.read()
        content = strip_json_comments(content)
        data = json.loads(content)

    return data


def get_profile(common_profiles: Dict[str, Any], profile_id: str) -> Optional[Dict[str, Any]]:
    """
    从 common_profiles 中查询指定的 profile
    
    Args:
        common_profiles: load_common_profiles() 返回的数据
        profile_id: 配置 ID，如 "ALG.AES", "ALG.RSA.PKE"
    
    Returns:
        配置字典，包含约束规则等信息，未找到返回 None
    """
    # common_profiles.json 使用 "rules" 而不是 "profiles"
    for rule in common_profiles.get("rules", []):
        if rule.get("id") == profile_id or rule.get("profile_id") == profile_id:
            return rule
    return None


def build_merged_rules_v2(
    api_mappings: List[Dict[str, Any]],
    common_profiles: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """将 API 映射与通用规则合并为统一规则集。

    - api_mappings 提供单个 API 的语义映射（含 semantic.profile_id）
    - common_profiles 提供算法级规则定义
    - 返回结构供 library 分析器使用
    """
    # 构建 profile_id -> rule 索引
    profiles_index: Dict[str, Dict[str, Any]] = {}
    for rule in common_profiles.get("rules", []):
        rule_id = rule.get("id")
        if rule_id:
            profiles_index[rule_id] = rule

    # 处理 id 别名
    id_aliases = common_profiles.get("id_aliases", {})

    merged: List[Dict[str, Any]] = []

    for api_map in api_mappings:
        api_id = api_map.get("api_id", "")
        function = api_map.get("function", "")
        imports = api_map.get("imports", [])
        semantic = api_map.get("semantic", {})
        semantic = _inject_legacy_semantic_fields(semantic)

        # profile_id 可以是直接字符串，也可以是 from_param 引用
        profile_id = semantic.get("profile_id")

        # 处理 from_param 形式（例如 cipher.NewGCM）
        if isinstance(profile_id, dict) and "from_param" in profile_id:
            param_name = profile_id["from_param"]

            # 若 key 的来源与 profile_id 的参数一致，则根据函数名推断算法族
            key_info = semantic.get("key", {})
            if isinstance(key_info, dict) and key_info.get("from_param") == param_name:
                upper_func = function.upper()
                if any(x in upper_func for x in ("AES", "GCM", "CBC", "CTR")):
                    profile_id = "ALG.AES"
                elif "DES" in upper_func:
                    if "3DES" in upper_func or "TRIPLEDES" in upper_func:
                        profile_id = "ALG.3DES"
                    else:
                        profile_id = "ALG.DES"
                else:
                    # 无法可靠推断时跳过
                    continue
            else:
                continue
        elif isinstance(profile_id, dict):
            # 其他 dict 结构暂不支持
            continue

        # [FIX 2024-12-09] 支持 algorithm_source 但无 profile_id 的 API (如 EVP_EncryptInit_ex)
        # 检查是否有 algorithm_source semantic
        has_algorithm_source = False
        algorithm_source = semantic.get("algorithm_source", {})
        if isinstance(algorithm_source, dict) and algorithm_source.get("param"):
            has_algorithm_source = True
        
        # [FIX 2026-01-04] 支持 param_constants 但无 profile_id 的 API (如 EVP_PKEY_CTX_new_id)
        # 检查是否有 param_constants 语义配置
        has_param_constants = False
        key_info = semantic.get("key", {})
        if isinstance(key_info, dict) and key_info.get("param_constants"):
            has_param_constants = True
        
        if not profile_id:
            # 如果有 algorithm_source 或 param_constants，允许通过，使用占位符 profile
            if has_algorithm_source or has_param_constants:
                profile_id = "ALG.DYNAMIC"
                # 创建占位符 profile
                profile = {
                    "id": "ALG.DYNAMIC",
                    "algorithm_family": "Dynamic (from parameter)",
                    "category": "unknown",
                    "quantum_secure": "unknown",
                    "reason": "Algorithm/keysize determined from parameter at runtime",
                    "recommendation": "Ensure secure algorithm is passed"
                }
            else:
                # 既无 profile_id 也无 algorithm_source/param_constants，跳过
                continue

        # 应用别名映射 (仅对非占位符 profile)
        if profile_id != "ALG.DYNAMIC":
            profile_id = id_aliases.get(profile_id, profile_id)
        
        # [FIX 2024-12-09] 公钥算法API自动分类
        # 使用配置表根据函数名自动分类（PKE/SIG/KEYEX）
        original_profile_id = profile_id
        if profile_id != "ALG.DYNAMIC":
            profile_id = classify_public_key_api(profile_id, function)
        
        # 如果分类后profile不存在，尝试回退到原profile
        # 这样可以优雅处理profile配置不完整的情况
        if profile_id != "ALG.DYNAMIC":
            profile = profiles_index.get(profile_id)
            if not profile and profile_id != original_profile_id:
                # 分类后的profile不存在，尝试原profile
                profile = profiles_index.get(original_profile_id)
                if profile:
                    profile_id = original_profile_id
        
        if not profile:
            # 两个都不存在，跳过
            # print(f"Warning: Profile not found for {profile_id} (original: {original_profile_id}) in {api_id}")
            continue

        merged_rule = {
            "id": profile_id,  # 保留旧版字段名
            "rule_id": profile_id,
            "api_id": api_id,
            "api": {
                "symbols": [function],
                "imports": imports,
                "literals": [],  # V2 不再使用字面量匹配
            },
            "match": {
                "symbols": [function],
                "imports": imports,
            },
            "layer": ["library"],
            "category": profile.get("category", "unknown"),
            "quantum_secure": profile.get("quantum_secure", "unknown"),
            "reason": profile.get("reason", ""),
            "recommendation": profile.get("recommendation", ""),
            "params": profile.get("params", {}),
            # 保留语义信息供分析阶段使用
            "semantic": semantic,
            # 保留函数参数列表供keysize参数追溯使用
            "func_params": api_map.get("func_params", []),
        }

        merged.append(merged_rule)

    return merged

    return merged


def load_kb_v2(kb_dir: pathlib.Path, language: str = "go") -> Dict[str, Any]:
    """知识库加载入口（v2）。"""
    kb_dir = pathlib.Path(kb_dir)

    api_mappings = load_api_mappings(kb_dir, language)
    
    # [OpenHiTLS 支持] 提取 algid_tables（如果存在）
    algid_tables = {}
    clean_mappings = []
    for item in api_mappings:
        if isinstance(item, dict) and "_meta_algid_tables" in item:
            algid_tables = item["_meta_algid_tables"]
        else:
            clean_mappings.append(item)
    
    common_profiles = load_common_profiles(kb_dir)
    merged_rules = build_merged_rules_v2(clean_mappings, common_profiles)

    result = {
        "api_mappings": clean_mappings,
        "common_profiles": common_profiles,
        "merged_rules": merged_rules,
        "version": "2.0",
        "language": language,
    }
    
    # 如果有 algid_tables，添加到结果中
    if algid_tables:
        result["algid_tables"] = algid_tables
    
    return result


def test_loader():
    """简单自检：加载 Go 规则并打印概况。"""
    kb_dir = pathlib.Path(__file__).parent.parent / "kb"

    print("Testing Go rules loader...")
    kb = load_kb_v2(kb_dir, "go")

    print(f"Loaded {len(kb['api_mappings'])} API mappings")
    print(f"Loaded {len(kb['common_profiles'].get('rules', []))} common profiles")
    print(f"Generated {len(kb['merged_rules'])} merged rules")

    print("\nFirst 5 merged rules:")
    for i, rule in enumerate(kb["merged_rules"][:5]):
        print(f"\n{i + 1}. {rule['rule_id']} - {rule['api']['symbols']}")
        print(f"   Category: {rule['category']}")
        print(f"   Quantum Secure: {rule['quantum_secure']}")


if __name__ == "__main__":
    test_loader()
