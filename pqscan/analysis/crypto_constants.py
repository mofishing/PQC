#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   crypto_constants.py
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/12/25 00:00   1.0         通用密码算法常量映射
"""

from typing import Optional, Dict
import re


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 哈希算法输出长度映射 (单位: bits)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HASH_OUTPUT_BITS: Dict[str, int] = {
    # SHA-1 系列
    'sha1': 160,
    'sha-1': 160,
    
    # SHA-2 系列
    'sha224': 224,
    'sha-224': 224,
    'sha256': 256,
    'sha-256': 256,
    'sha384': 384,
    'sha-384': 384,
    'sha512': 512,
    'sha-512': 512,
    'sha512-224': 224,
    'sha512-256': 256,
    
    # SHA-3 系列
    'sha3-224': 224,
    'sha3-256': 256,
    'sha3-384': 384,
    'sha3-512': 512,
    'sha3_224': 224,
    'sha3_256': 256,
    'sha3_384': 384,
    'sha3_512': 512,
    
    # SHAKE 系列 (XOF - 可扩展输出函数)
    # 返回安全强度（而非默认输出长度）
    'shake128': 128,  # 安全强度128位
    'shake256': 256,  # 安全强度256位
    
    # MD 系列
    'md5': 128,
    'md4': 128,
    'md2': 128,
    
    # RIPEMD 系列
    'ripemd160': 160,
    'ripemd-160': 160,
    
    # 国密算法
    'sm3': 256,
    
    # BLAKE 系列
    'blake2b': 512,
    'blake2s': 256,
    'blake2b-512': 512,
    'blake2s-256': 256,
    
    # Whirlpool
    'whirlpool': 512,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 对称加密算法密钥长度映射 (单位: bits)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CIPHER_KEY_BITS: Dict[str, int] = {
    # AES 系列
    'aes-128': 128,
    'aes-192': 192,
    'aes-256': 256,
    'aes128': 128,
    'aes192': 192,
    'aes256': 256,
    
    # DES 系列
    'des': 56,
    'des-ecb': 56,
    'des-cbc': 56,
    'des-cfb': 56,
    'des-ofb': 56,
    'des-ede': 112,  # 2DES
    'des-ede3': 168,  # 3DES
    'des3': 168,
    '3des': 168,
    'tripledes': 168,
    
    # IDEA
    'idea': 128,
    'idea-128': 128,
    
    # ARIA 系列
    'aria-128': 128,
    'aria-192': 192,
    'aria-256': 256,
    'aria128': 128,
    'aria192': 192,
    'aria256': 256,
    
    # Camellia 系列
    'camellia-128': 128,
    'camellia-192': 192,
    'camellia-256': 256,
    'camellia128': 128,
    'camellia192': 192,
    'camellia256': 256,
    
    # ChaCha 系列
    'chacha20': 256,
    'chacha20-poly1305': 256,
    
    # Salsa 系列
    'salsa20': 256,
    
    # 国密算法
    'sm4': 128,
    'sm1': 128,
    
    # RC 系列
    'rc4': 128,  # 可变,取常用值
    'rc2': 128,
    'rc5': 128,
    
    # Blowfish
    'blowfish': 128,  # 可变,取常用值
    'bf': 128,
    
    # CAST
    'cast5': 128,
    'cast-128': 128,
    
    # SEED
    'seed': 128,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 椭圆曲线密钥长度映射 (单位: bits)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EC_CURVE_BITS: Dict[str, int] = {
    # NIST P 系列
    'p-192': 192,
    'p-224': 224,
    'p-256': 256,
    'p-384': 384,
    'p-521': 521,
    'p192': 192,
    'p224': 224,
    'p256': 256,
    'p384': 384,
    'p521': 521,
    
    # SECP 系列
    'secp192r1': 192,
    'secp224r1': 224,
    'secp256r1': 256,
    'secp384r1': 384,
    'secp521r1': 521,
    'secp256k1': 256,  # Bitcoin
    
    # X9.62 prime 系列 (同 SECP)
    'prime192v1': 192,  # NID_X9_62_prime192v1
    'prime256v1': 256,  # NID_X9_62_prime256v1 (P-256)
    'x9_62_prime192v1': 192,
    'x9_62_prime256v1': 256,
    
    # SECG 曲线
    'sect163k1': 163,
    'sect233k1': 233,
    'sect283k1': 283,
    'sect409k1': 409,
    'sect571k1': 571,
    
    # Brainpool 系列
    'brainpoolp256r1': 256,
    'brainpoolp384r1': 384,
    'brainpoolp512r1': 512,
    
    # Curve25519 / Edwards 曲线
    'curve25519': 256,
    'x25519': 256,
    'ed25519': 256,
    
    # Curve448
    'curve448': 448,
    'x448': 448,
    'ed448': 448,
    
    # 国密曲线
    'sm2': 256,
    'sm2p256v1': 256,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 其他算法密钥长度映射
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OTHER_KEY_BITS: Dict[str, int] = {
    # DSA (可变,取常用值)
    'dsa-1024': 1024,
    'dsa-2048': 2048,
    'dsa-3072': 3072,
    
    # DH (可变,取常用值)
    'dh-1024': 1024,
    'dh-2048': 2048,
    'dh-3072': 3072,
    'dh-4096': 4096,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 通用查询函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_hash_output_bits(hash_name: str) -> Optional[int]:
    """
    获取哈希算法的输出长度
    
    Args:
        hash_name: 哈希算法名称,不区分大小写
        
    Returns:
        输出长度(bits),如果未找到返回 None
        
    Examples:
        >>> get_hash_output_bits('SHA256')
        256
        >>> get_hash_output_bits('sha-512')
        512
        >>> get_hash_output_bits('MD5')
        128
    """
    if not hash_name:
        return None
    
    # 首先尝试从 JSON 配置查询 (优先使用新的数据驱动方式)
    # from .keysize import query_constant_mapping  # LEGACY: module removed
    
    # 标准化名称
    normalized = hash_name.lower().strip()
    
    # 使用硬编码字典
    # 直接查找
    if normalized in HASH_OUTPUT_BITS:
        return HASH_OUTPUT_BITS[normalized]
    
    # 尝试移除常见前缀
    for prefix in ['evp_', 'openssl_', 'hashlib.']:
        if normalized.startswith(prefix):
            stripped = normalized[len(prefix):]
            if stripped in HASH_OUTPUT_BITS:
                return HASH_OUTPUT_BITS[stripped]
    
    # 尝试模糊匹配 (从名称中提取算法名)
    for key, bits in HASH_OUTPUT_BITS.items():
        if key in normalized or normalized in key:
            return bits
    
    return None


def get_cipher_key_bits(cipher_name: str) -> Optional[int]:
    """
    获取对称加密算法的密钥长度
    
    Args:
        cipher_name: 密码算法名称,不区分大小写
        
    Returns:
        密钥长度(bits),如果未找到返回 None
        
    Examples:
        >>> get_cipher_key_bits('AES-128-CBC')
        128
        >>> get_cipher_key_bits('des-ede3')
        168
        >>> get_cipher_key_bits('ChaCha20')
        256
    """
    if not cipher_name:
        return None
    
    # 首先尝试从 JSON 配置查询
    # from .keysize import query_constant_mapping  # LEGACY: module removed
    
    # 标准化名称
    normalized = cipher_name.lower().strip()
    
    # 使用硬编码字典和启发式规则
    # 尝试移除常见前缀
    for prefix in ['evp_', 'openssl_', 'cipher.']:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    
    # 首先尝试从名称中提取数字 (如 aes_128_cbc -> 128)
    # 这样可以处理 EVP_aes_128_cbc 的情况
    match = re.search(r'[-_](\d{3})[-_]', normalized)
    if match:
        return int(match.group(1))
    
    # 移除常见后缀 (模式)
    normalized = re.sub(r'[-_](ecb|cbc|cfb|ofb|ctr|gcm|ccm|ocb|xts|wrap).*$', '', normalized)
    
    # 直接查找
    if normalized in CIPHER_KEY_BITS:
        return CIPHER_KEY_BITS[normalized]
    
    # 尝试模糊匹配
    for key, bits in CIPHER_KEY_BITS.items():
        if key in normalized:
            return bits
    
    return None


def get_ec_curve_bits(curve_name: str) -> Optional[int]:
    """
    获取椭圆曲线的密钥长度
    
    Args:
        curve_name: 曲线名称,不区分大小写
        
    Returns:
        密钥长度(bits),如果未找到返回 None
        
    Examples:
        >>> get_ec_curve_bits('secp256r1')
        256
        >>> get_ec_curve_bits('P-384')
        384
        >>> get_ec_curve_bits('X25519')
        256
    """
    if not curve_name:
        return None
    
    # 首先尝试从 JSON 配置查询
    # from .keysize import query_constant_mapping  # LEGACY: module removed
    
    # 标准化名称
    normalized = curve_name.lower().strip()
    
    # 使用硬编码字典
    # 直接查找
    if normalized in EC_CURVE_BITS:
        return EC_CURVE_BITS[normalized]
    
    # 尝试移除常见前缀
    for prefix in ['nid_', 'openssl_', 'ec.']:
        if normalized.startswith(prefix):
            stripped = normalized[len(prefix):]
            if stripped in EC_CURVE_BITS:
                return EC_CURVE_BITS[stripped]
    
    # 尝试模糊匹配
    for key, bits in EC_CURVE_BITS.items():
        if key in normalized or normalized in key:
            return bits
    
    return None


def get_algorithm_key_bits(algo_name: str, algo_type: Optional[str] = None) -> Optional[int]:
    """
    通用算法密钥长度查询函数 (智能识别算法类型)
    
    Args:
        algo_name: 算法名称
        algo_type: 算法类型提示 ('hash', 'cipher', 'ec', 可选)
        
    Returns:
        密钥/输出长度(bits),如果未找到返回 None
        
    Examples:
        >>> get_algorithm_key_bits('SHA256', 'hash')
        256
        >>> get_algorithm_key_bits('AES-128-CBC', 'cipher')
        128
        >>> get_algorithm_key_bits('secp256r1', 'ec')
        256
        >>> get_algorithm_key_bits('AES-256-GCM')  # 自动识别
        256
    """
    if not algo_name:
        return None
    
    # 如果指定了类型,直接查询
    if algo_type:
        if algo_type.lower() == 'hash':
            return get_hash_output_bits(algo_name)
        elif algo_type.lower() in ['cipher', 'symmetric']:
            return get_cipher_key_bits(algo_name)
        elif algo_type.lower() in ['ec', 'curve', 'ecc']:
            return get_ec_curve_bits(algo_name)
    
    # 自动识别算法类型并查询
    # 优先级: cipher > ec > hash (避免误匹配)
    
    # 1. 尝试作为对称加密算法
    result = get_cipher_key_bits(algo_name)
    if result:
        return result
    
    # 2. 尝试作为椭圆曲线
    result = get_ec_curve_bits(algo_name)
    if result:
        return result
    
    # 3. 尝试作为哈希算法
    result = get_hash_output_bits(algo_name)
    if result:
        return result
    
    # 4. 尝试其他算法
    normalized = algo_name.lower().strip()
    if normalized in OTHER_KEY_BITS:
        return OTHER_KEY_BITS[normalized]
    
    return None


def extract_key_size_from_api_name(api_name: str) -> Optional[int]:
    """
    从API函数名中提取密钥大小
    
    适用于包含算法名的API函数,如:
    - EVP_aes_128_cbc -> 128
    - HMAC_SHA256 -> 256
    - EC_KEY_new_by_curve_name(NID_secp256r1) -> 256
    
    Args:
        api_name: API函数名
        
    Returns:
        密钥大小(bits),如果无法提取返回 None
    """
    if not api_name:
        return None
    
    # 策略1: 特殊模式优先处理
    normalized = api_name.lower()
    
    # DES特殊处理 (必须优先)
    if 'des_ede3' in normalized or 'des3' in normalized or '3des' in normalized:
        return 168
    elif 'des_ede' in normalized:
        return 112
    elif 'des_' in normalized:
        return 56
    
    # 策略2: 从函数名中提取算法名,然后查询
    # 移除常见前缀
    for prefix in ['evp_', 'openssl_', 'hmac_', 'pbkdf2_', 'ec_', 'rsa_', 'dsa_']:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    
    # 尝试查询
    result = get_algorithm_key_bits(normalized)
    if result:
        return result
    
    # 策略3: 从函数名中直接提取数字
    # 例如: set_key_length_256 -> 256
    match = re.search(r'[-_]?(\d{2,4})[-_]?', api_name)
    if match:
        num = int(match.group(1))
        # 验证是否为合理的密钥大小
        if num in [56, 64, 112, 128, 160, 168, 192, 224, 256, 384, 448, 512, 521, 1024, 2048, 3072, 4096]:
            return num
    
    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 所有合法密钥长度集合（聚合自以上所有字典）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_all_valid_key_sizes() -> frozenset:
    """
    返回所有已知的合法密钥/摘要长度集合（单位：bits）

    从 CIPHER_KEY_BITS、EC_CURVE_BITS、OTHER_KEY_BITS 及
    常见非对称密钥长度（RSA/DH/DSA）聚合而来。
    调用方无需硬编码数字集合，直接读取此函数结果。

    Returns:
        frozenset[int]: 所有合法密钥位数
    """
    sizes: set = set()
    sizes.update(CIPHER_KEY_BITS.values())
    sizes.update(EC_CURVE_BITS.values())
    sizes.update(OTHER_KEY_BITS.values())
    sizes.update(HASH_OUTPUT_BITS.values())
    # 常见非对称密钥长度（RSA/DH/DSA，单独列出因为不在对称或曲线字典中）
    sizes.update({512, 1024, 2048, 3072, 4096, 7680, 8192, 15360})
    return frozenset(sizes)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Pipeline v2 / post-augmentation helper constants（集中管理，减少硬编码）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PIPELINE_GEN_METHODS = frozenset({
    'generatekey', 'generatekeypair', 'dofinal', 'dophase', 'generatesecret',
    'encrypt', 'decrypt', 'encrypt_and_digest', 'decrypt_and_verify',
    'sign', 'verify', 'getencoded',
})

PIPELINE_INIT_METHODS = frozenset({'init', 'initialize', 'init_ex', 'reinit'})

PIPELINE_NULL_LIKE_TOKENS = frozenset({'null', 'none', 'nil'})

PIPELINE_OPERATION_SEMANTIC_TOKENS = frozenset({
    'generate', 'gen', 'encrypt', 'decrypt', 'sign', 'verify', 'exchange',
    'ecdh', 'ecdsa', 'keygen', 'init', 'derive', 'wrap', 'unwrap',
})

PIPELINE_ALG_FAMILY_SEPARATORS = ('/', '-', '_', '.', ':', '(', ')', ',', ';')

PIPELINE_ALG_FAMILY_SKIP_TOKENS = frozenset({'ALG', 'UTIL', 'PRIM', 'UNKNOWN', 'FACTORY'})

PIPELINE_KEY_BITS_LINE_WINDOW = 8


def get_pipeline_gen_methods() -> frozenset:
    return PIPELINE_GEN_METHODS


def get_pipeline_init_methods() -> frozenset:
    return PIPELINE_INIT_METHODS


def get_pipeline_null_like_tokens() -> frozenset:
    return PIPELINE_NULL_LIKE_TOKENS


def get_pipeline_operation_semantic_tokens() -> frozenset:
    return PIPELINE_OPERATION_SEMANTIC_TOKENS


def get_pipeline_key_bits_line_window() -> int:
    return PIPELINE_KEY_BITS_LINE_WINDOW


def get_pipeline_alg_family_separators() -> tuple:
    return PIPELINE_ALG_FAMILY_SEPARATORS


def get_pipeline_alg_family_skip_tokens() -> frozenset:
    return PIPELINE_ALG_FAMILY_SKIP_TOKENS


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 便捷别名
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 为了向后兼容,提供简短别名
get_hash_size = get_hash_output_bits
get_cipher_size = get_cipher_key_bits
get_curve_size = get_ec_curve_bits
get_key_size = get_algorithm_key_bits
