"""
封装派生架构：Wrapper Summary 数据结构

支持从敏感点（Sink）向外派生封装函数的约束，用于剪枝和入口判定。
"""

from typing import Dict, List, Optional, Set, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
from pathlib import Path

from .base import AnalyzerBase
from ..abstract_syntax_tree import extract_features
from ..reporting.model import Finding
from .crypto_constants import (
    get_all_valid_key_sizes,
    get_pipeline_alg_family_separators,
    get_pipeline_alg_family_skip_tokens,
    get_pipeline_operation_semantic_tokens,
)


# ============================================================================
# 0. Pipeline v2 helper utilities (Task 37)
# ============================================================================

LANG_SUFFIX_MAP = {
    'python': '.py',
    'java': '.java',
    'go': '.go',
    'c': '.c',
}

_CROSS_FILE_WRAPPER_CACHE: Dict[Tuple[str, str, int], Dict[str, str]] = {}
_CROSS_FILE_WRAPPER_CHAIN_CACHE: Dict[Tuple[str, str, int], Dict[str, List[str]]] = {}
_CROSS_FILE_WRAPPER_KEY_BITS_CACHE: Dict[Tuple[str, str, int], Dict[str, int]] = {}
_DEFAULT_VALID_KEY_BITS: Set[int] = set(get_all_valid_key_sizes())
_ALG_FAMILY_SEPARATORS = get_pipeline_alg_family_separators()
_ALG_FAMILY_SKIP_TOKENS = get_pipeline_alg_family_skip_tokens()
_NON_CRYPTO_TERMINAL_MEMBERS = {
    'encode',
    'decode',
    'digest',
    'hexdigest',
    'hex',
}
_PYTHON_NON_CRYPTO_GENERIC_MEMBERS = {
    'str',
    'bytes',
    'bytearray',
    'join',
    'get',
    'keys',
    'values',
    'items',
    'append',
    'extend',
    'insert',
    'pop',
    'remove',
    'replace',
    'split',
    'rsplit',
    'strip',
    'lstrip',
    'rstrip',
    'lower',
    'upper',
    'capitalize',
    'title',
    'format',
    'startswith',
    'endswith',
    'read',
    'write',
    'open',
    'close',
    'seek',
    'tell',
    'flush',
    'decode',
    'encode',
    'dump',
    'dumps',
    'load',
    'loads',
    'json',
    'dict',
    'list',
    'tuple',
    'set',
    'len',
    'sum',
    'min',
    'max',
    'map',
    'filter',
    'sorted',
    'any',
    'all',
    'iter',
    'next',
    'print',
    'queryset',
    'force_str',
    'value_to_string',
    'to_string',
    'as_string',
}
_PYTHON_GENERIC_NAMESPACE_TERMINALS = {
    'objects',
    'flags',
    'headers',
    'meta',
    'data',
    'attrs',
    'params',
    'kwargs',
    'config',
    'settings',
    'options',
}
_CXX_NON_CRYPTO_ACCESSOR_MEMBERS = {
    'data',
    'size',
    'length',
    'headers',
    'header',
    'status',
    'get',
    'release',
    'front',
    'back',
    'begin',
    'end',
    'constdata',
    'session',
    'user',
    'url',
    'path',
    'value',
    'name',
    'message',
    'str',
    'string',
    'config',
    'context',
    'provider',
    'providers',
    'secret',
    'token',
    'fetch',
    'overwrite',
    'matched',
    'checksum',
    'ipp',
    'number',
    'text',
    'widget',
    'item',
    'element',
    'source',
    'result',
    'response',
    'request',
    'owner',
    'parent',
    'filter',
    'key',
}


def _looks_like_crypto_name(name: Any) -> bool:
    text = str(name or '').strip().lower()
    if not text:
        return False
    compact = re.sub(r'[^a-z0-9]+', '', text)
    if not compact:
        return False
    return any(token in compact for token in (
        'aes', 'des', 'rsa', 'dsa', 'dh', 'ecdh', 'ecdsa', 'ed25519', 'ed448',
        'x25519', 'x448', 'curve25519', 'mlkem', 'mldsa', 'dilithium', 'kyber',
        'falcon', 'sphincs', 'hmac', 'cmac', 'hkdf', 'pbkdf', 'pbkdf2', 'scrypt',
        'bcrypt', 'argon', 'sha', 'shake', 'md5', 'sha1', 'sha2', 'sha3',
        'chacha', 'poly1305', 'salsa20', 'secretbox', 'box', 'cipher', 'mac',
        'digest', 'hash', 'encrypt', 'decrypt', 'sign', 'verify', 'wrap',
        'unwrap', 'oaep', 'pss', 'gcm', 'cbc', 'ctr', 'ecb', 'x509', 'cert',
        'privatekey', 'publickey', 'keypair', 'keygen', 'nonce', 'iv',
    ))


def _is_python_non_crypto_symbol(symbol: Any) -> bool:
    text = str(symbol or '').strip()
    if not text:
        return False
    tail = normalize_func_name(text).lower()
    if not tail:
        return False
    if _looks_like_crypto_name(text) or _looks_like_crypto_name(tail):
        return False
    if tail in _NON_CRYPTO_TERMINAL_MEMBERS:
        return True
    if tail in _PYTHON_NON_CRYPTO_GENERIC_MEMBERS:
        return True
    if '.' not in text and tail in {'str', 'bytes', 'bytearray'}:
        return True
    parts = [part.strip().lower() for part in str(text).split('.') if part.strip()]
    if parts:
        if parts[-1] in _PYTHON_NON_CRYPTO_GENERIC_MEMBERS:
            return True
        if len(parts) >= 2 and parts[-1] in {'get', 'join'}:
            if any(part in _PYTHON_GENERIC_NAMESPACE_TERMINALS for part in parts[:-1]):
                return True
    if ').' in text and tail not in {
        'new',
        'encrypt',
        'decrypt',
        'sign',
        'verify',
        'update',
        'final',
        'finalize',
        'dofinal',
    }:
        return True
    return False


def _allow_python_tail_fallback(symbol: Any) -> bool:
    text = str(symbol or '').strip()
    if not text:
        return False
    tail = normalize_func_name(text)
    if not tail:
        return False
    if _is_python_non_crypto_symbol(text) or _is_python_non_crypto_symbol(tail):
        return False
    return _looks_like_crypto_name(text) or _looks_like_crypto_name(tail)


def _is_c_non_crypto_wrapper_name(name: Any) -> bool:
    text = str(name or '').strip()
    if not text:
        return False
    tail = text
    for sep in ('::', '->', '.'):
        if sep in tail:
            tail = tail.split(sep)[-1]
    tail_lc = tail.lower()
    if any(token in tail_lc for token in (
        'rsa', 'ecdsa', 'ecdh', 'ed25519', 'ed448', 'x25519', 'x448',
        'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'aes', 'des', 'hmac', 'cmac', 'hkdf', 'digest',
        'encrypt', 'decrypt', 'sign', 'verify',
    )):
        return False
    return tail_lc in _CXX_NON_CRYPTO_ACCESSOR_MEMBERS


def is_c_non_crypto_callsite_symbol(symbol: Any) -> bool:
    text = str(symbol or '').strip()
    if not text:
        return False
    tail = text
    for sep in ('::', '->', '.'):
        if sep in tail:
            tail = tail.split(sep)[-1]
    tail_lc = tail.lower()
    if any(token in tail_lc for token in (
        'rsa', 'ecdsa', 'ecdh', 'ed25519', 'ed448', 'x25519', 'x448',
        'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'aes', 'des', 'hmac', 'cmac', 'hkdf', 'digest',
        'encrypt', 'decrypt', 'sign', 'verify',
    )):
        return False
    if tail_lc in _CXX_NON_CRYPTO_ACCESSOR_MEMBERS:
        return True
    parts = [part.strip().lower() for part in re.split(r'::|->|\.', text) if part.strip()]
    if any(part in _CXX_NON_CRYPTO_ACCESSOR_MEMBERS for part in parts[-2:]):
        return True
    if re.search(r'\(\)\s*\.', text):
        return True
    return False


def is_concrete_profile_id(profile_id: str) -> bool:
    if not isinstance(profile_id, str):
        return False
    if profile_id.upper() in {'ALG.CSPRNG', 'PRIM.CSPRNG', 'UTIL.RNGFACTORY'} or profile_id.upper().startswith('RNG.'):
        return False
    return profile_id.startswith('ALG.') and not profile_id.startswith('UTIL.') and profile_id != 'UNKNOWN'


def _allow_arg_based_profile_inference(symbol: str) -> bool:
    return bool(normalize_func_name(symbol))


def resolve_concrete_profile_from_call(
    scanner_ref: Any,
    symbol: str,
    language: str,
    args: Optional[List[Dict[str, Any]]] = None,
    var_str_map: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    if scanner_ref is None:
        return None

    symbol_text = str(symbol or '')
    if symbol_text:
        try:
            profile_id = scanner_ref._identify_kb_api_by_symbol(symbol_text, language)
        except Exception:
            profile_id = None
        if is_concrete_profile_id(profile_id):
            return profile_id

    algorithm_mapper = getattr(scanner_ref, 'algorithm_mapper', None)
    if algorithm_mapper is None:
        return None

    if symbol_text:
        try:
            algo_info = algorithm_mapper.get_algorithm(symbol_text)
            if algo_info and is_concrete_profile_id(getattr(algo_info, 'profile_id', None)):
                return algo_info.profile_id
        except Exception:
            pass

    if not _allow_arg_based_profile_inference(symbol_text):
        return None

    for arg in args or []:
        if not isinstance(arg, dict):
            continue

        raw = arg.get('value')
        if not isinstance(raw, str) and arg.get('type') == 'identifier':
            text = str(arg.get('text', '') or '').lower()
            if text and isinstance(var_str_map, dict):
                raw = var_str_map.get(text)

        if not isinstance(raw, str) or not raw:
            continue

        head = raw.split('/')[0].strip().upper()
        if not head:
            continue
        try:
            algo_info = algorithm_mapper.get_algorithm_by_name(head)
            if algo_info and is_concrete_profile_id(getattr(algo_info, 'profile_id', None)):
                return algo_info.profile_id
        except Exception:
            continue

    return None


def alg_family(text: str) -> str:
    upper_text = str(text or '').upper().strip()
    if not upper_text:
        return ''

    if upper_text.startswith('ALG.'):
        head = upper_text.split()[0]
        parts = head.split('.')
        if len(parts) >= 2 and parts[1]:
            return parts[1]

    normalized = upper_text
    for sep in _ALG_FAMILY_SEPARATORS:
        normalized = normalized.replace(sep, ' ')
    for token in normalized.split():
        if token in _ALG_FAMILY_SKIP_TOKENS:
            continue
        if any(ch.isalpha() for ch in token):
            return token
    return ''


def normalize_func_name(name: str) -> str:
    func_name = str(name or '').strip()
    if not func_name:
        return ''
    if ' [' in func_name:
        func_name = func_name.split(' [', 1)[0].strip()
    if '::' in func_name:
        func_name = func_name.split('::')[-1]
    if '.' in func_name:
        func_name = func_name.split('.')[-1]
    return func_name


def extract_secp_bits(text: str, valid_key_bits: Optional[Set[int]] = None) -> Optional[int]:
    if valid_key_bits is None:
        valid_key_bits = _DEFAULT_VALID_KEY_BITS

    upper_text = str(text or '').upper()
    marker = 'SECP'
    idx = upper_text.find(marker)
    if idx < 0:
        return None

    digits: List[str] = []
    for ch in upper_text[idx + len(marker):]:
        if ch.isdigit():
            digits.append(ch)
            if len(digits) >= 4:
                break
        elif digits:
            break

    if not digits:
        return None

    try:
        bits = int(''.join(digits))
    except (TypeError, ValueError):
        return None
    return bits if bits in valid_key_bits else None


def finding_key(item: Any) -> Tuple[int, str, Optional[str]]:
    return (
        getattr(item, 'line', 0),
        getattr(item, 'symbol', ''),
        getattr(item, 'profile_id', None),
    )


def as_valid_key_bits(value: Any, valid_key_bits: Optional[Set[int]] = None) -> Optional[int]:
    if valid_key_bits is None:
        valid_key_bits = _DEFAULT_VALID_KEY_BITS
    return value if isinstance(value, int) and value in valid_key_bits else None


def extract_candidate_key_bits(candidate: Any, valid_key_bits: Optional[Set[int]] = None) -> Optional[int]:
    if valid_key_bits is None:
        valid_key_bits = _DEFAULT_VALID_KEY_BITS

    def _normalize_bits(value: Any) -> Optional[int]:
        if isinstance(value, int) and value in valid_key_bits:
            return value
        if isinstance(value, str) and value.strip():
            try:
                from .crypto_constants import get_cipher_key_bits, get_algorithm_key_bits
                bits = get_cipher_key_bits(value)
                if bits is None:
                    bits = get_algorithm_key_bits(value)
                if bits in valid_key_bits:
                    return bits
            except Exception:
                pass
        return None

    def _bits_from_profile_or_symbol(value: Any) -> Optional[int]:
        text = str(value or '').strip()
        if not text:
            return None
        try:
            from .crypto_constants import extract_key_size_from_api_name, get_algorithm_key_bits
            candidates = [
                text,
                text.replace('ALG.', ''),
                text.split('.')[-1],
                text.replace('.', '-').replace('ALG-', ''),
            ]
            for item in candidates:
                bits = get_algorithm_key_bits(item)
                if bits in valid_key_bits:
                    return bits
                bits = extract_key_size_from_api_name(item)
                if bits in valid_key_bits:
                    return bits
        except Exception:
            return None
        return None

    literal_args = getattr(candidate, 'literal_args', {}) or {}
    ctx_bits = _normalize_bits(literal_args.get('_ctx_key_bits'))
    if ctx_bits is not None:
        return ctx_bits
    for value in literal_args.values():
        bits = _normalize_bits(value)
        if bits is not None:
            return bits
    for value in (
        getattr(candidate, 'profile_id', None),
        getattr(candidate, 'symbol', None),
    ):
        bits = _bits_from_profile_or_symbol(value)
        if bits is not None:
            return bits
    return None


def normalize_native_crypto_symbol(symbol: Any, language: str) -> str:
    text = str(symbol or '').strip()
    if not text:
        return ''

    tail = normalize_func_name(text).lower()
    if tail in _NON_CRYPTO_TERMINAL_MEMBERS:
        return ''
    if language in {'c', 'cpp'} and is_c_non_crypto_callsite_symbol(text):
        return ''

    if language == 'python':
        if _is_python_non_crypto_symbol(text):
            return ''
        # Reject chained result-object methods such as
        # hashlib.sha256(...).hexdigest / value.encode.
        if ').' in text and tail not in {
            'new',
            'encrypt',
            'decrypt',
            'sign',
            'verify',
            'update',
            'final',
            'finalize',
            'dofinal',
        }:
            return ''
    return text


def append_augmented_finding(
    findings: List[Finding],
    existing_keys: Set[Tuple[int, str, Optional[str]]],
    *,
    file_path: str,
    line: int,
    symbol: str,
    profile_id: str,
    key_bits: Optional[int],
    source: str,
    rule_id: str,
    severity: str,
    reason: str,
    recommendation: str,
    algorithm: str,
    confidence: float,
    wrapper_chain: Optional[List[str]] = None,
    key_bits_reason: Optional[str] = None,
) -> None:
    # [FIX] 同一 candidate（line + symbol）只保留一个最强结果。
    # 这样可以避免同一个调用点同时被 API / wrapper / 上下文传播命中后，
    # 产生多个 profile 版本的重复 finding。
    base_key = (line, symbol, None)

    def _rank(pid: str, source_name: str, chain: Optional[List[str]]) -> Tuple[int, int, int, int]:
        pid_u = str(pid or '').upper()
        source_l = str(source_name or '').lower()
        chain_len = len(chain or [])

        # 更可信的来源优先：api > import/library > wrapper > propagation > fallback
        source_rank = {
            'api': 0,
            'import': 1,
            'library': 1,
            'wrapper': 2,
            'propagation': 3,
            'context': 3,
            'fallback': 4,
            'unknown': 5,
        }.get(source_l, 4)

        # 更具体的算法优先
        concrete_rank = 0 if pid_u.startswith('ALG.') and not pid_u.startswith(('UTIL.', 'PRIM.', 'RNG.')) else 1

        # 更短的 wrapper 链优先
        return (source_rank, concrete_rank, chain_len, 0 if pid_u else 1)

    # 查找同一行同一符号的已存在 finding
    existing_idx = None
    existing_item = None
    for idx, item in enumerate(findings):
        if getattr(item, 'line', None) == line and getattr(item, 'symbol', None) == symbol:
            existing_idx = idx
            existing_item = item
            break

    if existing_item is not None:
        existing_profile = getattr(existing_item, 'profile_id', None)
        existing_source = ''
        existing_chain = getattr(existing_item, 'wrapper_chain', []) or []
        existing_evidence = getattr(existing_item, 'evidence', None)
        if isinstance(existing_evidence, dict):
            existing_source = str(existing_evidence.get('source', '') or '')

        new_rank = _rank(profile_id, source, wrapper_chain)
        old_rank = _rank(existing_profile, existing_source, existing_chain)

        # 只有在新证据更强时才替换旧 finding
        if new_rank >= old_rank:
            return

        # 替换旧 finding（不保留多个 profile 版本）
        existing_keys.discard((line, symbol, existing_profile))
        findings.pop(existing_idx)

    evidence = {
        'source': source,
        'algorithm': algorithm,
        'key_bits': key_bits,
        'confidence': confidence,
    }
    if key_bits is None and not key_bits_reason:
        chain = wrapper_chain or [symbol]
        chain_text = ' -> '.join(str(item) for item in chain if item)
        key_bits_reason = (
            f"无法通过静态分析得到 key_bits；封装传播链：{chain_text or symbol}。"
            "当前调用点未暴露可解析的固定密钥长度，密钥可能来自函数参数、配置、外部输入或上游 wrapper 实参；"
            "需要继续解析链头 API 的密钥参数或调用点实参来源。"
        )
    elif key_bits is not None and not key_bits_reason and wrapper_chain and len(wrapper_chain) > 1:
        chain_text = ' -> '.join(str(item) for item in wrapper_chain if item)
        key_bits_reason = (
            f"key_bits 由封装链传播得到：{chain_text or symbol}。"
            "该值来自链内较低层 crypto API 的密钥表达式、固定长度转换或固定算法语义；"
            "未使用无关 API 的 key_bits。"
        )
    if key_bits_reason:
        evidence['key_bits_reason'] = key_bits_reason
    findings.append(Finding(
        file=file_path,
        line=line,
        symbol=symbol,
        rule_id=rule_id,
        layer='phase2',
        category='crypto_api',
        quantum_secure=False,
        severity=severity,
        reason=reason,
        recommendation=recommendation,
        profile_id=profile_id,
        key_bits=key_bits,
        key_bits_reason=key_bits_reason,
        evidence=evidence,
        literals=[],
        wrapper_chain=wrapper_chain or [symbol],
    ))
    existing_keys.add((line, symbol, profile_id))


def _resolve_symbol_from_maps(
    symbol: str,
    maps: List[Dict[str, Any]],
    validator=None,
    language: str = '',
) -> Optional[Any]:
    if not symbol:
        return None
    tail = symbol.split('.')[-1]
    for symbol_map in maps:
        if not isinstance(symbol_map, dict):
            continue
        keys = [symbol]
        if language == 'python':
            if _allow_python_tail_fallback(symbol) and tail not in keys:
                keys.append(tail)
        elif tail not in keys:
            keys.append(tail)
        for key in keys:
            if key not in symbol_map:
                continue
            value = symbol_map[key]
            if validator is None or validator(value):
                return value
    return None


def resolve_wrapper_profile(
    symbol: str,
    local_profiles: Dict[str, str],
    cross_file_profiles: Dict[str, str],
    language: str = '',
) -> Optional[str]:
    resolved = _resolve_symbol_from_maps(
        symbol,
        [local_profiles, cross_file_profiles],
        language=language,
    )
    return resolved if isinstance(resolved, str) else None


def resolve_wrapper_chain(
    symbol: str,
    local_chains: Dict[str, List[str]],
    cross_file_chains: Dict[str, List[str]],
    language: str = '',
) -> Optional[List[str]]:
    resolved = _resolve_symbol_from_maps(
        symbol,
        [local_chains, cross_file_chains],
        validator=lambda value: isinstance(value, list),
        language=language,
    )
    return resolved if isinstance(resolved, list) else None


def resolve_wrapper_key_bits(
    symbol: str,
    local_key_bits: Dict[str, int],
    cross_file_key_bits: Dict[str, int],
    language: str = '',
) -> Optional[int]:
    resolved = _resolve_symbol_from_maps(
        symbol,
        [local_key_bits, cross_file_key_bits],
        validator=lambda value: isinstance(value, int),
        language=language,
    )
    return resolved if isinstance(resolved, int) else None


def build_cross_file_wrapper_profiles(
    scanner_ref: Any,
    lang: str,
    file_path: str,
    max_files: Optional[int] = None,
    return_context: bool = False,
    root_dir: Optional[str] = None,
    source_files: Optional[List[str]] = None,
    source_features: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, str]:
    if scanner_ref is None:
        return {}

    suffix = LANG_SUFFIX_MAP.get(lang)
    if not suffix:
        return {}
    suffixes = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'] if lang == 'c' else [suffix]

    current = Path(file_path) if file_path and not str(file_path).startswith('<') else None
    if source_files is None:
        if current is None or not current.exists() or not current.is_file():
            return {}
        root = Path(root_dir).resolve() if root_dir else current.parent
        files_to_scan = sorted(
            source_file
            for suffix_item in suffixes
            for source_file in root.rglob(f'*{suffix_item}')
        )
    else:
        root = Path(root_dir).resolve() if root_dir else (current.parent if current is not None else Path.cwd())
        files_to_scan = sorted(
            Path(p)
            for p in source_files
            if any(str(p).lower().endswith(suffix_item) for suffix_item in suffixes)
        )

    cache_limit = -1 if max_files is None else int(max_files)
    if source_files is None:
        source_sig = "*"
    else:
        try:
            source_sig = str(hash(tuple(str(Path(p).resolve()) for p in files_to_scan)))
        except Exception:
            source_sig = str(len(files_to_scan))
    cache_key = (f"{root.resolve()}::{source_sig}", lang, cache_limit)
    if cache_key in _CROSS_FILE_WRAPPER_CACHE:
        if return_context:
            return (
                _CROSS_FILE_WRAPPER_CACHE[cache_key],
                _CROSS_FILE_WRAPPER_CHAIN_CACHE.get(cache_key, {}),
                _CROSS_FILE_WRAPPER_KEY_BITS_CACHE.get(cache_key, {}),
            )
        return _CROSS_FILE_WRAPPER_CACHE[cache_key]

    profiles: Dict[str, str] = {}
    chains: Dict[str, List[str]] = {}
    key_bits_map: Dict[str, int] = {}
    call_edges: Dict[str, Set[str]] = {}
    known_wrappers: Set[str] = set()
    scoped_to_short: Dict[str, str] = {}
    short_to_scoped: Dict[str, Set[str]] = {}
    api_owner_by_file: Dict[str, Dict[str, str]] = {}
    files_seen = 0

    def _rel_source_key(source_file: Path) -> str:
        try:
            return str(source_file.resolve().relative_to(root.resolve())).replace('\\', '/')
        except Exception:
            return str(source_file).replace('\\', '/')

    def _scoped_func(source_file: Path, func_name: Any) -> str:
        raw_name = str(func_name or '').strip()
        if ' [' in raw_name:
            raw_name = raw_name.split(' [', 1)[0].strip()
        if '::' in raw_name:
            raw_name = raw_name.split('::', 1)[-1].strip()
        if lang in {'python', 'java'} and '.' in raw_name:
            name = raw_name
        else:
            name = normalize_func_name(raw_name)
        if not name:
            return ''
        return f"{_rel_source_key(source_file)}::{name}"

    def _register_func_scope(source_file: Path, func_name: Any) -> str:
        scoped = _scoped_func(source_file, func_name)
        short = normalize_func_name(str(func_name or ''))
        if scoped and short:
            known_wrappers.add(scoped)
            scoped_to_short[scoped] = short
            short_to_scoped.setdefault(short, set()).add(scoped)
        return scoped

    def _store_wrapper_context(
        key: str,
        short_name: str,
        profile_id: str,
        chain: List[str],
        key_bits: Optional[int] = None,
    ) -> None:
        if not key or not is_concrete_profile_id(profile_id):
            return
        profiles.setdefault(key, profile_id)
        chains.setdefault(key, chain)
        if isinstance(key_bits, int):
            key_bits_map[key] = key_bits
        if short_name:
            scoped_to_short[key] = short_name
            short_to_scoped.setdefault(short_name, set()).add(key)
        if '::' in key:
            _, func_name = key.split('::', 1)
            func_name = str(func_name or '').strip()
            if func_name and '.' in func_name:
                profiles.setdefault(func_name, profile_id)
                chains.setdefault(func_name, list(chain))
                if isinstance(key_bits, int):
                    key_bits_map[func_name] = key_bits
                scoped_to_short[func_name] = normalize_func_name(func_name)
                short_to_scoped.setdefault(normalize_func_name(func_name), set()).add(key)

    def _source_label_from_rel(rel_key: str) -> str:
        if lang == 'python':
            path = Path(rel_key)
            module_parts = [part for part in path.with_suffix('').parts if part and part != '__init__']
            if module_parts:
                return '.'.join(module_parts).replace('\\', '.').replace('/', '.')
        if lang == 'java':
            path = Path(rel_key)
            module_parts = [part for part in path.with_suffix('').parts if part]
            if module_parts:
                return '.'.join(module_parts).replace('\\', '.').replace('/', '.')
        parent = str(Path(rel_key).parent).replace('\\', '/')
        return parent if parent and parent != '.' else str(Path(rel_key).stem)

    def _display_wrapper(scoped_or_name: str) -> str:
        text = str(scoped_or_name or '').strip()
        if not text or ' [' in text:
            return text
        if '::' in text:
            rel_key, func_name = text.split('::', 1)
            label_name = func_name if (lang in {'python', 'java'} and '.' in func_name) else normalize_func_name(func_name)
            return f"{label_name} [{_source_label_from_rel(rel_key)}]"
        return text

    def _remember_api_owner(source_file: Path, call: Dict[str, Any]) -> None:
        owner = str(call.get('pkg_full') or '').strip()
        if not owner:
            candidates = call.get('pkg_full_candidates') or []
            if candidates:
                owner = str(candidates[0] or '').strip()
        if not owner:
            resolved = str(call.get('resolved_symbol') or '').strip()
            symbol = str(call.get('symbol') or '').strip()
            if resolved and symbol and resolved != symbol and resolved.endswith(symbol):
                owner = resolved[: -len(symbol)].rstrip('.')
        if not owner:
            return
        rel_key = _rel_source_key(source_file)
        bucket = api_owner_by_file.setdefault(rel_key, {})
        for key in (
            str(call.get('symbol') or '').strip(),
            str(call.get('resolved_symbol') or '').strip(),
            str(call.get('code') or '').strip(),
        ):
            if key:
                bucket.setdefault(key, owner)

    def _display_api(symbol: str, source_file: Path) -> str:
        text = str(symbol or '').strip()
        if not text or ' [' in text:
            return text
        owner = api_owner_by_file.get(_rel_source_key(source_file), {}).get(text)
        if owner:
            return f"{text} [{owner}]"
        return text

    def _normalize_java_receiver_symbol(receiver_type: Any, member: Any) -> str:
        if lang != 'java':
            return ''
        recv = str(receiver_type or '').strip()
        meth = str(member or '').strip()
        if not recv or not meth:
            return ''
        if recv.lower().startswith('new '):
            recv = recv[4:].strip()
        if '(' in recv:
            recv = recv.split('(', 1)[0].strip()
        if '<' in recv:
            recv = recv.split('<', 1)[0].strip()
        if '.' in recv:
            recv = recv.rsplit('.', 1)[-1].strip()
        if not recv:
            return ''
        return f"{recv}.{meth}"

    def _display_chain_for_file(chain: List[str], source_file: Path) -> List[str]:
        rel_key = _rel_source_key(source_file)
        local_scopes = short_to_scoped
        displayed: List[str] = []
        for idx, item in enumerate(chain or []):
            item_text = str(item or '').strip()
            if not item_text:
                continue
            if idx == 0 and _is_native_crypto_symbol(item_text):
                displayed.append(_display_api(item_text, source_file))
                continue
            if lang in {'python', 'java'} and '.' in item_text:
                item_norm = item_text
            else:
                item_norm = normalize_func_name(item_text)
            scoped = f"{rel_key}::{item_norm}" if item_norm else ''
            if scoped in scoped_to_short or scoped in known_wrappers:
                displayed.append(_display_wrapper(scoped))
            else:
                displayed.append(item_text)
        return displayed

    def _resolve_concrete_contract_profile(wrapper_contract: Dict[str, Any]) -> Optional[str]:
        profile_id = wrapper_contract.get('profile_id')
        api_symbol = str(wrapper_contract.get('api_symbol', '') or '')
        key_arg_expr = str(wrapper_contract.get('key_arg_expr', '') or '').strip()

        if is_concrete_profile_id(profile_id):
            if profile_id == 'ALG.RSA' and re.search(r'generate|encrypt|decrypt', api_symbol, re.I):
                return 'ALG.RSA.PKE'
            return profile_id

        args: List[Dict[str, Any]] = []
        if key_arg_expr:
            args.append({'value': key_arg_expr.strip('"\'')})

        resolved = resolve_concrete_profile_from_call(
            scanner_ref,
            api_symbol,
            lang,
            args=args,
        )

        # RSA key-generation / encryption wrappers should be tracked as PKE.
        if resolved == 'ALG.RSA' and re.search(r'generate|encrypt|decrypt', api_symbol, re.I):
            return 'ALG.RSA.PKE'

        return resolved

    def _extract_contract_key_bits(wrapper_contract: Dict[str, Any]) -> Optional[int]:
        if scanner_ref is None:
            return None
        try:
            bits = scanner_ref._evaluate_wrapper_key_bits(
                wrapper_contract,
                {'args': []},
            )
            valid_bits = as_valid_key_bits(bits)
            if valid_bits is not None:
                return valid_bits
        except Exception:
            pass
        return None

    def _is_native_crypto_symbol(symbol: Any) -> bool:
        text = normalize_native_crypto_symbol(symbol, lang)
        if not text:
            return False
        if lang == 'c':
            text_u = text.upper()
            c_native_prefixes = (
                'EVP_', 'RSA_', 'DSA_', 'DH_', 'EC_', 'ECDH_', 'ECDSA_', 'AES_',
                'DES_', 'SHA', 'MD5', 'HMAC', 'CMAC', 'HKDF', 'PKCS5_', 'PKCS12_',
                'RAND_', 'BN_', 'X509_', 'PEM_', 'BIO_',
            )
            if not text_u.startswith(c_native_prefixes):
                return False
        try:
            if scanner_ref is not None:
                return is_concrete_profile_id(resolve_concrete_profile_from_call(scanner_ref, text, lang))
        except Exception:
            pass
        if '.' not in text:
            return False
        return False

    def _contract_has_native_crypto_anchor(wrapper_contract: Dict[str, Any]) -> bool:
        api_symbol = str(wrapper_contract.get('api_symbol', '') or '')
        if lang == 'python' and is_concrete_profile_id(wrapper_contract.get('profile_id')):
            key_arg_expr = str(wrapper_contract.get('key_arg_expr', '') or '').strip()
            if _looks_like_crypto_name(api_symbol) or _looks_like_crypto_name(key_arg_expr):
                return True
        if _is_native_crypto_symbol(api_symbol):
            return True
        for item in wrapper_contract.get('wrapper_chain', []) or []:
            if _is_native_crypto_symbol(item):
                return True
        return False

    for source_file in files_to_scan:
        if source_files is None and current is not None and source_file == current:
            continue
        if max_files is not None and files_seen >= max_files:
            break

        try:
            cached_features = source_features.get(str(source_file)) if isinstance(source_features, dict) else None
            if isinstance(cached_features, dict):
                features = cached_features
            else:
                source_code = source_file.read_text(encoding='utf-8', errors='replace')
                features = extract_features(source_code, lang)
            module_name = source_file.stem if lang in {'python', 'java'} else ''
            scanner_ref._function_params = {
                fn.get('name', ''): fn.get('params', [])
                for fn in features.get('functions', [])
            }

            local_func_scopes: Dict[str, str] = {}
            local_tail_scopes: Dict[str, Set[str]] = {}
            for fn in features.get('functions', []):
                if lang == 'python':
                    fn_name = str(fn.get('qualified_name') or fn.get('normalized_name') or normalize_func_name(fn.get('name', '')))
                else:
                    fn_name = str(fn.get('normalized_name') or normalize_func_name(fn.get('name', '')))
                if lang == 'c' and _is_c_non_crypto_wrapper_name(fn_name):
                    continue
                if fn_name:
                    scoped_fn = _register_func_scope(source_file, fn_name)
                    local_func_scopes[fn_name] = scoped_fn
                    fn_tail = normalize_func_name(fn_name)
                    if fn_tail:
                        local_tail_scopes.setdefault(fn_tail, set()).add(scoped_fn)
                    if module_name:
                        # Python module-qualified names are only aliases for
                        # uniquely resolved project wrappers; Java reuses the
                        # same mechanism with ClassName.method keys.
                        local_func_scopes[f"{module_name}.{fn_name}"] = scoped_fn
                        scoped_to_short[f"{module_name}.{fn_name}"] = normalize_func_name(fn_name)

            for call in features.get('calls', []):
                if isinstance(call, dict):
                    _remember_api_owner(source_file, call)
                raw_symbol = str(call.get('symbol', '') or '')
                if not raw_symbol:
                    continue
                resolved_symbol = str(call.get('resolved_symbol', raw_symbol) or raw_symbol)
                resolved_member = str(call.get('resolved_member', '') or '')
                java_receiver_symbol = _normalize_java_receiver_symbol(call.get('receiver_type', ''), resolved_member or raw_symbol.split('.')[-1])
                callee_short = normalize_func_name(resolved_member or resolved_symbol)
                if lang == 'c' and _is_c_non_crypto_wrapper_name(callee_short):
                    callee_short = ''
                callee = (
                    local_func_scopes.get(resolved_symbol)
                    or local_func_scopes.get(raw_symbol, '')
                    or local_func_scopes.get(java_receiver_symbol, '')
                )
                if not callee and callee_short:
                    tail_candidates = local_tail_scopes.get(callee_short, set())
                    if len(tail_candidates) == 1:
                        callee = next(iter(tail_candidates))

                scope = call.get('scope', {})
                if lang == 'python':
                    caller_short = str(
                        call.get('owner_function_qualified')
                        or call.get('owner_function')
                        or call.get('owner_function_normalized')
                        or ''
                    )
                else:
                    caller_short = str(call.get('owner_function_normalized') or normalize_func_name(call.get('owner_function', '')))
                if isinstance(scope, dict):
                    caller_short = caller_short or normalize_func_name(scope.get('function_name') or scope.get('function') or '')
                if not caller_short:
                    caller_short = normalize_func_name(call.get('function', ''))
                if lang == 'c' and _is_c_non_crypto_wrapper_name(caller_short):
                    continue
                caller = (
                    local_func_scopes.get(caller_short)
                    or local_func_scopes.get(normalize_func_name(caller_short))
                    or _scoped_func(source_file, caller_short)
                )
                if not caller:
                    continue

                _register_func_scope(source_file, caller_short)
                # Only same-file function calls are linked by short names. Calls
                # to external packages/modules must be resolved by explicit
                # import/package metadata, not by a project-wide short name like
                # Start/Run/NewClient.
                if callee:
                    call_edges.setdefault(caller, set()).add(callee)

                call_profile = None
                if _is_native_crypto_symbol(resolved_symbol):
                    call_profile = resolve_concrete_profile_from_call(
                        scanner_ref,
                        resolved_symbol,
                        lang,
                        args=call.get('args', []) or [],
                    )
                if is_concrete_profile_id(call_profile):
                    caller_norm = normalize_func_name(caller_short)
                    native_anchor = normalize_native_crypto_symbol(resolved_symbol, lang)
                    if not native_anchor:
                        continue
                    chain = [_display_api(native_anchor, source_file), _display_wrapper(caller)]
                    _store_wrapper_context(caller, caller_norm, call_profile, chain)

            contracts = scanner_ref._build_local_wrapper_contracts(
                features.get('functions', []),
                features.get('calls', []),
                lang,
                features.get('var_assignments', []),
            )
        except Exception:
            continue

        files_seen += 1
        for symbol, wrapper_contract in contracts.items():
            symbol_text = str(symbol or '').strip()
            variant_suffix = ''
            base_symbol_text = symbol_text
            if lang == 'c' and '@@' in symbol_text:
                base_symbol_text, variant_suffix = symbol_text.split('@@', 1)
                variant_suffix = f"@@{variant_suffix}" if variant_suffix else ''
            norm_symbol = normalize_func_name(symbol_text)
            if lang == 'python' and '.' in symbol_text:
                symbol_name = symbol_text
            else:
                symbol_name = normalize_func_name(base_symbol_text)
            if lang == 'c' and _is_c_non_crypto_wrapper_name(symbol_name):
                continue
            if lang == 'python':
                if not symbol_name or '.' not in symbol_name:
                    for fn in features.get('functions', []):
                        if not isinstance(fn, dict):
                            continue
                        fn_name = str(fn.get('name', '') or '').strip()
                        if fn_name == symbol_text:
                            class_name = str(fn.get('class_name', '') or '').strip()
                            if class_name and norm_symbol:
                                symbol_name = f"{class_name}.{norm_symbol}"
                            break
            scoped_symbol = _register_func_scope(source_file, symbol_name)
            scoped_store_key = f"{scoped_symbol}{variant_suffix}" if variant_suffix else scoped_symbol
            profile_id = _resolve_concrete_contract_profile(wrapper_contract)
            if is_concrete_profile_id(profile_id) and _contract_has_native_crypto_anchor(wrapper_contract):
                qualified_symbol = f"{module_name}.{symbol_name}" if module_name and symbol_name else ''
                qualified_store_key = f"{qualified_symbol}{variant_suffix}" if qualified_symbol and variant_suffix else qualified_symbol

                contract_chain = list(wrapper_contract.get('wrapper_chain', []))
                if not contract_chain:
                    api_symbol = str(wrapper_contract.get('api_symbol', '') or '')
                    contract_chain = [api_symbol] if api_symbol else [symbol]
                if lang == 'python' and contract_chain:
                    first_item = str(contract_chain[0] or '').strip()
                    if first_item in {'Cipher', 'cryptography.hazmat.primitives.ciphers.Cipher'}:
                        key_expr = str(wrapper_contract.get('key_arg_expr', '') or '').strip()
                        match = re.search(r'([A-Za-z_][\w\.]*\.[A-Za-z_][\w]*)\s*\(', key_expr)
                        if match:
                            contract_chain[0] = match.group(1)
                contract_chain = _display_chain_for_file(contract_chain, source_file)

                bits = _extract_contract_key_bits(wrapper_contract)
                _store_wrapper_context(scoped_store_key, norm_symbol, profile_id, contract_chain, bits)
                if symbol_name and '.' in symbol_name:
                    symbol_store_key = f"{symbol_name}{variant_suffix}" if variant_suffix else symbol_name
                    profiles[symbol_store_key] = profile_id
                    chains[symbol_store_key] = list(contract_chain)
                    if isinstance(bits, int):
                        key_bits_map[symbol_store_key] = bits
                    scoped_to_short[symbol_store_key] = norm_symbol
                    short_to_scoped.setdefault(norm_symbol, set()).add(scoped_store_key)
                if qualified_store_key:
                    profiles[qualified_store_key] = profile_id
                    chains[qualified_store_key] = list(contract_chain)
                    if isinstance(bits, int):
                        key_bits_map[qualified_store_key] = bits
                    scoped_to_short[qualified_store_key] = norm_symbol
                    short_to_scoped.setdefault(norm_symbol, set()).add(scoped_store_key)

    if known_wrappers and call_edges:
        def _collect_wrapper_variants(wrapper_name: str) -> List[Tuple[str, List[str], Optional[int]]]:
            wrapper_text = str(wrapper_name or '').strip()
            if not wrapper_text:
                return []
            rows: List[Tuple[str, List[str], Optional[int]]] = []
            seen = set()
            for candidate_key, candidate_profile in profiles.items():
                candidate_text = str(candidate_key or '').strip()
                if not candidate_text.startswith(f"{wrapper_text}@@"):
                    continue
                if not is_concrete_profile_id(candidate_profile):
                    continue
                candidate_chain = list(chains.get(candidate_text, []) or [])
                candidate_bits = key_bits_map.get(candidate_text)
                row_key = (
                    str(candidate_profile),
                    tuple(candidate_chain),
                    int(candidate_bits) if isinstance(candidate_bits, int) else None,
                )
                if row_key in seen:
                    continue
                seen.add(row_key)
                rows.append((str(candidate_profile), candidate_chain, candidate_bits if isinstance(candidate_bits, int) else None))
            return rows

        changed = True
        while changed:
            changed = False
            for caller, callees in call_edges.items():
                caller_name = str(caller or '').strip()
                caller_short = scoped_to_short.get(caller_name) or normalize_func_name(caller_name)
                if not caller_name or caller_name not in known_wrappers:
                    continue
                if caller_name in profiles and is_concrete_profile_id(profiles.get(caller_name)):
                    continue

                for callee in callees:
                    callee_name = str(callee or '').strip()
                    callee_short = scoped_to_short.get(callee_name) or normalize_func_name(callee_name)
                    candidates = [callee]
                    if callee_name and callee_name not in candidates:
                        candidates.append(callee_name)

                    selected = ''
                    callee_profile = None
                    for callee_candidate in candidates:
                        if callee_candidate not in known_wrappers:
                            continue
                        candidate_profile = profiles.get(callee_candidate)
                        if is_concrete_profile_id(candidate_profile):
                            selected = callee_candidate
                            callee_profile = candidate_profile
                            break

                    if not selected or not is_concrete_profile_id(callee_profile):
                        continue
                    profiles[caller_name] = callee_profile
                    callee_chain = chains.get(selected) or chains.get(callee_name, [callee_short or callee_name])
                    caller_chain = list(callee_chain)
                    if not caller_chain or normalize_func_name(caller_chain[-1]) != caller_short:
                        caller_chain.append(_display_wrapper(caller_name))
                    chains[caller_name] = caller_chain

                    callee_bits = key_bits_map.get(selected)
                    if not isinstance(callee_bits, int):
                        callee_bits = key_bits_map.get(callee_name)
                    if isinstance(callee_bits, int):
                        key_bits_map[caller_name] = callee_bits
                    for variant_index, (variant_profile, variant_chain, variant_bits) in enumerate(_collect_wrapper_variants(selected), start=1):
                        caller_variant_key = f"{caller_name}@@{variant_index}"
                        caller_variant_chain = list(variant_chain or [])
                        if not caller_variant_chain or normalize_func_name(caller_variant_chain[-1]) != caller_short:
                            caller_variant_chain.append(_display_wrapper(caller_name))
                        if profiles.get(caller_variant_key) != variant_profile:
                            profiles[caller_variant_key] = variant_profile
                            chains[caller_variant_key] = caller_variant_chain
                            if isinstance(variant_bits, int):
                                key_bits_map[caller_variant_key] = variant_bits
                            changed = True
                    changed = True
                    break

    # Expose short wrapper names only when they identify exactly one scoped
    # function in the project. This keeps cross-file call sites usable for
    # specific wrappers while preventing generic names (Start/Run/NewClient)
    # from merging unrelated packages/files.
    for short_name, scoped_names in list(short_to_scoped.items()):
        if lang == 'java':
            # Java cross-file propagation should prefer ClassName.method keys.
            # Exposing bare short names like add/encrypt/fillDetail causes
            # project-wide collisions and false positives.
            continue
        if lang == 'python' and not _allow_python_tail_fallback(short_name):
            continue
        short_tail = normalize_func_name(short_name).lower()
        if short_tail in {
            'get', 'set', 'put', 'add', 'new', 'init', 'run', 'start', 'stop',
            'open', 'close', 'read', 'write', 'load', 'save', 'parse', 'encode',
            'decode', 'config', 'service', 'execute', 'process', 'handle',
            'encrypt', 'decrypt', 'update', 'final', 'finalize', 'sign', 'verify',
            'generate', 'filldetail',
        }:
            continue
        profiled_scopes = [name for name in scoped_names if is_concrete_profile_id(profiles.get(name))]
        if len(profiled_scopes) != 1:
            continue
        scoped_name = profiled_scopes[0]
        if short_name not in profiles:
            profiles[short_name] = profiles[scoped_name]
        if scoped_name in chains and short_name not in chains:
            chains[short_name] = list(chains[scoped_name])
        if isinstance(key_bits_map.get(scoped_name), int) and short_name not in key_bits_map:
            key_bits_map[short_name] = key_bits_map[scoped_name]

    if chains:
        changed = True
        while changed:
            changed = False
            for symbol, chain in list(chains.items()):
                symbol_norm = normalize_func_name(symbol)
                targets = [symbol]
                if '::' not in str(symbol) and symbol_norm and symbol_norm not in targets:
                    targets.append(symbol_norm)
                if any(isinstance(key_bits_map.get(target), int) for target in targets):
                    continue

                inherited_bits = None
                for item in reversed(list(chain or [])):
                    item_norm = normalize_func_name(item)
                    for key in (item, item_norm):
                        if key and isinstance(key_bits_map.get(key), int):
                            inherited_bits = key_bits_map[key]
                            break
                    if inherited_bits is not None:
                        break

                if inherited_bits is None:
                    continue
                for target in targets:
                    if target and not isinstance(key_bits_map.get(target), int):
                        key_bits_map[target] = inherited_bits
                        changed = True

    # Expose stable class-qualified aliases for scoped wrappers such as
    # "path/to/file.py::AtClient.query" -> "AtClient.query" so external
    # call-sites that resolve only to the class/method can match project-level
    # wrapper contracts.
    for scoped_name, profile_id in list(profiles.items()):
        if '::' not in str(scoped_name):
            continue
        rel_key, func_name = str(scoped_name).split('::', 1)
        func_name = str(func_name or '').strip()
        if not func_name or '.' not in func_name:
            continue
        if func_name not in profiles:
            profiles[func_name] = profile_id
        if scoped_name in chains and func_name not in chains:
            chains[func_name] = list(chains[scoped_name])
        if isinstance(key_bits_map.get(scoped_name), int) and func_name not in key_bits_map:
            key_bits_map[func_name] = key_bits_map[scoped_name]
        module_alias = f"{Path(rel_key).stem}.{func_name}"
        if module_alias not in profiles:
            profiles[module_alias] = profile_id
        if scoped_name in chains and module_alias not in chains:
            chains[module_alias] = list(chains[scoped_name])
        if isinstance(key_bits_map.get(scoped_name), int) and module_alias not in key_bits_map:
            key_bits_map[module_alias] = key_bits_map[scoped_name]

    _CROSS_FILE_WRAPPER_CACHE[cache_key] = profiles
    _CROSS_FILE_WRAPPER_CHAIN_CACHE[cache_key] = chains
    _CROSS_FILE_WRAPPER_KEY_BITS_CACHE[cache_key] = key_bits_map

    if return_context:
        return profiles, chains, key_bits_map
    return profiles


def reconcile_symbolic_findings(
    *,
    findings: List[Finding],
    line_to_func: Optional[Dict[int, str]] = None,
    obj_profile: Optional[Dict[str, str]] = None,
    obj_key_bits: Optional[Dict[str, int]] = None,
    valid_key_bits: Optional[Set[int]] = None,
    key_bits_line_window: int = 8,
) -> List[Finding]:
    line_to_func = line_to_func or {}
    obj_profile = obj_profile or {}
    obj_key_bits = obj_key_bits or {}
    if valid_key_bits is None:
        valid_key_bits = _DEFAULT_VALID_KEY_BITS

    no_profile_bits: List[Dict[str, Any]] = []

    for finding in findings:
        if getattr(finding, 'profile_id', None) is None:
            finding_bits = getattr(finding, 'key_bits', None)
            if finding_bits is None:
                finding_ev = getattr(finding, 'evidence', {}) or {}
                finding_bits = finding_ev.get('key_bits') if isinstance(finding_ev, dict) else None
            finding_bits = as_valid_key_bits(finding_bits, valid_key_bits)
            if finding_bits is not None:
                line = getattr(finding, 'line', 0) or 0
                finding_ev = getattr(finding, 'evidence', {}) or {}
                alg_hint = finding_ev.get('algorithm', '') if isinstance(finding_ev, dict) else ''
                sym_hint = getattr(finding, 'symbol', '') or ''
                no_profile_bits.append({
                    'line': line,
                    'key_bits': finding_bits,
                    'family': alg_family(f"{alg_hint} {sym_hint}"),
                    'function': normalize_func_name(line_to_func.get(line, '')),
                })

    if no_profile_bits:
        for finding in findings:
            if getattr(finding, 'profile_id', None) is not None and getattr(finding, 'key_bits', None) is None:
                finding_line = getattr(finding, 'line', 0) or 0
                finding_func = normalize_func_name(line_to_func.get(finding_line, ''))
                finding_pid = getattr(finding, 'profile_id', '') or ''
                finding_ev = getattr(finding, 'evidence', {}) or {}
                finding_alg = finding_ev.get('algorithm', '') if isinstance(finding_ev, dict) else ''
                finding_family = alg_family(f"{finding_pid} {finding_alg} {getattr(finding, 'symbol', '') or ''}")

                candidates = [
                    record for record in no_profile_bits
                    if record['line'] > 0 and abs(record['line'] - finding_line) <= key_bits_line_window
                ]
                if finding_func:
                    same_func = [record for record in candidates if record['function'] == finding_func]
                    if same_func:
                        candidates = same_func
                if finding_family:
                    same_family = [record for record in candidates if record.get('family') == finding_family]
                    if not same_family:
                        continue
                    candidates = same_family

                if candidates:
                    nearest = min(candidates, key=lambda record: abs(record['line'] - finding_line))
                    nearest_bits = nearest['key_bits']
                    setattr(finding, 'key_bits', nearest_bits)
                    if isinstance(finding_ev, dict):
                        finding_ev['key_bits'] = nearest_bits

    for finding in findings:
        pid = getattr(finding, 'profile_id', None)
        ev = getattr(finding, 'evidence', {}) or {}
        alg = str(ev.get('algorithm', '')).upper()
        if pid == 'ALG.DILITHIUM' and alg == 'DSA':
            setattr(finding, 'profile_id', 'ALG.DSA')

    findings = [finding for finding in findings if getattr(finding, 'profile_id', None) is not None]

    operation_tokens = get_pipeline_operation_semantic_tokens()

    line_symbols: Dict[int, List[str]] = {}
    func_family_has_anchor: Set[Tuple[str, str]] = set()
    for finding in findings:
        pid = getattr(finding, 'profile_id', '') or ''
        family = alg_family(pid)
        if not family:
            continue
        line = getattr(finding, 'line', 0) or 0
        symbol = str(getattr(finding, 'symbol', '') or '')
        line_symbols.setdefault(line, []).append(symbol)

        func_name = normalize_func_name(line_to_func.get(line, ''))
        symbol_lc = symbol.lower()
        if getattr(finding, 'key_bits', None) is not None or any(tok in symbol_lc for tok in operation_tokens):
            func_family_has_anchor.add((func_name, family))

    pruned: List[Finding] = []
    for finding in findings:
        pid = getattr(finding, 'profile_id', '') or ''
        family = alg_family(pid)
        line = getattr(finding, 'line', 0) or 0
        symbol = str(getattr(finding, 'symbol', '') or '')
        symbol_lc = symbol.lower()
        rule_id = str(getattr(finding, 'rule_id', '') or '')
        is_symbolic_fallback = (rule_id == 'quantum_deprecated')

        drop_finding = False

        if is_symbolic_fallback and symbol_lc.endswith('.exchange'):
            same_line_symbols = line_symbols.get(line, [])
            if any(sym != symbol and 'ecdh' in str(sym).lower() for sym in same_line_symbols):
                drop_finding = True

        if (
            is_symbolic_fallback
            and not drop_finding
            and getattr(finding, 'key_bits', None) is None
            and family
        ):
            # 直接工厂/生成类调用不能因为同函数里有更“像操作”的锚点就被剪掉，
            # 否则 KeyAgreement.getInstance("ECDH") 这类必要的上游发现会丢失。
            if any(tok in symbol_lc for tok in ('getinstance', 'generateprivatekey', 'generatekeypair', 'generatesecret')):
                pruned.append(finding)
                continue

            func_name = normalize_func_name(line_to_func.get(line, ''))
            has_anchor = (func_name, family) in func_family_has_anchor
            if has_anchor:
                has_operation_semantics = any(tok in symbol_lc for tok in operation_tokens)
                has_family_semantics = family.lower() in symbol_lc
                if not has_operation_semantics and not has_family_semantics:
                    drop_finding = True

        if not drop_finding:
            pruned.append(finding)

    return pruned


def apply_pipeline_v2_post_augmentations(
    *,
    findings: List[Finding],
    candidates: List[Any],
    kb: Dict[str, Any],
    lang: str,
    file_path: str,
    line_to_func: Optional[Dict[int, str]] = None,
    candidate_func_name_resolver=None,
    gen_methods: Optional[Set[str]] = None,
    init_methods: Optional[Set[str]] = None,
) -> List[Finding]:
    line_to_func = line_to_func or {}
    gen_methods = gen_methods or set()
    init_methods = init_methods or set()

    local_wrapper_profiles = kb.get('_local_wrapper_profiles', {}) if isinstance(kb, dict) else {}
    cross_file_wrapper_profiles = kb.get('_cross_file_wrapper_profiles', {}) if isinstance(kb, dict) else {}
    local_wrapper_chains = kb.get('_local_wrapper_chains', {}) if isinstance(kb, dict) else {}
    cross_file_wrapper_chains = kb.get('_cross_file_wrapper_chains', {}) if isinstance(kb, dict) else {}
    local_wrapper_key_bits = kb.get('_local_wrapper_key_bits', {}) if isinstance(kb, dict) else {}
    cross_file_wrapper_key_bits = kb.get('_cross_file_wrapper_key_bits', {}) if isinstance(kb, dict) else {}
    operation_tokens = get_pipeline_operation_semantic_tokens()

    has_wrapper_index = any(
        isinstance(value, dict) and value
        for value in (
            local_wrapper_profiles,
            cross_file_wrapper_profiles,
            local_wrapper_chains,
            cross_file_wrapper_chains,
        )
    )
    if not candidates and not has_wrapper_index:
        return findings

    def _normalize_java_receiver_symbol_local(receiver_type: Any, member: Any) -> str:
        if lang != 'java':
            return ''
        recv = str(receiver_type or '').strip()
        meth = str(member or '').strip()
        if not recv or not meth:
            return ''
        if recv.lower().startswith('new '):
            recv = recv[4:].strip()
        if '(' in recv:
            recv = recv.split('(', 1)[0].strip()
        if '<' in recv:
            recv = recv.split('<', 1)[0].strip()
        if '.' in recv:
            recv = recv.rsplit('.', 1)[-1].strip()
        if not recv:
            return ''
        return f"{recv}.{meth}"

    def _normalize_tail(symbol: str) -> str:
        tail = normalize_func_name(str(symbol or '').split('.')[-1])
        return tail

    def _looks_like_direct_api(symbol: str) -> bool:
        """Heuristic: direct sink/API calls should keep their own chain instead of inheriting a wrapper chain."""
        text = str(symbol or '').lower()
        tail = _normalize_tail(symbol)
        if not text:
            return False
        if '.' in text:
            prefix = text.split('.', 1)[0]
            if prefix in {
                'aes', 'cipher', 'des', 'dsa', 'ecdh', 'ecdsa', 'ed25519',
                'hmac', 'hkdf', 'md5', 'rand', 'rsa', 'scrypt', 'sha1',
                'sha3', 'sha224', 'sha256', 'sha384', 'sha512', 'subtle',
                'tls', 'x509', 'chacha20', 'chacha20poly1305',
                'curve25519', 'bcrypt', 'argon2', 'nacl', 'box',
                'secretbox',
            }:
                return True
        if tail in operation_tokens:
            return True
        return any(token in text for token in (
            'getinstance', 'init', 'digest', 'finalize', 'dofinal',
            'generatekey', 'encrypt', 'decrypt', 'sign', 'verify',
            'wrap', 'unwrap', 'mac', 'cipher'
        ))

    def _repair_wrapper_chain(finding: Finding, *, anchor_chain: Optional[List[str]] = None) -> None:
        symbol = str(getattr(finding, 'symbol', '') or '')
        if not symbol:
            return

        chain = list(getattr(finding, 'wrapper_chain', []) or [])
        if len(chain) > 1:
            return

        # Direct/native crypto APIs should keep their own sink chain; function-level
        # anchor chains are for wrapper propagation, not for rewriting the native API
        # evidence itself into "sink -> function -> sink".
        if _looks_like_direct_api(symbol):
            return

        if not anchor_chain or len(anchor_chain) <= 1:
            return

        tail = _normalize_tail(symbol)
        lower_anchor = [str(item).lower() for item in anchor_chain]
        if tail and tail not in lower_anchor:
            repaired = list(anchor_chain) + [symbol]
        else:
            repaired = list(anchor_chain)

        if repaired and repaired != chain:
            setattr(finding, 'wrapper_chain', repaired)

    def _append_from_candidate(
        candidate: Any,
        *,
        existing_keys: Set[Tuple[int, str, Optional[str]]],
        profile_id: str,
        key_bits: Optional[int],
        source: str,
        rule_id: str,
        severity: str,
        reason: str,
        recommendation: str,
        confidence: float,
        wrapper_chain: Optional[List[str]] = None,
    ) -> None:
        symbol = getattr(candidate, 'symbol', '')
        location = getattr(candidate, 'location', None)
        line = getattr(location, 'line', 0) if location is not None else 0
        if not symbol or not line:
            return

        append_augmented_finding(
            findings,
            existing_keys,
            file_path=file_path,
            line=line,
            symbol=symbol,
            profile_id=profile_id,
            key_bits=key_bits,
            source=source,
            rule_id=rule_id,
            severity=severity,
            reason=reason,
            recommendation=recommendation,
            algorithm=alg_family(profile_id),
            confidence=confidence,
            wrapper_chain=wrapper_chain,
        )

    def _lookup_wrapper_context(symbol: str) -> Tuple[Optional[str], Optional[List[str]], Optional[int]]:
        symbol_text = str(symbol or '').strip()
        if not symbol_text:
            return None, None, None
        tail = normalize_func_name(symbol_text)
        if lang == 'python' and _is_python_non_crypto_symbol(symbol_text):
            return None, None, None
        if lang == 'c' and is_c_non_crypto_callsite_symbol(symbol_text):
            return None, None, None
        if lang == 'c' and ('.' in symbol_text or '->' in symbol_text):
            keys = [symbol_text, symbol_text.lower()]
            qualified = symbol_text.replace('->', '::').replace('.', '::').strip()
            if qualified and qualified not in keys:
                keys.append(qualified)
            qualified_lc = qualified.lower()
            if qualified_lc and qualified_lc not in keys:
                keys.append(qualified_lc)
            tail_symbol = normalize_func_name(str(symbol_text).split('->')[-1].split('.')[-1])
            if (
                tail_symbol
                and tail_symbol not in keys
                and not _is_c_non_crypto_wrapper_name(tail_symbol)
                and not is_c_non_crypto_callsite_symbol(tail_symbol)
            ):
                keys.append(tail_symbol)
                tail_lc = tail_symbol.lower()
                if tail_lc not in keys:
                    keys.append(tail_lc)
        elif lang == 'python':
            keys = [symbol_text, symbol_text.lower()]
            if _allow_python_tail_fallback(symbol_text):
                for key in (tail, tail.lower()):
                    if key and key not in keys:
                        keys.append(key)
        else:
            keys = [symbol_text, symbol_text.lower(), tail, tail.lower()]
        if '.' in symbol_text and not (lang == 'c' and ('.' in symbol_text or '->' in symbol_text)) and lang != 'python':
            parts = [part for part in symbol_text.split('.') if part]
            for idx in range(1, len(parts)):
                suffix = '.'.join(parts[idx:])
                if suffix and suffix not in keys:
                    keys.append(suffix)
                suffix_lc = suffix.lower()
                if suffix_lc and suffix_lc not in keys:
                    keys.append(suffix_lc)

        profile_id = None
        for mapping in (local_wrapper_profiles, cross_file_wrapper_profiles):
            if not isinstance(mapping, dict):
                continue
            for key in keys:
                profile_id = mapping.get(key)
                if profile_id:
                    break
            if profile_id:
                break

        chain = None
        for mapping in (cross_file_wrapper_chains, local_wrapper_chains):
            if not isinstance(mapping, dict):
                continue
            for key in keys:
                value = mapping.get(key)
                if value:
                    chain = list(value)
                    break
            if chain:
                break

        key_bits = None
        for mapping in (local_wrapper_key_bits, cross_file_wrapper_key_bits):
            if not isinstance(mapping, dict):
                continue
            for key in keys:
                value = mapping.get(key)
                if isinstance(value, int):
                    key_bits = value
                    break
            if isinstance(key_bits, int):
                break

        if lang == 'python' and not is_concrete_profile_id(profile_id) and '.' in symbol_text:
            member_tail = normalize_func_name(symbol_text)
            if member_tail and not _is_python_non_crypto_symbol(member_tail):
                candidate_rows: List[Tuple[str, str, Optional[List[str]], Optional[int]]] = []
                candidate_profiles: Set[str] = set()
                for mapping_name, mapping in (
                    ('local', local_wrapper_profiles),
                    ('cross', cross_file_wrapper_profiles),
                ):
                    if not isinstance(mapping, dict):
                        continue
                    for key, value in mapping.items():
                        key_text = str(key or '').strip()
                        if not is_concrete_profile_id(value):
                            continue
                        if normalize_func_name(key_text) != member_tail:
                            continue
                        wrapper_member_text = key_text.split('::', 1)[-1] if '::' in key_text else key_text
                        if '.' not in wrapper_member_text:
                            continue
                        wrapper_owner = wrapper_member_text.rsplit('.', 1)[0]
                        if not any(ch.isupper() for ch in wrapper_owner):
                            continue
                        chain_value = None
                        if mapping_name == 'cross' and isinstance(cross_file_wrapper_chains, dict):
                            chain_value = cross_file_wrapper_chains.get(key_text)
                        if chain_value is None and isinstance(local_wrapper_chains, dict):
                            chain_value = local_wrapper_chains.get(key_text)
                        bits_value = None
                        if mapping_name == 'cross' and isinstance(cross_file_wrapper_key_bits, dict):
                            bits_value = cross_file_wrapper_key_bits.get(key_text)
                        if bits_value is None and isinstance(local_wrapper_key_bits, dict):
                            bits_value = local_wrapper_key_bits.get(key_text)
                        candidate_rows.append((key_text, str(value), list(chain_value) if chain_value else None, bits_value if isinstance(bits_value, int) else None))
                        candidate_profiles.add(str(value))
                if len(candidate_profiles) == 1 and candidate_rows:
                    chosen_key, chosen_profile, chosen_chain, chosen_bits = sorted(
                        candidate_rows,
                        key=lambda item: (
                            len(item[2] or []),
                            len(str(item[0] or '')),
                        ),
                    )[0]
                    profile_id = chosen_profile
                    if not chain and chosen_chain:
                        chain = list(chosen_chain)
                    if key_bits is None and isinstance(chosen_bits, int):
                        key_bits = chosen_bits

        return profile_id, chain, key_bits

    def _lookup_wrapper_context_candidates(symbols: List[str]) -> Tuple[Optional[str], Optional[List[str]], Optional[int], str]:
        for symbol in symbols:
            profile_id, chain, key_bits = _lookup_wrapper_context(symbol)
            if is_concrete_profile_id(profile_id):
                return profile_id, chain, key_bits, str(symbol or '')
        return None, None, None, ''

    def _lookup_wrapper_key_bits(symbol: str) -> Optional[int]:
        _, _, key_bits = _lookup_wrapper_context(symbol)
        return key_bits if isinstance(key_bits, int) else None

    def _lookup_wrapper_variants(symbol: str) -> List[Tuple[str, List[str], Optional[int]]]:
        symbol_text = str(symbol or '').strip()
        if not symbol_text:
            return []
        tail = normalize_func_name(symbol_text)
        keys = [symbol_text, symbol_text.lower(), tail, tail.lower()]
        variant_rows: List[Tuple[str, List[str], Optional[int]]] = []
        seen_rows = set()
        for profile_map, chain_map, bits_map in (
            (local_wrapper_profiles, local_wrapper_chains, local_wrapper_key_bits),
            (cross_file_wrapper_profiles, cross_file_wrapper_chains, cross_file_wrapper_key_bits),
        ):
            if not isinstance(profile_map, dict):
                continue
            for key, profile_id in profile_map.items():
                key_text = str(key or '').strip()
                if '@@' not in key_text:
                    continue
                base_key = key_text.split('@@', 1)[0]
                if base_key not in keys:
                    continue
                if not is_concrete_profile_id(profile_id):
                    continue
                chain = list((chain_map or {}).get(key_text, []) or [])
                bits = (bits_map or {}).get(key_text)
                row_key = (
                    str(profile_id),
                    tuple(chain),
                    int(bits) if isinstance(bits, int) else None,
                )
                if row_key in seen_rows:
                    continue
                seen_rows.add(row_key)
                variant_rows.append((str(profile_id), chain, bits if isinstance(bits, int) else None))
        return variant_rows

    def _inherit_key_bits_from_chain(
        chain: Optional[List[str]],
        fallback: Optional[int] = None,
        extra_symbols: Optional[List[str]] = None,
    ) -> Optional[int]:
        if isinstance(fallback, int):
            return fallback
        symbols: List[str] = []
        symbols.extend(extra_symbols or [])
        symbols.extend(list(chain or []))
        for symbol in reversed(symbols):
            bits = _lookup_wrapper_key_bits(str(symbol or ''))
            if isinstance(bits, int):
                return bits
            bits = extract_candidate_key_bits(
                type(
                    '_SyntheticCandidate',
                    (),
                    {'literal_args': {}, 'profile_id': None, 'symbol': str(symbol or '')},
                )()
            )
            if isinstance(bits, int):
                return bits
        return None

    # Project-level wrapper index: emit findings at call sites that invoke a
    # known wrapper, even when the current file has no direct crypto API
    # candidate. This is what makes cross-file wrapper chains visible in JSON.
    if has_wrapper_index:
        existing_keys = {finding_key(finding) for finding in findings}
        features = kb.get('features', {}) if isinstance(kb, dict) else {}
        hash_like_families = {
            'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
            'SHA3', 'HMAC', 'HKDF', 'PBKDF', 'PBKDF2', 'ARGON2',
            'BCRYPT', 'SCRYPT',
        }
        def _current_callsite_label(symbol_text: str) -> str:
            raw_symbol = str(symbol_text or '').strip()
            if not raw_symbol:
                return raw_symbol
            if lang == 'python':
                path = Path(file_path)
                module_parts = [part for part in path.with_suffix('').parts if part and part != '__init__']
                if len(module_parts) > 3:
                    module_parts = module_parts[-3:]
                module_label = '.'.join(module_parts).replace('\\', '.').replace('/', '.')
                if module_label:
                    return f"{raw_symbol} [{module_label}]"
            if lang == 'java':
                path = Path(file_path)
                module_parts = [part for part in path.with_suffix('').parts if part]
                if len(module_parts) > 4:
                    module_parts = module_parts[-4:]
                module_label = '.'.join(module_parts).replace('\\', '.').replace('/', '.')
                if module_label:
                    return f"{raw_symbol} [{module_label}]"
            return raw_symbol
        for call in features.get('calls', []) if isinstance(features, dict) else []:
            if not isinstance(call, dict):
                continue
            call_line = int(call.get('line', 0) or 0)
            call_symbol = str(call.get('symbol', '') or '')
            resolved_call_symbol = str(call.get('resolved_symbol', call_symbol) or call_symbol)
            if call_line <= 0 or not call_symbol:
                continue
            if lang == 'c' and (
                is_c_non_crypto_callsite_symbol(call_symbol)
                or is_c_non_crypto_callsite_symbol(resolved_call_symbol)
            ):
                continue
            lookup_candidates = [resolved_call_symbol or call_symbol, call_symbol]
            if lang == 'java':
                java_receiver_symbol = _normalize_java_receiver_symbol_local(
                    call.get('receiver_type', ''),
                    call.get('resolved_member', '') or call_symbol.split('.')[-1],
                )
                if java_receiver_symbol and java_receiver_symbol not in lookup_candidates:
                    lookup_candidates.append(java_receiver_symbol)
            lookup_candidates = [candidate for candidate in lookup_candidates if str(candidate or '').strip()]
            profile_id, chain, key_bits, lookup_symbol = _lookup_wrapper_context_candidates(lookup_candidates)
            if not is_concrete_profile_id(profile_id) and not normalize_native_crypto_symbol(lookup_symbol, lang) and lang != 'java':
                continue
            if not is_concrete_profile_id(profile_id):
                continue
            if (call_line, call_symbol, profile_id) in existing_keys:
                continue

            family = alg_family(profile_id)
            severity = 'info' if family in hash_like_families else 'high'
            call_owner = normalize_func_name(
                call.get('owner_function_normalized') or call.get('owner_function') or line_to_func.get(call_line, '')
            )
            key_bits = _inherit_key_bits_from_chain(chain, key_bits, [call_owner] if call_owner else None)
            wrapper_chain = list(chain or [])
            if lang in {'python', 'java'} and resolved_call_symbol and resolved_call_symbol != call_symbol:
                callsite_step = _current_callsite_label(call_symbol)
                if not wrapper_chain or wrapper_chain[-1] != callsite_step:
                    wrapper_chain.append(callsite_step)
            elif chain and normalize_func_name(call_symbol) != normalize_func_name(chain[-1]):
                wrapper_chain = list(chain) + [call_symbol]
            elif not wrapper_chain:
                wrapper_chain = [call_symbol]
            append_augmented_finding(
                findings,
                existing_keys,
                file_path=file_path,
                line=call_line,
                symbol=call_symbol,
                profile_id=str(profile_id),
                key_bits=key_bits,
                source='pipeline_v2_project_wrapper_callsite',
                rule_id='PIPELINE.V2.PROJECT_WRAPPER_CALLSITE',
                severity=severity,
                reason=f'Project-level wrapper call-site resolved from wrapper index: {call_symbol}',
                recommendation='Verify wrapper chain algorithm and key length meet quantum-safe policy.',
                algorithm=family,
                confidence=0.62,
                wrapper_chain=wrapper_chain,
            )
            if lang == 'c':
                for variant_profile, variant_chain, variant_bits in _lookup_wrapper_variants(lookup_symbol):
                    if variant_profile == profile_id and list(variant_chain or []) == list(chain or []):
                        continue
                    if (call_line, call_symbol, variant_profile) in existing_keys:
                        continue
                    variant_family = alg_family(variant_profile)
                    variant_key_bits = _inherit_key_bits_from_chain(
                        variant_chain,
                        variant_bits,
                        [call_owner] if call_owner else None,
                    )
                    append_augmented_finding(
                        findings,
                        existing_keys,
                        file_path=file_path,
                        line=call_line,
                        symbol=call_symbol,
                        profile_id=str(variant_profile),
                        key_bits=variant_key_bits,
                        source='pipeline_v2_project_wrapper_callsite_variant',
                        rule_id='PIPELINE.V2.PROJECT_WRAPPER_CALLSITE_VARIANT',
                        severity='info' if variant_family in hash_like_families else 'high',
                        reason=f'Project-level wrapper call-site resolved from wrapper variant index: {call_symbol}',
                        recommendation='Verify wrapper chain algorithm and key length meet quantum-safe policy.',
                        algorithm=variant_family,
                        confidence=0.58,
                        wrapper_chain=list(variant_chain or [call_symbol]),
                    )

    if isinstance(local_wrapper_profiles, dict) or isinstance(cross_file_wrapper_profiles, dict):
        existing_keys = {finding_key(finding) for finding in findings}
        family_anchor_pid = {}
        family_anchor_bits = {}
        family_anchor_chain = {}
        func_family_anchor_chain = {}
        function_start_lines: Dict[str, int] = {}

        features = kb.get('features', {}) if isinstance(kb, dict) else {}
        for fn in features.get('functions', []) if isinstance(features, dict) else []:
            if not isinstance(fn, dict):
                continue
            fn_raw_name = str(fn.get('qualified_name') or fn.get('name', '') or '')
            fn_name = normalize_func_name(fn_raw_name)
            start_line = fn.get('start_line', fn.get('line', 0))
            try:
                start_line = int(start_line or 0)
            except (TypeError, ValueError):
                start_line = 0
            if fn_name and start_line > 0:
                function_start_lines[fn_name] = start_line
            if fn_raw_name and start_line > 0:
                function_start_lines[fn_raw_name] = start_line

        call_edges: Dict[str, Set[str]] = {}
        for call in features.get('calls', []) if isinstance(features, dict) else []:
            if not isinstance(call, dict):
                continue
            call_line = int(call.get('line', 0) or 0)
            caller = normalize_func_name(call.get('owner_function_normalized') or call.get('owner_function') or line_to_func.get(call_line, ''))
            if not caller:
                caller = normalize_func_name(line_to_func.get(call_line, ''))
            callee_symbol = str(call.get('symbol', '') or '')
            if not callee_symbol:
                continue
            callee = normalize_func_name(callee_symbol.split('.')[-1])
            if not caller or not callee or caller == callee:
                continue
            call_edges.setdefault(caller, set()).add(callee)

        for finding in findings:
            finding_pid = getattr(finding, 'profile_id', None)
            if not is_concrete_profile_id(finding_pid):
                continue
            finding_family = alg_family(finding_pid)
            if finding_family and finding_family not in family_anchor_pid:
                family_anchor_pid[finding_family] = finding_pid
            finding_bits = getattr(finding, 'key_bits', None)
            if finding_family and isinstance(finding_bits, int):
                current_bits = family_anchor_bits.get(finding_family)
                if current_bits is None or finding_bits > current_bits:
                    family_anchor_bits[finding_family] = finding_bits
            if finding_family:
                file_key = str(getattr(finding, 'file', '') or '').lower()
                chain = list(getattr(finding, 'wrapper_chain', []) or [])
                current_chain = family_anchor_chain.get((file_key, finding_family), [])
                if len(chain) > len(current_chain):
                    family_anchor_chain[(file_key, finding_family)] = chain

                finding_line = int(getattr(finding, 'line', 0) or 0)
                func_name = normalize_func_name(line_to_func.get(finding_line, ''))
                if func_name:
                    func_key = (func_name, finding_family)
                    symbol_text = str(getattr(finding, 'symbol', '') or '').strip()
                    func_chain = list(chain)
                    if _looks_like_direct_api(symbol_text):
                        # 直接 sink/API：将“sink → enclosing function”作为函数级 anchor，
                        # 后续的调用者可以继续在此基础上追加自己的函数名。
                        func_chain = [symbol_text, func_name]
                    elif len(func_chain) <= 1:
                        # 直接 API 之外的 finding，优先把它挂到当前函数的 sink anchor 上。
                        # 这样 method2 / bc.go / String.valueOf 之类的报告会带上原始 sink。
                        func_chain = [symbol_text, func_name] if symbol_text else [func_name]
                    current_func_chain = func_family_anchor_chain.get(func_key, [])
                    if len(func_chain) > len(current_func_chain):
                        func_family_anchor_chain[func_key] = func_chain

        # 为链中的中间 wrapper 生成独立 finding：
        # 例如 sink -> method1 -> method2 -> main
        # 会额外生成 method1、method2 的独立报告，但不重复生成 main。
        for finding in list(findings):
            finding_pid = getattr(finding, 'profile_id', None)
            if not is_concrete_profile_id(finding_pid):
                continue
            chain = list(getattr(finding, 'wrapper_chain', []) or [])
            if len(chain) < 3:
                continue

            original_source = str(getattr(getattr(finding, 'evidence', {}) or {}, 'get', lambda *_: '')('source', '') or '')
            if not original_source:
                evidence = getattr(finding, 'evidence', {}) or {}
                if isinstance(evidence, dict):
                    original_source = str(evidence.get('source', '') or '')

            for idx, wrapper_name in enumerate(chain[1:-1], start=1):
                wrapper_symbol = str(wrapper_name or '')
                wrapper_norm = normalize_func_name(wrapper_name)
                if lang == 'c' and (
                    is_c_non_crypto_callsite_symbol(wrapper_symbol)
                    or _is_c_non_crypto_wrapper_name(wrapper_symbol)
                ):
                    continue
                wrapper_line = function_start_lines.get(wrapper_symbol) or function_start_lines.get(wrapper_norm)
                if not wrapper_line:
                    continue
                # If this wrapper is already represented by another finding in the
                # chain (typically as the call-site form), do not emit a second
                # anchor at the function definition line.
                already_covered = False
                for existing in findings:
                    if int(getattr(existing, 'line', 0) or 0) == wrapper_line:
                        continue
                    existing_chain = [normalize_func_name(x) for x in (getattr(existing, 'wrapper_chain', []) or [])]
                    if wrapper_norm and wrapper_norm in existing_chain:
                        already_covered = True
                        break
                if already_covered:
                    continue
                wrapper_chain = chain[: idx + 1]
                wrapper_bits = _inherit_key_bits_from_chain(wrapper_chain, None)
                append_augmented_finding(
                    findings,
                    existing_keys,
                    file_path=file_path,
                    line=wrapper_line,
                    symbol=wrapper_symbol or wrapper_norm,
                    profile_id=str(finding_pid),
                    key_bits=wrapper_bits,
                    source='pipeline_v2_wrapper_anchor',
                    rule_id='PIPELINE.V2.WRAPPER_ANCHOR',
                    severity=str(getattr(finding, 'severity', 'medium') or 'medium'),
                    reason=f'Wrapper anchor recovered from chain: {wrapper_norm}',
                    recommendation=str(getattr(finding, 'recommendation', '') or 'Verify wrapper chain algorithm and key length meet quantum-safe policy.'),
                    algorithm=str(getattr(finding, 'algorithm', '') or alg_family(str(finding_pid))),
                    confidence=0.55,
                    wrapper_chain=wrapper_chain,
                )

        # 为只有一层封装的链补生成 wrapper definition finding：
        # 例如 sink -> wrapper。此前中间 wrapper 恢复逻辑要求 len(chain) >= 3，
        # 会漏掉最常见的单层封装场景。
        for finding in list(findings):
            finding_pid = getattr(finding, 'profile_id', None)
            if not is_concrete_profile_id(finding_pid):
                continue
            chain = list(getattr(finding, 'wrapper_chain', []) or [])
            if len(chain) != 2:
                continue

            wrapper_norm = normalize_func_name(chain[-1])
            wrapper_symbol = str(chain[-1] or '')
            if not wrapper_norm:
                continue
            if lang == 'c' and (
                is_c_non_crypto_callsite_symbol(wrapper_symbol)
                or _is_c_non_crypto_wrapper_name(wrapper_symbol)
            ):
                continue
            wrapper_line = function_start_lines.get(wrapper_symbol) or function_start_lines.get(wrapper_norm)
            if not wrapper_line:
                continue

            already_covered = False
            for existing in findings:
                if int(getattr(existing, 'line', 0) or 0) != wrapper_line:
                    continue
                existing_symbol = normalize_func_name(str(getattr(existing, 'symbol', '') or ''))
                existing_chain = [
                    normalize_func_name(x)
                    for x in (getattr(existing, 'wrapper_chain', []) or [])
                ]
                if existing_symbol == wrapper_norm or wrapper_norm in existing_chain:
                    already_covered = True
                    break
            if already_covered:
                continue

            wrapper_bits = _inherit_key_bits_from_chain(chain, None)
            append_augmented_finding(
                findings,
                existing_keys,
                file_path=file_path,
                line=wrapper_line,
                symbol=wrapper_symbol or wrapper_norm,
                profile_id=str(finding_pid),
                key_bits=wrapper_bits,
                source='pipeline_v2_wrapper_anchor',
                rule_id='PIPELINE.V2.WRAPPER_ANCHOR',
                severity=str(getattr(finding, 'severity', 'medium') or 'medium'),
                reason=f'Wrapper anchor recovered from chain: {wrapper_norm}',
                recommendation=str(getattr(finding, 'recommendation', '') or 'Verify wrapper chain algorithm and key length meet quantum-safe policy.'),
                algorithm=str(getattr(finding, 'algorithm', '') or alg_family(str(finding_pid))),
                confidence=0.55,
                wrapper_chain=chain,
            )

        # 复用 AST call 列表，在后续“chain 修复”之后生成 wrapper 调用点 finding。
        call_sites: List[Dict[str, Any]] = list(features.get('calls', []) if isinstance(features, dict) else [])

        # 传播函数级别的 sink anchor：callee → caller
        # Bound propagation on real-world cyclic call graphs. These chains are
        # evidence only; they should not try to enumerate every possible path.
        max_func_chain_depth = 4 if lang == 'c' else 8
        max_propagation_rounds = max(1, min(len(call_edges) + 1, 32))
        changed = True
        propagation_rounds = 0
        while changed and call_edges and propagation_rounds < max_propagation_rounds:
            propagation_rounds += 1
            changed = False
            for caller, callees in call_edges.items():
                for callee in callees:
                    for (func_name, family), chain in list(func_family_anchor_chain.items()):
                        if func_name != callee or len(chain) <= 1:
                            continue
                        caller_key = (caller, family)
                        caller_chain = func_family_anchor_chain.get(caller_key, [])
                        propagated = list(chain)
                        if caller in propagated:
                            continue
                        if len(propagated) >= max_func_chain_depth:
                            continue
                        if propagated and propagated[-1] != caller:
                            propagated = propagated + [caller]
                        if len(propagated) > len(caller_chain):
                            func_family_anchor_chain[caller_key] = propagated
                            changed = True

        # 先修补已有 findings 的 wrapper_chain：
        # 1) 同文件/同 family 中存在更完整的传播链时，补上当前 wrapper/call-site；
        # 2) 对于 bc.go / method2 / String.valueOf 这类非直接 API 的点，避免只保留单点。
        for finding in findings:
            finding_pid = getattr(finding, 'profile_id', None)
            if not is_concrete_profile_id(finding_pid):
                continue
            finding_family = alg_family(finding_pid)
            if not finding_family:
                continue
            file_key = str(getattr(finding, 'file', '') or '').lower()
            finding_line = int(getattr(finding, 'line', 0) or 0)
            func_name = normalize_func_name(line_to_func.get(finding_line, ''))
            anchor_chain = func_family_anchor_chain.get((func_name, finding_family))
            if not anchor_chain:
                anchor_chain = family_anchor_chain.get((file_key, finding_family))
            _repair_wrapper_chain(finding, anchor_chain=anchor_chain)
            if (
                getattr(finding, 'key_bits', None) is not None
                and not getattr(finding, 'key_bits_reason', None)
                and len(getattr(finding, 'wrapper_chain', []) or []) > 1
            ):
                chain = list(getattr(finding, 'wrapper_chain', []) or [])
                chain_text = ' -> '.join(str(item) for item in chain if item)
                chain_reason = (
                    f"key_bits 由封装链传播得到：{chain_text}。"
                    "该值来自链内较低层 crypto API 的密钥表达式、固定长度转换或固定算法语义；"
                    "未使用无关 API 的 key_bits。"
                )
                setattr(finding, 'key_bits_reason', chain_reason)
                evidence = getattr(finding, 'evidence', None)
                if isinstance(evidence, dict):
                    evidence['key_bits_reason'] = chain_reason
            if getattr(finding, 'key_bits', None) is None and func_name:
                inherited_bits = _lookup_wrapper_key_bits(func_name)
                if isinstance(inherited_bits, int):
                    setattr(finding, 'key_bits', inherited_bits)
                    chain = list(getattr(finding, 'wrapper_chain', []) or [])
                    chain_text = ' -> '.join(str(item) for item in chain if item)
                    inherited_reason = (
                        f"key_bits 由封装链传播得到：{chain_text or func_name}。"
                        "该值来自链内较低层 crypto API 的密钥表达式、固定长度转换或固定算法语义；"
                        "未使用无关 API 的 key_bits。"
                    )
                    setattr(finding, 'key_bits_reason', inherited_reason)
                    evidence = getattr(finding, 'evidence', None)
                    if isinstance(evidence, dict):
                        evidence['key_bits'] = inherited_bits
                        evidence['key_bits_reason'] = inherited_reason

        # 经过 chain 修复后，再补充中间 wrapper 的调用点 finding：
        # 这样可以确保 line 级 wrapper 调用点不会因为原始链过短而被跳过。
        for finding in list(findings):
            finding_pid = getattr(finding, 'profile_id', None)
            if not is_concrete_profile_id(finding_pid):
                continue
            chain = list(getattr(finding, 'wrapper_chain', []) or [])
            if len(chain) < 3:
                continue

            for idx, wrapper_name in enumerate(chain[1:-1], start=1):
                wrapper_symbol = str(wrapper_name or '')
                wrapper_norm = normalize_func_name(wrapper_name)
                caller_norm = normalize_func_name(chain[idx + 1])
                if not wrapper_norm or not caller_norm:
                    continue
                if lang == 'c' and (
                    is_c_non_crypto_callsite_symbol(wrapper_symbol)
                    or _is_c_non_crypto_wrapper_name(wrapper_symbol)
                ):
                    continue

                for call in call_sites:
                    if not isinstance(call, dict):
                        continue
                    call_line = int(call.get('line', 0) or 0)
                    if call_line <= 0:
                        continue
                    call_owner = normalize_func_name(
                        call.get('owner_function_normalized') or call.get('owner_function') or line_to_func.get(call_line, '')
                    )
                    call_symbol = normalize_func_name(str(call.get('symbol', '') or '').split('.')[-1])
                    if not call_owner or not call_symbol:
                        continue
                    if call_owner != caller_norm or call_symbol != wrapper_norm:
                        continue

                    call_chain = chain[: idx + 2]
                    call_bits = _inherit_key_bits_from_chain(
                        call_chain,
                        None,
                        [caller_norm, wrapper_norm],
                    )
                    append_augmented_finding(
                        findings,
                        existing_keys,
                        file_path=file_path,
                        line=call_line,
                        symbol=wrapper_symbol or wrapper_norm,
                        profile_id=str(finding_pid),
                        key_bits=call_bits,
                        source='pipeline_v2_wrapper_callsite',
                        rule_id='PIPELINE.V2.WRAPPER_CALLSITE',
                        severity=str(getattr(finding, 'severity', 'medium') or 'medium'),
                        reason=f'Wrapper call-site recovered from chain: {wrapper_norm} in {caller_norm}',
                        recommendation=str(getattr(finding, 'recommendation', '') or 'Verify wrapper chain algorithm and key length meet quantum-safe policy.'),
                        algorithm=str(getattr(finding, 'algorithm', '') or alg_family(str(finding_pid))),
                        confidence=0.58,
                        wrapper_chain=call_chain,
                    )

        # Fallback: synthesize independent wrapper findings from already-resolved chains.
        # This keeps middle wrappers like method1/method2 visible even when the local
        # wrapper index is incomplete or unavailable.
        for finding in list(findings):
            finding_pid = getattr(finding, 'profile_id', None)
            if not is_concrete_profile_id(finding_pid):
                continue
            chain = list(getattr(finding, 'wrapper_chain', []) or [])
            if len(chain) < 3:
                continue

            for idx, wrapper_name in enumerate(chain[1:-1], start=1):
                wrapper_symbol = str(wrapper_name or '')
                wrapper_norm = normalize_func_name(wrapper_name)
                wrapper_line = function_start_lines.get(wrapper_symbol) or function_start_lines.get(wrapper_norm)
                if not wrapper_line:
                    continue
                already_covered = False
                for existing in findings:
                    if int(getattr(existing, 'line', 0) or 0) == wrapper_line:
                        continue
                    existing_chain = [normalize_func_name(x) for x in (getattr(existing, 'wrapper_chain', []) or [])]
                    if wrapper_norm and wrapper_norm in existing_chain:
                        already_covered = True
                        break
                if already_covered:
                    continue
                wrapper_chain = chain[: idx + 1]
                wrapper_bits = _inherit_key_bits_from_chain(wrapper_chain, None)
                append_augmented_finding(
                    findings,
                    existing_keys,
                    file_path=file_path,
                    line=wrapper_line,
                    symbol=wrapper_symbol or wrapper_norm,
                    profile_id=str(finding_pid),
                    key_bits=wrapper_bits,
                    source='pipeline_v2_wrapper_anchor',
                    rule_id='PIPELINE.V2.WRAPPER_ANCHOR',
                    severity=str(getattr(finding, 'severity', 'medium') or 'medium'),
                    reason=f'Wrapper anchor recovered from chain: {wrapper_norm}',
                    recommendation=str(getattr(finding, 'recommendation', '') or 'Verify wrapper chain algorithm and key length meet quantum-safe policy.'),
                    algorithm=str(getattr(finding, 'algorithm', '') or alg_family(str(finding_pid))),
                    confidence=0.55,
                    wrapper_chain=wrapper_chain,
                )

    if lang == 'java':
        existing_keys = {finding_key(finding) for finding in findings}
        existing_by_key = {finding_key(finding): finding for finding in findings}
        java_receiver_init_bits: List[Dict[str, Any]] = []

        for candidate in candidates:
            symbol = str(getattr(candidate, 'symbol', '') or '')
            profile_id = getattr(candidate, 'profile_id', None)
            location = getattr(candidate, 'location', None)
            line = getattr(location, 'line', 0) if location is not None else 0
            if not symbol or not line or '.' not in symbol or not is_concrete_profile_id(profile_id):
                continue
            receiver = symbol.split('.', 1)[0].lower()
            method = symbol.split('.')[-1].lower()
            if method not in init_methods:
                continue
            key = (line, symbol, profile_id)
            finding = existing_by_key.get(key)
            if finding is None:
                continue
            key_bits = getattr(finding, 'key_bits', None)
            if not isinstance(key_bits, int):
                continue
            java_receiver_init_bits.append({
                'receiver': receiver,
                'function': candidate_func_name_resolver(candidate) if callable(candidate_func_name_resolver) else '',
                'family': alg_family(profile_id),
                'line': line,
                'key_bits': key_bits,
            })

        for candidate in candidates:
            symbol = getattr(candidate, 'symbol', '')
            profile_id = getattr(candidate, 'profile_id', None)
            location = getattr(candidate, 'location', None)
            line = getattr(location, 'line', 0) if location is not None else 0
            if not symbol or not line or not is_concrete_profile_id(profile_id):
                continue
            if '.' not in symbol:
                continue

            method = symbol.split('.')[-1].lower()
            if method not in gen_methods and method not in init_methods:
                continue
            key = (line, symbol, profile_id)
            candidate_key_bits = extract_candidate_key_bits(candidate)
            cand_func = candidate_func_name_resolver(candidate) if callable(candidate_func_name_resolver) else ''
            cand_family = alg_family(profile_id)
            receiver = symbol.split('.', 1)[0].lower()
            if not isinstance(candidate_key_bits, int) and receiver:
                matching_init_bits = [
                    record for record in java_receiver_init_bits
                    if record.get('receiver') == receiver
                    and (not cand_func or not record.get('function') or record.get('function') == cand_func)
                    and (not cand_family or record.get('family') == cand_family)
                    and int(record.get('line', 0) or 0) <= line
                ]
                if matching_init_bits:
                    nearest = max(matching_init_bits, key=lambda record: int(record.get('line', 0) or 0))
                    inherited_bits = nearest.get('key_bits')
                    if isinstance(inherited_bits, int):
                        candidate_key_bits = inherited_bits
            if key in existing_keys:
                existing = existing_by_key.get(key)
                if (
                    existing is not None
                    and getattr(existing, 'key_bits', None) is None
                    and isinstance(candidate_key_bits, int)
                ):
                    setattr(existing, 'key_bits', candidate_key_bits)
                    existing_reason = str(getattr(existing, 'key_bits_reason', '') or '').strip()
                    if not existing_reason or '无法通过静态分析得到 key_bits' in existing_reason:
                        setattr(existing, 'key_bits_reason', 'key_bits 由同一对象的 init/initialize 上下文传播得到。')
                    evidence = getattr(existing, 'evidence', None)
                    if not isinstance(evidence, dict):
                        evidence = {}
                        setattr(existing, 'evidence', evidence)
                    evidence['key_bits'] = candidate_key_bits
                    evidence['source'] = 'pipeline_v2_operation_propagation'
                continue

            has_anchor = False
            for finding in findings:
                finding_pid = getattr(finding, 'profile_id', None)
                if not is_concrete_profile_id(finding_pid):
                    continue
                if cand_family and alg_family(finding_pid) != cand_family:
                    continue
                finding_line = getattr(finding, 'line', 0) or 0
                finding_func = normalize_func_name(line_to_func.get(finding_line, ''))
                if not cand_func or not finding_func or cand_func == finding_func:
                    has_anchor = True
                    break
            if not has_anchor:
                continue

            _append_from_candidate(
                candidate,
                existing_keys=existing_keys,
                profile_id=profile_id,
                key_bits=candidate_key_bits,
                source='pipeline_v2_operation_propagation',
                rule_id='PIPELINE.V2.OP_PROP',
                severity='medium',
                reason='Operation-level finding propagated from concrete object context',
                recommendation='Verify algorithm and key length meet quantum-safe policy.',
                confidence=0.6,
            )

    if lang == 'c':
        existing_keys = {finding_key(finding) for finding in findings}
        for candidate in candidates:
            symbol = getattr(candidate, 'symbol', '')
            profile_id = getattr(candidate, 'profile_id', None)
            location = getattr(candidate, 'location', None)
            line = getattr(location, 'line', 0) if location is not None else 0
            if not symbol or not line or '.' in symbol:
                continue
            if not is_concrete_profile_id(profile_id):
                continue

            _append_from_candidate(
                candidate,
                existing_keys=existing_keys,
                profile_id=profile_id,
                key_bits=extract_candidate_key_bits(candidate),
                source='pipeline_v2_c_factory_propagation',
                rule_id='PIPELINE.V2.C_FACTORY_PROP',
                severity='medium',
                reason='C factory/API finding propagated from concrete candidate profile',
                recommendation='Verify algorithm and key length meet quantum-safe policy.',
                confidence=0.65,
            )

    if lang == 'python':
        existing_keys = {finding_key(finding) for finding in findings}
        for candidate in candidates:
            symbol = getattr(candidate, 'symbol', '')
            profile_id = getattr(candidate, 'profile_id', None)
            location = getattr(candidate, 'location', None)
            line = getattr(location, 'line', 0) if location is not None else 0
            symbol_lc = str(symbol or '').lower()
            if not symbol or not line or not is_concrete_profile_id(profile_id):
                continue
            if not symbol_lc.startswith('ec.'):
                continue
            if not (symbol_lc in ('ec.generate_private_key', 'ec.ecdh') or symbol_lc.startswith('ec.secp')):
                continue
            if (line, symbol, profile_id) in existing_keys:
                continue

            key_bits = extract_candidate_key_bits(candidate)
            literal_args = getattr(candidate, 'literal_args', {}) or {}
            if key_bits is None:
                key_bits = extract_secp_bits(symbol)
            if key_bits is None:
                for value in literal_args.values():
                    key_bits = extract_secp_bits(value)
                    if key_bits is not None:
                        break

            _append_from_candidate(
                candidate,
                existing_keys=existing_keys,
                profile_id=profile_id,
                key_bits=key_bits,
                source='pipeline_v2_python_ec_propagation',
                rule_id='PIPELINE.V2.PY_EC_PROP',
                severity='high',
                reason='Python EC API finding propagated from concrete candidate profile',
                recommendation='Verify EC/ECDH usage against post-quantum migration policy.',
                confidence=0.65,
            )

    line_symbols: Dict[int, List[str]] = {}
    for finding in findings:
        line = getattr(finding, 'line', 0) or 0
        symbol = str(getattr(finding, 'symbol', '') or '')
        line_symbols.setdefault(line, []).append(symbol)

    filtered_findings: List[Finding] = []
    for finding in findings:
        symbol = str(getattr(finding, 'symbol', '') or '')
        symbol_lc = symbol.lower()
        line = getattr(finding, 'line', 0) or 0

        if symbol_lc.endswith('.exchange'):
            same_line_symbols = line_symbols.get(line, [])
            has_explicit_ecdh_api = any(
                sym != symbol and 'ecdh' in str(sym).lower() and str(sym).lower().startswith('ec.')
                for sym in same_line_symbols
            )
            if has_explicit_ecdh_api:
                continue

        filtered_findings.append(finding)

    findings = filtered_findings

    for finding in findings:
        profile_id = getattr(finding, 'profile_id', None)
        if profile_id != 'ALG.DES':
            continue
        symbol_u = str(getattr(finding, 'symbol', '') or '').upper()
        evidence = getattr(finding, 'evidence', {}) or {}
        alg_u = str(evidence.get('algorithm', '')).upper() if isinstance(evidence, dict) else ''
        if 'DES3' in symbol_u or '3DES' in symbol_u or alg_u in {'DES3', '3DES', 'TRIPLEDES'}:
            setattr(finding, 'profile_id', 'ALG.3DES')
            if isinstance(evidence, dict):
                evidence['algorithm'] = '3DES'

    return findings


# ============================================================================
# 1. 调用点数据结构（CallSite）
# ============================================================================

@dataclass
class CallSite:
    """
    调用点：记录某个函数调用另一个函数的信息
    
    用于构建 callers_index（反向调用索引）
    """
    caller_fqname: str          # 调用者函数全限定名（含 module/class）
    callee_fqname: str          # 被调函数全限定名
    args_repr: List[str]        # 参数表达式（文本形式）
    line: int                   # 调用行号
    file: str                   # 文件路径
    receiver: Optional[str] = None    # receiver（OO 语言）
    module: Optional[str] = None      # 模块名（Python/Go）


# ============================================================================
# 2. 表达式（Expr）：可替换的关键输入表达式
# ============================================================================

class ExprType(Enum):
    """表达式类型"""
    PARAM = "param"         # 来自参数
    CONST = "const"         # 常量
    MUL = "mul"            # 乘法（bits = bytes * 8）
    ADD = "add"            # 加法
    UNION = "union"        # 候选集合
    STATE = "state"        # 来自状态（ctx.field）
    UNKNOWN = "unknown"    # 未知


@dataclass
class Expr:
    """
    可替换的表达式：支持常量、参数、线性变换、候选集合
    
    用于表示关键输入的来源，支持代数变换和替换
    """
    type: ExprType
    value: Any = None           # 常量值
    param: Optional[str] = None # 参数名
    left: Optional['Expr'] = None   # 左子表达式
    right: Optional['Expr'] = None  # 右子表达式
    candidates: Optional[List['Expr']] = None  # 候选集合
    obj: Optional[str] = None   # 对象名（STATE）
    field: Optional[str] = None # 字段名（STATE）
    
    def is_constant(self) -> bool:
        """判断是否为常量（不依赖参数或状态）"""
        if self.type == ExprType.CONST:
            return True
        if self.type in (ExprType.MUL, ExprType.ADD):
            return self.left.is_constant() and self.right.is_constant()
        return False
    
    def depends_on_param(self) -> bool:
        """判断是否依赖参数"""
        if self.type == ExprType.PARAM:
            return True
        if self.type in (ExprType.MUL, ExprType.ADD):
            return self.left.depends_on_param() or self.right.depends_on_param()
        if self.type == ExprType.UNION:
            return any(c.depends_on_param() for c in self.candidates)
        return False
    
    def depends_on_state(self) -> bool:
        """判断是否依赖状态"""
        if self.type == ExprType.STATE:
            return True
        if self.type in (ExprType.MUL, ExprType.ADD):
            return self.left.depends_on_state() or self.right.depends_on_state()
        return False
    
    def evaluate(self) -> Optional[Any]:
        """求值（仅适用于常量表达式）"""
        if self.type == ExprType.CONST:
            return self.value
        if self.type == ExprType.MUL and self.is_constant():
            return self.left.evaluate() * self.right.evaluate()
        if self.type == ExprType.ADD and self.is_constant():
            return self.left.evaluate() + self.right.evaluate()
        return None
    
    def substitute(self, param_values: Dict[str, 'Expr']) -> 'Expr':
        """
        替换：将参数替换为实参表达式
        
        Args:
            param_values: {param_name: actual_expr}
        
        Returns:
            替换后的表达式
        """
        if self.type == ExprType.PARAM:
            return param_values.get(self.param, self)
        if self.type == ExprType.CONST:
            return self
        if self.type == ExprType.MUL:
            return Expr(
                type=ExprType.MUL,
                left=self.left.substitute(param_values),
                right=self.right.substitute(param_values)
            )
        if self.type == ExprType.ADD:
            return Expr(
                type=ExprType.ADD,
                left=self.left.substitute(param_values),
                right=self.right.substitute(param_values)
            )
        if self.type == ExprType.UNION:
            return Expr(
                type=ExprType.UNION,
                candidates=[c.substitute(param_values) for c in self.candidates]
            )
        return self
    
    def __repr__(self):
        if self.type == ExprType.CONST:
            return f"Const({self.value})"
        if self.type == ExprType.PARAM:
            return f"Param({self.param})"
        if self.type == ExprType.MUL:
            return f"Mul({self.left}, {self.right})"
        if self.type == ExprType.ADD:
            return f"Add({self.left}, {self.right})"
        if self.type == ExprType.STATE:
            return f"State({self.obj}.{self.field})"
        if self.type == ExprType.UNION:
            return f"Union({self.candidates})"
        return "Unknown"


# ============================================================================
# 3. 关键输入归因（Key Input Attribution）
# ============================================================================

class InputSource(Enum):
    """关键输入来源"""
    PARAM_DEP = "param"     # 来自参数
    CONST_DEP = "const"     # 来自常量
    STATE_DEP = "state"     # 来自状态（ctx_read）
    UNKNOWN = "unknown"     # 未知


@dataclass
class StateAccess:
    """状态访问（读/写）"""
    obj: str                # 对象名（ctx）
    field: str              # 字段名（key_bits/algorithm）
    value: Optional[Expr] = None  # 写入值（仅 write）


@dataclass
class Effect:
    """
    Effect：函数内部对某个敏感点的触达效果
    
    描述关键输入来源、状态访问、触发条件
    """
    sink_profile_id: str                    # 敏感点 profile（ALG.RSA/AES...）
    key_inputs: Dict[str, Expr]             # 关键输入：{field: expr}
    input_sources: Dict[str, InputSource]   # 输入来源：{field: source}
    state_reads: List[StateAccess] = field(default_factory=list)
    state_writes: List[StateAccess] = field(default_factory=list)
    trigger: str = "unconditional"          # unconditional | conditional | unknown
    evidence: Dict[str, Any] = field(default_factory=dict)  # 证据（行号、来源）


# ============================================================================
# 4. 派生约束（Contract）
# ============================================================================

class Predicate(Enum):
    """约束谓词"""
    GEQ = ">="      # 大于等于
    LEQ = "<="      # 小于等于
    EQ = "=="       # 等于
    NEQ = "!="      # 不等于
    IN = "in"       # 属于集合


@dataclass
class ParamConstraint:
    """参数约束"""
    param: str              # 参数名
    predicate: Predicate    # 谓词
    value: Any             # 阈值
    confidence: str = "confirmed"  # confirmed | probable | suspect


@dataclass
class StateConstraint:
    """状态约束"""
    obj: str                # 对象名
    field: str              # 字段名
    predicate: Predicate    # 谓词
    value: Any             # 阈值
    confidence: str = "confirmed"


@dataclass
class Contract:
    """
    Contract：派生约束
    
    描述函数的安全充分条件（满足则可剪枝）
    """
    param_constraints: List[ParamConstraint] = field(default_factory=list)
    state_constraints: List[StateConstraint] = field(default_factory=list)
    
    def is_sat(self, param_values: Dict[str, Any], 
               state_values: Dict[str, Dict[str, Any]]) -> Optional[bool]:
        """
        判断约束是否满足（SAT）
        
        Args:
            param_values: {param: value}
            state_values: {obj: {field: value}}
        
        Returns:
            True: SAT（满足，可剪枝）
            False: UNSAT（不满足，继续）
            None: UNKNOWN（不确定）
        """
        # 检查参数约束
        for constraint in self.param_constraints:
            value = param_values.get(constraint.param)
            if value is None:
                return None  # UNKNOWN
            
            # 如果值是字符串（符号表达式），返回 UNKNOWN
            if isinstance(value, str):
                return None  # UNKNOWN - 无法求值
            
            if constraint.predicate == Predicate.GEQ:
                if value < constraint.value:
                    return False  # UNSAT
            elif constraint.predicate == Predicate.LEQ:
                if value > constraint.value:
                    return False  # UNSAT
            elif constraint.predicate == Predicate.EQ:
                if value != constraint.value:
                    return False  # UNSAT
        
        # 检查状态约束
        for constraint in self.state_constraints:
            obj_state = state_values.get(constraint.obj, {})
            value = obj_state.get(constraint.field)
            if value is None:
                return None  # UNKNOWN
            
            # 如果值是字符串（符号表达式），返回 UNKNOWN
            if isinstance(value, str):
                return None  # UNKNOWN
            
            if constraint.predicate == Predicate.GEQ:
                if value < constraint.value:
                    return False  # UNSAT
        
        return True  # SAT


# ============================================================================
# 5. Wrapper Summary
# ============================================================================

@dataclass
class Summary:
    """
    Wrapper Summary：函数的封装摘要
    
    描述函数内部触达哪些敏感点及其关键输入来源
    """
    function_name: str                      # 函数名
    effects: List[Effect] = field(default_factory=list)
    contract: Optional[Contract] = None     # 派生约束
    confidence: str = "confirmed"           # confirmed | probable | suspect
    
    def get_effects_by_profile(self, profile_id: str) -> List[Effect]:
        """获取特定 profile 的所有 effects"""
        return [e for e in self.effects if e.sink_profile_id == profile_id]


# ============================================================================
# 6. CallersIndex：反向调用索引
# ============================================================================

class CallersIndex:
    """
    反向调用索引：callers_index[callee] -> [CallSite]
    
    用于快速查找所有调用某个函数的位置
    """
    
    def __init__(self):
        self.index: Dict[str, List[CallSite]] = {}
    
    def add_call(self, callsite: CallSite):
        """添加调用关系"""
        callee = callsite.callee_fqname
        if callee not in self.index:
            self.index[callee] = []
        self.index[callee].append(callsite)
    
    def get_callers(self, callee: str) -> List[CallSite]:
        """获取所有调用 callee 的位置"""
        return self.index.get(callee, [])
    
    def has_callers(self, callee: str) -> bool:
        """判断是否有调用者"""
        return callee in self.index and len(self.index[callee]) > 0


# ============================================================================
# 7. Legacy Wrapper Analyzer（合并自 wrapper.py）
# ============================================================================

_BAD_NUMS = {1024, 2048}
_BAD_TOKENS = {"ecb", "pkcs1v15", "pkcs1"}


class WrapperAnalyzer(AnalyzerBase):
    """
    输出两类调用链：
      1) from_func.by_target：以当前函数为起点 → 密码原语
      2) full.by_target：从任意“根函数”出发，经过当前函数 → 密码原语（完整链）
    并保留 use-def / def-use 证据。
    """

    def analyze(
        self,
        code_path: str,
        code: str,
        features: Dict[str, Any],
        *,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        # 延迟导入，避免 wrapper_summary 成为重型依赖
        from ..graph.callgraph import build_callgraph_from_ast
        from ..slice.use_def import backward_slice
        from ..slice.def_use import forward_uses, extract_params_from_signature
        from ..loader import find_rules_for_function

        prior_findings: List[Any] = (context or {}).get("prior_findings", [])
        findings: List[Any] = []
        funcs = features.get("functions", [])
        calls = features.get("calls", [])
        if not funcs:
            return findings

        # 策略参数（可在 policy.org_policy.wrapper_strategy 下配置）
        ws = (self.kb.get("policy") or {}).get("org_policy", {}).get("wrapper_strategy", {}) or {}
        k_per_target = int(ws.get("k_per_target", 2))
        max_paths_total = int(ws.get("max_paths_total", 10))
        max_depth_paths = int(ws.get("max_depth_paths", 8))
        k_prefix = int(ws.get("k_prefix_from_roots", 2))
        include_trie = bool(ws.get("include_trie", True))

        cg = build_callgraph_from_ast(funcs, calls)
        insecure_syms, tainted_funcs = self._collect_insecure_targets(prior_findings, funcs)

        calls_by_line = {c["line"]: c for c in calls}
        code_lines = code.splitlines()

        for fn in funcs:
            fname = fn["name"]
            start, end = fn["start_line"], fn["end_line"]

            # 仅保留能到“密码原语”的命中
            reachable = cg.reachable_from(fname, max_depth=8)
            target_hits = sorted(list(reachable & insecure_syms))
            if not target_hits and not (reachable & tainted_funcs):
                continue

            rules = find_rules_for_function(fname, self.kb)
            if not rules:
                continue
            rule = rules[0]

            # 1) 以当前函数为起点的调用链
            from_func_map = cg.k_shortest_paths(
                src=fname,
                targets=set(target_hits),
                max_depth=max_depth_paths,
                k_per_target=k_per_target,
                max_paths_total=max_paths_total,
                prune=True
            )

            # 2) 经过当前函数的“完整调用链”（根→...→fname→...→原语）
            full_map = cg.k_paths_via_to_targets(
                via=fname,
                targets=set(target_hits),
                max_depth_prefix=max_depth_paths,
                max_depth_suffix=max_depth_paths,
                k_prefix=k_prefix,
                k_suffix_per_target=k_per_target,
                max_paths_total=max_paths_total
            )

            # 压缩树（把所有链扁平化后构建）
            flat_from = [p for plist in from_func_map.values() for p in plist]
            flat_full = [p for plist in full_map.values() for p in plist]
            trie_from = cg.build_path_trie(flat_from) if (include_trie and flat_from) else None
            trie_full = cg.build_path_trie(flat_full) if (include_trie and flat_full) else None

            # 函数体内命中的“原语调用”（用于 use-def）
            local_crypto_calls = []
            for ln in range(start, end + 1):
                c = calls_by_line.get(ln)
                if c and c["symbol"] in target_hits:
                    local_crypto_calls.append(c)

            # use-def：检查是否硬编码/弱参数
            hardcoded_flags = []
            for c in local_crypto_calls:
                m = re.search(r"\((.*)\)", c["code"])
                arg_text = m.group(1) if m else ""
                var_names = re.findall(r'\b([A-Za-z_]\w*)\b', arg_text)
                slice_lines = backward_slice(code_lines, c["line"], var_names, hops=16)
                text = "\n".join(code_lines[i-1] for i in slice_lines)
                nums = set(int(x) for x in re.findall(r'\b(\d{3,5})\b', text))
                toks = {t for t in _BAD_TOKENS if t in text.lower()}
                hard = bool(nums & _BAD_NUMS or toks)
                hardcoded_flags.append({
                    "call_line": c["line"],
                    "nums": sorted(list(nums & _BAD_NUMS)),
                    "tokens": sorted(list(toks)),
                    "is_hardcoded": hard,
                    "use_def_lines": slice_lines[:80]
                })

            # def-use：入参是否被传播
            param_names = extract_params_from_signature(fn["src"])
            ignored_params = []
            for p in param_names:
                used = False
                for hc in hardcoded_flags:
                    ctx_lines = set(hc["use_def_lines"])
                    uses = forward_uses(code_lines, start, p, max_search=(end - start + 8))
                    if uses or any(p in code_lines[i-1] for i in ctx_lines):
                        used = True
                        break
                if not used:
                    ignored_params.append(p)

            violation = any(hc["is_hardcoded"] for hc in hardcoded_flags) or bool(ignored_params)

            # 瘦身硬编码证据
            reduced_hc = [h for h in hardcoded_flags if h["is_hardcoded"]]
            if not reduced_hc and hardcoded_flags:
                reduced_hc = [hardcoded_flags[0]]

            evidence = {
                "violation": violation,
                "call_graph_hits": target_hits,  # 只列出“密码原语”
                "hardcoded": reduced_hc,
                "ignored_params": ignored_params,
                "chains": {
                    "from_func": {
                        "by_target": [{"target": t, "paths": from_func_map.get(t, [])} for t in target_hits],
                        "trie": trie_from
                    },
                    "full": {
                        "by_target": [{"target": t, "paths": full_map.get(t, [])} for t in target_hits],
                        "trie": trie_full
                    }
                }
            }

            f = self.make_finding(
                file=code_path,
                line=fn["start_line"],
                symbol=fname,
                rule=rule,
                layer="wrapper",
                category=rule.get("category", "wrapper"),
                evidence=evidence
            )
            findings.append(f)

        return findings

    # ------- helpers -------
    def _collect_insecure_targets(self, prior: List[Any], funcs: List[Dict[str, Any]]):
        """
        从（library/custom）层 finding 中提取“原语符号”与“不安全本地函数名”。
        """
        insecure_syms: Set[str] = set()
        tainted_funcs: Set[str] = set()
        line_to_func = {}
        for fn in funcs:
            for ln in range(fn["start_line"], fn["end_line"] + 1):
                line_to_func[ln] = fn["name"]
        for f in prior:
            if getattr(f, "layer", None) not in ("library", "custom"):
                continue
            if getattr(f, "symbol", None):
                insecure_syms.add(f.symbol)  # 作为“密码原语”节点
            owner = line_to_func.get(getattr(f, "line", None))
            if owner:
                tainted_funcs.add(owner)
        return insecure_syms, tainted_funcs
