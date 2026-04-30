"""
两阶段分析 Pipeline (v2.0)

Phase 1: AST 快速候选提取
Phase 2: 符号执行精确分析
"""

import ast
import os
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from pqscan.abstract_syntax_tree import scan_candidates
from pqscan.symbolic import analyze_candidates
from pqscan.loader import load_kb_and_policy
from pqscan.reporting.model import Report, Finding
from pqscan.analysis.crypto_constants import (
    get_all_valid_key_sizes,
    get_pipeline_gen_methods,
    get_pipeline_init_methods,
    get_pipeline_key_bits_line_window,
    get_pipeline_null_like_tokens,
)
from pqscan.analysis.wrapper_summary import (
    alg_family as _alg_family,
    append_augmented_finding as _append_augmented_finding,
    apply_pipeline_v2_post_augmentations,
    build_cross_file_wrapper_profiles,
    extract_secp_bits as _extract_secp_bits,
    extract_candidate_key_bits,
    finding_key as _finding_key,
    is_concrete_profile_id as _is_concrete_profile_id,
    is_c_non_crypto_callsite_symbol,
    normalize_func_name as _normalize_func_name,
    reconcile_symbolic_findings,
    resolve_concrete_profile_from_call,
)

# Aliases for backward compatibility and test imports
ScanReport = Report
ScanFinding = Finding


VALID_KEY_BITS = get_all_valid_key_sizes()
GEN_METHODS = get_pipeline_gen_methods()
INIT_METHODS = get_pipeline_init_methods()
NULL_LIKE_TOKENS = get_pipeline_null_like_tokens()
KEY_BITS_LINE_WINDOW = get_pipeline_key_bits_line_window()

_KB_CACHE: Dict[tuple[str, str], Dict[str, Any]] = {}


def _load_pipeline_kb(kb_dir: Path, lang: str) -> Dict[str, Any]:
    """Load KB once per process/language and return a shallow per-file copy."""
    cache_key = (str(Path(kb_dir).resolve()), lang)
    base = _KB_CACHE.get(cache_key)
    if base is None:
        base = load_kb_and_policy(kb_dir, lang, use_v2=True)
        _KB_CACHE[cache_key] = base
    return dict(base)


def _deep_fill_mapping(base: dict, extra: dict) -> dict:
    """Recursively fill missing fields in ``base`` from ``extra``."""
    result = dict(base or {})
    for key, value in (extra or {}).items():
        existing = result.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[key] = _deep_fill_mapping(existing, value)
            continue
        if key not in result or existing in (None, '', [], {}):
            result[key] = value
    return result


def _merge_api_meta(primary: dict, candidate: dict) -> dict:
    merged = dict(primary or {})
    for key, value in (candidate or {}).items():
        if key == 'semantic' and isinstance(value, dict):
            merged['semantic'] = _deep_fill_mapping(
                merged.get('semantic', {}) if isinstance(merged.get('semantic', {}), dict) else {},
                value,
            )
            continue
        if key == 'func_params' and value and not merged.get('func_params'):
            merged[key] = value
            continue
        if key not in merged or merged.get(key) in (None, '', [], {}):
            merged[key] = value
    return merged


def _build_api_meta_map(api_mappings: List[dict]) -> Dict[str, dict]:
    """
    Build a function -> metadata map without losing richer semantics from earlier
    KB entries when later libraries define the same symbol with thinner schemas.
    """
    meta_map: Dict[str, dict] = {}
    for api in api_mappings or []:
        if not isinstance(api, dict) or not api.get('function'):
            continue
        symbol = str(api.get('function')).strip().lower()
        if not symbol:
            continue
        if symbol not in meta_map:
            meta_map[symbol] = dict(api)
        else:
            meta_map[symbol] = _merge_api_meta(meta_map[symbol], api)
    return meta_map


def _semantic_bits_index(meta: dict) -> Optional[int]:
    semantic = meta.get('semantic', {}) if isinstance(meta.get('semantic', {}), dict) else {}
    key_spec = semantic.get('key', {}) if isinstance(semantic.get('key', {}), dict) else {}
    if isinstance(key_spec.get('bits_index'), int):
        return int(key_spec['bits_index'])
    key_bits_spec = semantic.get('key_bits', {}) if isinstance(semantic.get('key_bits', {}), dict) else {}
    if isinstance(key_bits_spec.get('index'), int):
        return int(key_bits_spec['index'])
    bits_param = str(key_spec.get('bits_param') or key_spec.get('nbits_param') or '').strip()
    if bits_param:
        func_params = meta.get('func_params', []) or []
        if bits_param in func_params:
            return func_params.index(bits_param)
    bits_param = str(key_bits_spec.get('param') or key_bits_spec.get('from_param') or '').strip()
    if bits_param:
        func_params = meta.get('func_params', []) or []
        if bits_param in func_params:
            return func_params.index(bits_param)
    return None


def _find_local_include(base_file: str, include_path: str) -> Optional[Path]:
    try:
        base = Path(base_file).resolve()
    except Exception:
        return None
    rel = Path(str(include_path).replace('/', os.sep))
    for parent in [base.parent, *base.parents]:
        candidate = parent / rel
        if candidate.exists():
            return candidate
    return None


def _build_c_expr_helpers(code: str, file_path: str, features: dict) -> dict:
    code_lines = code.splitlines()
    function_ranges: dict[str, tuple[int, int]] = {}
    for fn in features.get('functions', []) or []:
        if not isinstance(fn, dict):
            continue
        name = _normalize_func_name(fn.get('name', ''))
        start = int(fn.get('start_line', 0) or 0)
        end = int(fn.get('end_line', 0) or 0)
        if name and start > 0 and end >= start:
            function_ranges[name] = (start, end)

    const_values: dict[str, int] = {}

    def _collect_constants(text: str) -> None:
        current_owner = ''
        brace_depth = 0
        for raw_line in text.splitlines():
            line = raw_line.strip()
            owner_match = re.match(r'(?:struct|class)\s+([A-Za-z_]\w*)', line)
            if owner_match and '{' in line:
                current_owner = owner_match.group(1)
                brace_depth = line.count('{') - line.count('}')
            elif current_owner:
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    current_owner = ''
                    brace_depth = 0
            for match in re.finditer(
                r'(?:static\s+)?constexpr\s+(?:[\w:<>]+\s+)+([A-Za-z_]\w*)\s*=\s*(\d+)\s*;',
                line,
            ):
                name = match.group(1)
                value = int(match.group(2))
                const_values.setdefault(name, value)
                if current_owner:
                    const_values.setdefault(f'{current_owner}::{name}', value)

    _collect_constants(code)
    include_paths = re.findall(r'^\s*#include\s+"([^"]+)"', code, flags=re.MULTILINE)
    for include in include_paths:
        include_file = _find_local_include(file_path, include)
        if not include_file:
            continue
        try:
            if include_file.stat().st_size > 512 * 1024:
                continue
            _collect_constants(include_file.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            continue

    def _resolve_const_token(token: str) -> Optional[int]:
        text = str(token or '').strip()
        if not text:
            return None
        if text in const_values:
            return const_values[text]
        text_tail = text.split('::')[-1]
        if text_tail in const_values:
            return const_values[text_tail]
        return None

    def _function_text(func_name: str) -> str:
        start_end = function_ranges.get(_normalize_func_name(func_name or ''))
        if not start_end:
            return ''
        start, end = start_end
        return '\n'.join(code_lines[max(0, start - 1):min(len(code_lines), end)])

    def _resolve_size_expr_bytes(expr: str, func_name: str) -> Optional[int]:
        target = re.sub(r'\s+', '', str(expr or ''))
        if not target:
            return None
        func_text = _function_text(func_name)
        if not func_text:
            return None
        patterns = [
            rf'Expects\s*\(\s*{re.escape(target)}\s*==\s*([A-Za-z_][\w:]*)\s*\)',
            rf'if\s*\(\s*{re.escape(target)}\s*!=\s*([A-Za-z_][\w:]*)\s*\)',
            rf'if\s*\(\s*{re.escape(target)}\s*==\s*([A-Za-z_][\w:]*)\s*\)',
        ]
        for pattern in patterns:
            match = re.search(pattern, func_text)
            if not match:
                continue
            value = _resolve_const_token(match.group(1))
            if isinstance(value, int):
                return value
        return None

    def resolve_bits_expr(expr: Any, func_name: str = '') -> Optional[int]:
        text = str(expr or '').strip()
        if not text:
            return None
        try:
            value = int(text, 0)
        except (TypeError, ValueError):
            value = None
        if isinstance(value, int):
            if value <= 64:
                bits = value * 8
                return bits if bits in VALID_KEY_BITS else value if value in VALID_KEY_BITS else None
            return value if value in VALID_KEY_BITS else None

        compact = re.sub(r'\s+', '', text)
        char_match = re.fullmatch(r'(.+)\*CHAR_BIT', compact)
        if char_match:
            lhs = char_match.group(1)
            lhs_value = resolve_bits_expr(lhs, func_name)
            if isinstance(lhs_value, int):
                if lhs_value in VALID_KEY_BITS:
                    return lhs_value
                bits = lhs_value * 8
                return bits if bits in VALID_KEY_BITS else None
            lhs_const = _resolve_const_token(lhs)
            if isinstance(lhs_const, int):
                bits = lhs_const * 8
                return bits if bits in VALID_KEY_BITS else None
            size_bytes = _resolve_size_expr_bytes(lhs, func_name)
            if isinstance(size_bytes, int):
                bits = size_bytes * 8
                return bits if bits in VALID_KEY_BITS else None

        direct_const = _resolve_const_token(compact)
        if isinstance(direct_const, int):
            if direct_const in VALID_KEY_BITS:
                return direct_const
            bits = direct_const * 8
            return bits if bits in VALID_KEY_BITS else None

        size_bytes = _resolve_size_expr_bytes(compact, func_name)
        if isinstance(size_bytes, int):
            bits = size_bytes * 8
            return bits if bits in VALID_KEY_BITS else None
        return None

    return {
        'resolve_bits_expr': resolve_bits_expr,
        'const_values': const_values,
    }


def _infer_c_chain_bits_from_labeled_source(file_path: str, chain: List[str]) -> Optional[int]:
    labels: list[str] = []
    for item in chain or []:
        text = str(item or '').strip()
        if ' [' not in text or not text.endswith(']'):
            continue
        label = text.rsplit(' [', 1)[-1][:-1].strip()
        if label and label not in labels:
            labels.append(label)
    if not labels:
        return None

    try:
        current = Path(file_path).resolve()
    except Exception:
        return None

    search_roots: list[Path] = []
    for parent in [current.parent, *current.parents]:
        if (parent / 'SourceFiles').exists() or parent.name.lower() == 'sourcefiles':
            search_roots.append(parent)
    if not search_roots:
        search_roots.append(current.parent)

    candidates: list[Path] = []
    for label in labels:
        rel = Path(str(label).replace('/', os.sep))
        for root in search_roots:
            exact = root / rel
            if exact.exists():
                if exact.is_file():
                    candidates.append(exact)
                elif exact.is_dir():
                    for match in exact.rglob('*.cpp'):
                        candidates.append(match)
                    for match in exact.rglob('*.cc'):
                        candidates.append(match)
                    for match in exact.rglob('*.c'):
                        candidates.append(match)
                    for match in exact.rglob('*.h'):
                        candidates.append(match)
                    for match in exact.rglob('*.hpp'):
                        candidates.append(match)
            stem = rel.name
            if not stem.endswith(('.c', '.cc', '.cpp', '.h', '.hpp')):
                for ext in ('.cpp', '.cc', '.c', '.h', '.hpp'):
                    for match in root.rglob(stem + ext):
                        candidates.append(match)

    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            text = candidate.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for pattern in (
            r'\bkAesKeyLength\s*=\s*(\d+)\s*;',
            r'\bKeySize\s*=\s*(\d+)\s*;',
            r'\bAES_KEY_LENGTH\s*=\s*(\d+)\s*;',
        ):
            match = re.search(pattern, text)
            if not match:
                continue
            bits = int(match.group(1)) * 8
            if bits in VALID_KEY_BITS:
                return bits
    return None


def run_two_phase_pipeline(
    file_path: str,
    code: str,
    lang: str,
    kb_dir: Path = None,
    use_symbolic: bool = True,
    project_wrapper_context: Dict[str, Any] = None,
    features_override: Optional[Dict[str, Any]] = None,
) -> Report:
    """
    两阶段分析流程
    
    Args:
        file_path: 文件路径
        code: 源代码
        lang: 语言类型
        kb_dir: 知识库目录
        use_symbolic: 是否使用符号执行（Phase 2）
    
    Returns:
        Report 对象
    
    流程：
        1. 加载知识库
        2. Phase 1: AST 快速扫描 → candidates
        3. Phase 2: 符号执行 → findings (可选)
        4. 生成报告
    """
    
    # 1. 加载知识库
    if kb_dir is None:
        kb_dir = Path(__file__).parent.parent / "kb"
    
    kb = _load_pipeline_kb(kb_dir, lang)
    
    # [Task 13.2.2] 提取 features 并添加到 kb（函数内联需要）
    from pqscan.abstract_syntax_tree import extract_features
    features = features_override if isinstance(features_override, dict) and features_override else extract_features(code, lang)
    kb['features'] = features  # 添加到 kb，供 SymbolicAnalyzer 使用
    kb['code'] = code  # 添加代码，供变量追踪使用
    kb['lang'] = lang
    _c_expr_helpers = _build_c_expr_helpers(code, file_path, features) if lang == 'c' else {}

    # [Task 15] 构建本地 wrapper 传播链路（供 _to_finding 读取）
    _scanner_ref = None
    try:
        from pqscan.analysis.scanner import PQScanner as _PQScanner
        _scanner = _PQScanner(kb_dir=kb_dir, verbose=False)
        _scanner_ref = _scanner
        # 直接从 features 填充函数参数表（避免重跑完整 Phase 1）
        _scanner._function_params = {
            f.get('name', ''): f.get('params', [])
            for f in features.get('functions', [])
        }
        _wrapper_contracts = _scanner._build_local_wrapper_contracts(
            features.get('functions', []),
            features.get('calls', []),
            lang,
            features.get('var_assignments', []),
        )

        def _is_native_crypto_anchor(symbol: Any) -> bool:
            text = str(symbol or '').strip()
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
                return True
            try:
                pid = resolve_concrete_profile_from_call(_scanner_ref, text, lang)
                return isinstance(pid, str) and pid.startswith('ALG.')
            except Exception:
                pass
            if '.' not in text:
                return False
            return False

        _wrapper_contracts = {
            sym: wc
            for sym, wc in _wrapper_contracts.items()
            if (
                _is_native_crypto_anchor(wc.get('api_symbol'))
                or any(_is_native_crypto_anchor(item) for item in (wc.get('wrapper_chain', []) or []))
            )
        }

        # [FIX-RECOVERED] Wrapper chains are now safe to enable because candidates
        # with generic symbols (append, add, fix, etc.) are filtered at extraction time
        kb['wrapper_chains'] = {
            sym: wc.get('wrapper_chain', [wc.get('api_symbol', ''), sym])
            for sym, wc in _wrapper_contracts.items()
        }
        kb['_local_wrapper_contracts'] = dict(_wrapper_contracts)
        kb['_local_wrapper_chains'] = {
            sym: list(wc.get('wrapper_chain', []))
            for sym, wc in _wrapper_contracts.items()
            if wc.get('wrapper_chain')
        }
        # [Task 36] Store wrapper contract profile_ids for _to_finding fallback
        kb['_local_wrapper_profiles'] = {
            sym: wc['profile_id']
            for sym, wc in _wrapper_contracts.items()
            if wc.get('profile_id')
        }
        kb['_local_wrapper_key_bits'] = {}
        for sym, wc in _wrapper_contracts.items():
            try:
                bits = _scanner._evaluate_wrapper_key_bits(
                    wc,
                    {'args': []},
                )
                if isinstance(bits, int) and bits in VALID_KEY_BITS:
                    kb['_local_wrapper_key_bits'][sym] = bits
            except Exception:
                continue
        if kb['_local_wrapper_key_bits']:
            changed_bits = True
            while changed_bits:
                changed_bits = False
                for sym, chain in list(kb.get('_local_wrapper_chains', {}).items()):
                    if sym in kb['_local_wrapper_key_bits']:
                        continue
                    inherited = None
                    for item in reversed(list(chain or [])):
                        item_norm = str(item or '').split('.')[-1]
                        for key in (item, item_norm):
                            value = kb['_local_wrapper_key_bits'].get(key)
                            if isinstance(value, int):
                                inherited = value
                                break
                        if inherited is not None:
                            break
                    if isinstance(inherited, int):
                        kb['_local_wrapper_key_bits'][sym] = inherited
                        changed_bits = True

        # Add bounded aliases for local wrapper lookup. For C++ member wrappers
        # the AST often reports member call-sites like `_private.encrypt`, while
        # local contracts are keyed by qualified names such as
        # `RSAPublicKey::Private::encrypt`. Expose a bare normalized alias only
        # when it is unique within the file to avoid cross-wrapper pollution.
        _local_tail_to_symbols: dict[str, list[str]] = {}
        for _sym in _wrapper_contracts:
            _tail = _normalize_func_name(str(_sym or '').split('::')[-1])
            if _tail:
                _local_tail_to_symbols.setdefault(_tail, []).append(_sym)
        for _tail, _symbols in list(_local_tail_to_symbols.items()):
            if len(_symbols) != 1:
                continue
            _sym = _symbols[0]
            _chain = kb.get('_local_wrapper_chains', {}).get(_sym)
            _profile = kb.get('_local_wrapper_profiles', {}).get(_sym)
            _bits = kb.get('_local_wrapper_key_bits', {}).get(_sym)
            if _chain and _tail not in kb['_local_wrapper_chains']:
                kb['_local_wrapper_chains'][_tail] = list(_chain)
            if _profile and _tail not in kb['_local_wrapper_profiles']:
                kb['_local_wrapper_profiles'][_tail] = _profile
            if isinstance(_bits, int) and _tail not in kb['_local_wrapper_key_bits']:
                kb['_local_wrapper_key_bits'][_tail] = _bits

        # [Task 37] Cross-file wrapper profile index. Directory scans pass a
        # project-level index built once and reused by every file; single-file
        # scans keep the bounded local fallback.
        lang_project_context = {}
        if isinstance(project_wrapper_context, dict):
            lang_project_context = project_wrapper_context.get(lang, project_wrapper_context)
        if isinstance(lang_project_context, dict) and lang_project_context.get('profiles') is not None:
            kb['_cross_file_wrapper_profiles'] = dict(lang_project_context.get('profiles') or {})
            kb['_cross_file_wrapper_chains'] = dict(lang_project_context.get('chains') or {})
            kb['_cross_file_wrapper_key_bits'] = dict(lang_project_context.get('key_bits') or {})
        else:
            (
                kb['_cross_file_wrapper_profiles'],
                kb['_cross_file_wrapper_chains'],
                kb['_cross_file_wrapper_key_bits'],
            ) = build_cross_file_wrapper_profiles(
                _scanner_ref,
                lang,
                file_path,
                return_context=True,
            )
        # [Task 36] Store algorithm_mapper reference for _to_finding Pass 4 (e.g. DESede → ALG.3DES)
        kb['algorithm_mapper'] = _scanner.algorithm_mapper
    except Exception:
        kb['wrapper_chains'] = {}
        kb['_local_wrapper_chains'] = {}
        kb['_local_wrapper_profiles'] = {}
        kb['_local_wrapper_key_bits'] = {}
        kb['_cross_file_wrapper_profiles'] = {}
        kb['_cross_file_wrapper_chains'] = {}
        kb['_cross_file_wrapper_key_bits'] = {}
    
    # 2. Phase 1: AST 快速候选提取
    print(f"[Phase 1] AST 快速扫描: {file_path}")
    candidates = scan_candidates(code, lang, kb, file_path)
    print(f"[Phase 1] 发现 {len(candidates)} 个候选点")
    
    # [Task 36] Enrich candidate.profile_id from KB lookup (api_v2 semantic.profile_id support)
    if _scanner_ref is not None:
        # Build a string variable map for dynamic algorithm name resolution
        # e.g., String cipherSpec = "AES/GCM/NoPadding" → _var_str_map['cipherspec'] = 'AES/GCM/NoPadding'
        _early_var_str_map: dict = {}
        for _va in features.get('var_assignments', []):
            _vaname = _va.get('name', '')
            _vaval = _va.get('value', '')
            if isinstance(_vaval, str) and _vaval.startswith('"') and _vaval.endswith('"'):
                _str_content = _vaval[1:-1].strip()
                if _str_content:
                    _early_var_str_map[_vaname.lower()] = _str_content

        # Build a raw call map: (symbol, line) → args list (for enriching candidates with factory string args)
        _call_args_map: dict = {}  # (symbol, line) → args list
        for _rc in features.get('calls', []):
            _rc_sym = _rc.get('symbol', '')
            _rc_line = _rc.get('line', 0)
            if _rc_sym:
                _call_args_map[(_rc_sym, _rc_line)] = _rc.get('args', [])

        # [FIX] 将调用参数中的标识符回代成已知字符串字面量，提升 Java 项目级常量传播能力
        # 例如：crypto = "DES/ECB/PKCS5Padding"; bc.go(crypto, keyAlgo)
        #       → bc.go 的 args 中将携带 resolved value，便于后续 wrapper key_bits 推导。
        for _c in candidates:
            _args = getattr(_c, 'literal_args', None)
            if not isinstance(_args, dict) or not _args:
                continue
            for _k, _v in list(_args.items()):
                if not isinstance(_v, str):
                    continue
                _resolved = _early_var_str_map.get(_v.lower())
                if _resolved:
                    _args[_k] = _resolved

        for _c in candidates:
            if _c.profile_id is None:
                _pid = resolve_concrete_profile_from_call(
                    _scanner_ref,
                    _c.symbol,
                    lang,
                    args=_call_args_map.get((_c.symbol, _c.location.line), []),
                    var_str_map=_early_var_str_map,
                )
                if _pid:
                    _c.profile_id = _pid
            if _c.profile_id is None:
                _wrapper_pid = None
                _symbol_text = str(_c.symbol or '').strip()
                if _symbol_text:
                    _wrapper_maps = []
                    for _key in ('_local_wrapper_profiles', '_cross_file_wrapper_profiles'):
                        _wm = kb.get(_key, {}) if isinstance(kb, dict) else {}
                        if isinstance(_wm, dict):
                            _wrapper_maps.append(_wm)
                    _symbol_candidates = [_symbol_text]
                    _symbol_tail = _normalize_func_name(_symbol_text)
                    if _symbol_tail and _symbol_tail not in _symbol_candidates:
                        _symbol_candidates.append(_symbol_tail)
                    for _wm in _wrapper_maps:
                        for _sym_key in _symbol_candidates:
                            _wrapper_pid = _wm.get(_sym_key) or _wm.get(_sym_key.lower())
                            if _wrapper_pid:
                                break
                        if _wrapper_pid:
                            break
                if _wrapper_pid:
                    _c.profile_id = _wrapper_pid
            elif lang == 'java' and isinstance(_c.profile_id, str):
                # 若已有结果只是泛化 family（如 ALG.RSA / ALG.EC），而 wrapper 元数据
                # 能提供更具体的 profile（如 ALG.RSA.PKE / ALG.ECDH），则优先采用更具体的。
                _wrapper_pid = None
                _symbol_text = str(_c.symbol or '').strip()
                if _symbol_text:
                    for _key in ('_local_wrapper_profiles', '_cross_file_wrapper_profiles'):
                        _wm = kb.get(_key, {}) if isinstance(kb, dict) else {}
                        if not isinstance(_wm, dict):
                            continue
                        _wrapper_pid = _wm.get(_symbol_text) or _wm.get(_normalize_func_name(_symbol_text))
                        if _wrapper_pid:
                            break
                if isinstance(_wrapper_pid, str) and _wrapper_pid.startswith('ALG.'):
                    _current_pid = str(_c.profile_id)
                    _current_rank = len(_current_pid.split('.'))
                    _wrapper_rank = len(_wrapper_pid.split('.'))
                    if _wrapper_rank > _current_rank or _current_pid in {'ALG.RSA', 'ALG.EC', 'ALG.AES', 'ALG.DES', 'ALG.DSA', 'ALG.DH'}:
                        _c.profile_id = _wrapper_pid
            elif lang == 'python' and isinstance(_c.profile_id, str):
                # Python wrapper chains also need the same specificity upgrade.
                _wrapper_pid = None
                _symbol_text = str(_c.symbol or '').strip()
                if _symbol_text:
                    for _key in ('_local_wrapper_profiles', '_cross_file_wrapper_profiles'):
                        _wm = kb.get(_key, {}) if isinstance(kb, dict) else {}
                        if not isinstance(_wm, dict):
                            continue
                        _wrapper_pid = _wm.get(_symbol_text) or _wm.get(_normalize_func_name(_symbol_text))
                        if _wrapper_pid:
                            break
                if isinstance(_wrapper_pid, str) and _wrapper_pid.startswith('ALG.'):
                    _current_pid = str(_c.profile_id)
                    _current_rank = len(_current_pid.split('.'))
                    _wrapper_rank = len(_wrapper_pid.split('.'))
                    if _wrapper_rank > _current_rank or _current_pid in {'ALG.RSA', 'ALG.EC', 'ALG.AES', 'ALG.DES', 'ALG.DSA', 'ALG.DH'}:
                        _c.profile_id = _wrapper_pid
            if lang == 'python' and (_c.profile_id is None or _c.profile_id == 'ALG.ECDH'):
                _sym_lc = str(_c.symbol or '').lower()
                if _sym_lc.startswith('ec.'):
                    if any(_sym_lc == _k for _k in ('ec.generate_private_key', 'ec.ecdh')) or _sym_lc.startswith('ec.secp'):
                        _c.profile_id = 'ALG.EC'
                        _curve_bits = _extract_secp_bits(_c.symbol)
                        if _curve_bits is None:
                            for _lav in (_c.literal_args or {}).values():
                                _curve_bits = _extract_secp_bits(_lav)
                                if _curve_bits is not None:
                                    break
                        if _curve_bits is not None:
                            if _c.literal_args is None:
                                _c.literal_args = {}
                            _c.literal_args['_ctx_key_bits'] = _curve_bits
            if _c.profile_id is not None and str(_c.profile_id).startswith('UTIL.'):
                _resolved_profile = resolve_concrete_profile_from_call(
                    _scanner_ref,
                    _c.symbol,
                    lang,
                    args=_call_args_map.get((_c.symbol, _c.location.line), []),
                    var_str_map=_early_var_str_map,
                )
                if _resolved_profile and not str(_resolved_profile).startswith('UTIL.'):
                    _c.profile_id = _resolved_profile

    # [Task 36] Object context propagation: receiver-chain detection for JCA (Java) and
    # Python hazmat/pycryptodome patterns like:
    #   keyGen = KeyGenerator.getInstance("AES")  → obj_profile[keyGen] = ALG.AES
    #   keyGen.init(256)                           → profile=ALG.AES, key_bits=256
    #   keyGen.generateKey()                       → profile=ALG.AES, key_bits=256 (inherited)
    if _scanner_ref is not None:
        _calls_raw = sorted(
            features.get('calls', []),
            key=lambda item: (int(item.get('line', 0) or 0), int(item.get('column', 0) or 0)),
        )
        _line_to_func: dict = {}
        for _fn in features.get('functions', []):
            _fname = _fn.get('name', '')
            _start = _fn.get('start_line', 0)
            _end = _fn.get('end_line', 0)
            _fname_norm = _normalize_func_name(_fname)
            if _fname_norm and isinstance(_start, int) and isinstance(_end, int) and _end >= _start:
                for _ln in range(_start, _end + 1):
                    _line_to_func[_ln] = _fname_norm

        def _call_func_name(_call: dict) -> str:
            _scope = _call.get('scope', {})
            if isinstance(_scope, dict):
                _fn = _scope.get('function_name') or _scope.get('function')
                if _fn:
                    return _normalize_func_name(_fn)
            _fn = _call.get('function', '')
            if _fn:
                return _normalize_func_name(_fn)
            return _normalize_func_name(_line_to_func.get(_call.get('line', 0), ''))

        def _scope_key(_func_name: str, _var_name: str) -> str:
            _vn = str(_var_name or '').lower()
            if not _vn:
                return _vn
            return f"{_func_name}::{_vn}" if _func_name else _vn

        def _candidate_func_name(_cand) -> str:
            _scope = getattr(_cand, 'scope', None)
            if _scope is not None:
                _fn = getattr(_scope, 'function_name', None) or getattr(_scope, 'function', None)
                if _fn:
                    return _normalize_func_name(_fn)
            _loc = getattr(_cand, 'location', None)
            _line = getattr(_loc, 'line', 0) if _loc is not None else 0
            return _normalize_func_name(_line_to_func.get(_line, ''))

        _obj_profile_history: dict[str, list[tuple[int, str]]] = {}
        _obj_key_bits_history: dict[str, list[tuple[int, int]]] = {}

        def _record_profile(_key: str, _value: Optional[str], _line: Any) -> None:
            if not _key or not _is_concrete_profile_id(_value):
                return
            _obj_profile[_key] = str(_value)
            try:
                _ln = int(_line or 0)
            except Exception:
                _ln = 0
            _obj_profile_history.setdefault(_key, []).append((_ln, str(_value)))

        def _record_key_bits(_key: str, _value: Any, _line: Any) -> None:
            if not _key or not isinstance(_value, int):
                return
            _obj_key_bits[_key] = int(_value)
            try:
                _ln = int(_line or 0)
            except Exception:
                _ln = 0
            _obj_key_bits_history.setdefault(_key, []).append((_ln, int(_value)))

        def _lookup_history(_history: dict, _scoped_key: str, _fallback_key: str, _line: Any):
            try:
                _ln = int(_line or 0)
            except Exception:
                _ln = 0
            for _key in (_scoped_key, _fallback_key):
                if not _key:
                    continue
                _entries = _history.get(_key, [])
                if not _entries:
                    continue
                _best = None
                for _entry_line, _entry_value in _entries:
                    if _ln and _entry_line and _entry_line > _ln:
                        continue
                    if _best is None or _entry_line >= _best[0]:
                        _best = (_entry_line, _entry_value)
                if _best is not None:
                    return _best[1]
                if _entries:
                    return _entries[-1][1]
            return None

        def _lookup_history_values(_history: dict, _scoped_key: str, _fallback_key: str, _line: Any) -> list[Any]:
            try:
                _ln = int(_line or 0)
            except Exception:
                _ln = 0
            for _key in (_scoped_key, _fallback_key):
                if not _key:
                    continue
                _entries = _history.get(_key, [])
                if not _entries:
                    continue
                _values: list[Any] = []
                for _entry_line, _entry_value in _entries:
                    if _ln and _entry_line and _entry_line > _ln:
                        continue
                    if _entry_value not in _values:
                        _values.append(_entry_value)
                if _values:
                    return _values
            return []

        def _lookup_profile(_func_name: str, _var_name: str, _line: Any) -> Optional[str]:
            _vn = str(_var_name or '').lower()
            if not _vn:
                return None
            _value = _lookup_history(_obj_profile_history, _scope_key(_func_name, _vn), _vn, _line)
            return str(_value) if _is_concrete_profile_id(_value) else None

        def _lookup_profile_options(_func_name: str, _var_name: str, _line: Any) -> list[str]:
            _vn = str(_var_name or '').lower()
            if not _vn:
                return []
            return [
                str(_value)
                for _value in _lookup_history_values(_obj_profile_history, _scope_key(_func_name, _vn), _vn, _line)
                if _is_concrete_profile_id(_value)
            ]

        def _lookup_key_bits(_func_name: str, _var_name: str, _line: Any) -> Optional[int]:
            _vn = str(_var_name or '').lower()
            if not _vn:
                return None
            _value = _lookup_history(_obj_key_bits_history, _scope_key(_func_name, _vn), _vn, _line)
            return int(_value) if isinstance(_value, int) else None

        def _lookup_key_bits_options(_func_name: str, _var_name: str, _line: Any) -> list[int]:
            _vn = str(_var_name or '').lower()
            if not _vn:
                return []
            return [
                int(_value)
                for _value in _lookup_history_values(_obj_key_bits_history, _scope_key(_func_name, _vn), _vn, _line)
                if isinstance(_value, int)
            ]

        def _is_java_static_class_call(_symbol: Any) -> bool:
            if lang != 'java':
                return False
            text = str(_symbol or '').strip()
            if '.' not in text:
                return False
            recv = text.split('.', 1)[0].strip()
            if not recv:
                return False
            return recv[:1].isupper()

        def _python_key_bits_from_assignment(_assignment: dict) -> Optional[int]:
            if lang != 'python' or not isinstance(_assignment, dict):
                return None
            _value = str(_assignment.get('value', '') or '').strip()
            if not _value:
                return None
            try:
                _parsed = ast.literal_eval(_value)
            except Exception:
                return None
            if isinstance(_parsed, (bytes, bytearray)):
                _bits = len(_parsed) * 8
                return _bits if _bits in VALID_KEY_BITS else None
            return None

        _obj_profile: dict = {}    # var_name (lower) → profile_id
        _obj_key_bits: dict = {}   # var_name (lower) → key_bits (from init/initialize)
        _c_ctx_findings: list[Finding] = []

        def _build_c_ctx_object_state() -> None:
            """Build OpenSSL-style ctx state using ObjectIDManager, not variable-name globals."""
            if lang != 'c' or _scanner_ref is None:
                return

            oid_manager = getattr(_scanner_ref, 'object_id_manager', None)
            if oid_manager is None:
                return
            try:
                oid_manager.reset()
            except Exception:
                pass

            api_mappings = kb.get('api_mappings', []) if isinstance(kb, dict) else []
            meta_by_symbol: dict[str, dict] = _build_api_meta_map(api_mappings)

            def _clean_var(value: Any) -> str:
                text = str(value or '').strip()
                while text.startswith(('*', '&')):
                    text = text[1:].strip()
                if '[' in text:
                    text = text.split('[', 1)[0].strip()
                return text

            def _arg_text(arg: Any) -> str:
                if isinstance(arg, dict):
                    return str(arg.get('text') or arg.get('value') or '').strip()
                return str(arg or '').strip()

            def _ctx_index(meta: dict) -> int:
                semantic = meta.get('semantic', {}) if isinstance(meta.get('semantic', {}), dict) else {}
                ctx_spec = semantic.get('ctx', {}) if isinstance(semantic.get('ctx', {}), dict) else {}
                if isinstance(ctx_spec.get('index'), int):
                    return int(ctx_spec['index'])
                for idx, param in enumerate(meta.get('func_params', []) or []):
                    if str(param).lower() in {'ctx', 'c', 'dctx', 'm_ctx'}:
                        return idx
                return 0

            def _key_object_index(meta: dict) -> Optional[int]:
                semantic = meta.get('semantic', {}) if isinstance(meta.get('semantic', {}), dict) else {}
                key_spec = semantic.get('key', {}) if isinstance(semantic.get('key', {}), dict) else {}
                if isinstance(key_spec.get('index'), int):
                    return int(key_spec['index'])
                key_param = str(key_spec.get('param') or '').strip()
                if key_param:
                    for idx, param in enumerate(meta.get('func_params', []) or []):
                        if str(param).strip() == key_param:
                            return idx
                return None

            def _resolve_object_from_call(call: dict, meta: dict) -> tuple[Optional[str], Optional[int]]:
                args = call.get('args', []) or []
                candidate_indexes: list[int] = []
                primary_ctx_idx = _ctx_index(meta)
                if isinstance(primary_ctx_idx, int):
                    candidate_indexes.append(primary_ctx_idx)
                key_obj_idx = _key_object_index(meta)
                if isinstance(key_obj_idx, int) and key_obj_idx not in candidate_indexes:
                    candidate_indexes.append(key_obj_idx)
                for idx in candidate_indexes:
                    if idx < 0 or idx >= len(args):
                        continue
                    object_id = oid_manager.resolve_ctx_arg(args[idx], _call_func_name(call), 'c')
                    if object_id:
                        return object_id, idx
                return None, None

            def _object_type(symbol: str, meta: dict) -> str:
                try:
                    return _scanner_ref._infer_object_type(symbol, meta)
                except Exception:
                    if 'MD_CTX' in symbol:
                        return 'EVP_MD_CTX'
                    return 'EVP_CIPHER_CTX'

            def _resolve_algorithm(arg: Any) -> tuple[Optional[str], Optional[int], str, str]:
                symbol = ''
                if isinstance(arg, dict):
                    symbol = str(arg.get('nested_call') or arg.get('function') or arg.get('text') or '').strip()
                else:
                    symbol = str(arg or '').strip()
                symbol = symbol.rstrip(')').rstrip('(').strip()
                if not symbol or symbol.upper() in NULL_LIKE_TOKENS:
                    return None, None, '', ''

                profile_id = None
                try:
                    profile_id = _scanner_ref._identify_kb_api_by_symbol(symbol, lang)
                except Exception:
                    profile_id = None

                key_bits = None
                algorithm = symbol
                meta = meta_by_symbol.get(symbol.lower(), {})
                semantic = meta.get('semantic', {}) if isinstance(meta.get('semantic', {}), dict) else {}
                try:
                    info = _scanner_ref.algorithm_mapper.get_algorithm(symbol)
                    if info:
                        if not profile_id:
                            profile_id = getattr(info, 'profile_id', None)
                        if isinstance(getattr(info, 'key_bits', None), int):
                            key_bits = info.key_bits
                        algorithm = getattr(info, 'name', None) or symbol
                except Exception:
                    pass

                if not profile_id and isinstance(semantic.get('profile_id'), str):
                    profile_id = semantic.get('profile_id')
                if not isinstance(key_bits, int) and isinstance(semantic.get('key_bits'), int):
                    key_bits = semantic.get('key_bits')

                if not _is_concrete_profile_id(profile_id):
                    return None, key_bits, symbol, algorithm
                return str(profile_id), key_bits, symbol, algorithm

            def _write_ctx_from_call(call: dict) -> None:
                symbol = str(call.get('symbol') or '').strip()
                meta = meta_by_symbol.get(symbol.lower(), {})
                if not meta:
                    return
                semantic = meta.get('semantic', {}) if isinstance(meta.get('semantic', {}), dict) else {}
                args = call.get('args', []) or []
                object_id, _ = _resolve_object_from_call(call, meta)
                if not object_id:
                    return

                func_params = meta.get('func_params', []) or []
                alg_idx = None
                alg_source = semantic.get('algorithm_source')
                if isinstance(alg_source, dict):
                    alg_param = alg_source.get('param')
                    if alg_param in func_params:
                        alg_idx = func_params.index(alg_param)
                    elif isinstance(alg_source.get('index'), int):
                        alg_idx = int(alg_source['index'])
                if alg_idx is None:
                    for idx, param in enumerate(func_params):
                        if str(param).lower() in {'cipher', 'md', 'digest', 'alg', 'algorithm'}:
                            alg_idx = idx
                            break

                if alg_idx is not None and alg_idx < len(args):
                    profile_id, key_bits, alg_symbol, algorithm = _resolve_algorithm(args[alg_idx])
                    if _is_concrete_profile_id(profile_id):
                        oid_manager.write_state(object_id, 'profile_id', profile_id, call.get('line'))
                        oid_manager.write_state(object_id, 'algorithm', algorithm, call.get('line'))
                        oid_manager.write_state(object_id, 'algorithm_symbol', alg_symbol, call.get('line'))
                        if isinstance(key_bits, int):
                            oid_manager.write_state(object_id, 'key_bits', key_bits, call.get('line'))

                # APIs like AES_set_encrypt_key/AES_set_decrypt_key write an object
                # state directly through semantic.key + bits_param without a separate
                # algorithm_source field. Persist that state so follow-up calls such as
                # AES_ige_encrypt(..., &aes, ...) can recover key_bits from the same
                # AES_KEY object.
                key_spec = semantic.get('key', {}) if isinstance(semantic.get('key', {}), dict) else {}
                semantic_profile = semantic.get('profile_id')
                if _is_concrete_profile_id(semantic_profile):
                    oid_manager.write_state(object_id, 'profile_id', str(semantic_profile), call.get('line'))
                    oid_manager.write_state(object_id, 'algorithm', _alg_family(str(semantic_profile)), call.get('line'))
                    bits_idx = None
                    bits_idx = _semantic_bits_index(meta)
                    if isinstance(bits_idx, int) and 0 <= bits_idx < len(args):
                        raw_bits = _arg_text(args[bits_idx])
                        try:
                            bits = int(raw_bits, 0)
                        except (TypeError, ValueError):
                            bits = None
                        if isinstance(bits, int):
                            if bits <= 64:
                                bits *= 8
                            if bits in VALID_KEY_BITS:
                                oid_manager.write_state(object_id, 'key_bits', bits, call.get('line'))

                # Explicit key-length setters should refine the same object_id.
                if 'set_key_length' in symbol.lower() and len(args) >= 2:
                    raw_len = _arg_text(args[1])
                    try:
                        key_len = int(raw_len, 0)
                        bits = key_len * 8 if key_len <= 64 else key_len
                        if bits in VALID_KEY_BITS:
                            oid_manager.write_state(object_id, 'key_bits', bits, call.get('line'))
                    except (TypeError, ValueError):
                        pass

            def _ctx_state_for_call(call: dict) -> tuple[Optional[str], Optional[int], str, str]:
                symbol = str(call.get('symbol') or '').strip()
                meta = meta_by_symbol.get(symbol.lower(), {})
                if not meta:
                    return None, None, '', ''
                object_id, _ = _resolve_object_from_call(call, meta)
                if not object_id:
                    return None, None, '', ''
                profile_id = oid_manager.read_state(object_id, 'profile_id')
                key_bits = oid_manager.read_state(object_id, 'key_bits')
                alg_symbol = oid_manager.read_state(object_id, 'algorithm_symbol') or ''
                return profile_id, key_bits if isinstance(key_bits, int) else None, object_id, alg_symbol

            func_params = {
                str(fn.get('name') or ''): [str(p) for p in (fn.get('params', []) or [])]
                for fn in features.get('functions', []) or []
                if isinstance(fn, dict) and fn.get('name')
            }
            existing_keys: set = set()
            timeline: list[tuple[int, int, str, dict]] = []
            for assignment in features.get('var_assignments', []) or []:
                if isinstance(assignment, dict):
                    timeline.append((int(assignment.get('line', 0) or 0), 0, 'assignment', assignment))
            for call in features.get('calls', []) or []:
                if isinstance(call, dict):
                    timeline.append((int(call.get('line', 0) or 0), 1, 'call', call))
            timeline.sort(key=lambda item: (item[0], item[1]))

            def _refresh_legacy_scope_maps() -> None:
                _obj_profile.clear()
                _obj_key_bits.clear()
                for (scope, var_name), object_id in list(oid_manager.var_to_object.items()):
                    state = oid_manager.get_all_state(object_id)
                    pid = state.get('profile_id')
                    bits = state.get('key_bits')
                    if _is_concrete_profile_id(pid):
                        _record_profile(_scope_key(scope, var_name), pid, state.get('updated_at'))
                    if isinstance(bits, int):
                        _record_key_bits(_scope_key(scope, var_name), bits, state.get('updated_at'))

            def _emit_ctx_finding_for_call(call: dict) -> None:
                symbol = str(call.get('symbol') or '').strip()
                if not symbol:
                    return
                meta = meta_by_symbol.get(symbol.lower(), {})
                semantic = meta.get('semantic', {}) if isinstance(meta.get('semantic', {}), dict) else {}
                operation = str(semantic.get('operation') or '').lower()
                is_ctx_api = (
                    isinstance(semantic.get('ctx'), dict)
                    or (
                        isinstance(semantic.get('key'), dict)
                        and isinstance(_key_object_index(meta), int)
                    )
                    or isinstance(semantic.get('context_reads'), list)
                    or operation in {'init', 'update', 'final', 'finalize'}
                    or symbol.startswith(('EVP_Encrypt', 'EVP_Decrypt', 'EVP_Cipher'))
                )
                if not is_ctx_api:
                    return
                profile_id, key_bits, object_id, alg_symbol = _ctx_state_for_call(call)
                if not _is_concrete_profile_id(profile_id):
                    return
                line = int(call.get('line', 0) or 0)
                chain = [item for item in [alg_symbol, symbol] if item]
                _append_augmented_finding(
                    _c_ctx_findings,
                    existing_keys,
                    file_path=file_path,
                    line=line,
                    symbol=symbol,
                    profile_id=str(profile_id),
                    key_bits=key_bits,
                    source='pipeline_v2_c_object_ctx',
                    rule_id='PIPELINE.V2.C_OBJECT_CTX',
                    severity='high',
                    reason=f'OpenSSL ctx object state resolved for {symbol}',
                    recommendation='Verify OpenSSL context algorithm and key length meet quantum-safe policy.',
                    algorithm=_alg_family(str(profile_id)),
                    confidence=0.72,
                    wrapper_chain=chain or [symbol],
                    key_bits_reason=(
                        f"key_bits 由 OpenSSL ctx object_id 传播得到：{object_id}。"
                        "该值来自同一对象上的 EVP_*Init*/配置调用，按作用域和对象分配点区分不同 ctx。"
                        if isinstance(key_bits, int)
                        else None
                    ),
                )

            for _, _, event_type, payload in timeline:
                if event_type == 'assignment':
                    assignment = payload
                    name = str(assignment.get('name') or '').strip()
                    value = str(assignment.get('value') or '').strip()
                    scope = _normalize_func_name(assignment.get('function') or 'global') or 'global'
                    if not name or not value:
                        continue
                    ast_info = assignment.get('ast_info') if isinstance(assignment.get('ast_info'), dict) else {}
                    if ast_info.get('type') == 'call' and oid_manager.is_allocator(value, language='c'):
                        meta = meta_by_symbol.get(value.lower(), {})
                        oid_manager.allocate_object(
                            name,
                            f"{value}:line{int(assignment.get('line', 0) or 0)}",
                            scope,
                            _object_type(value, meta),
                            assignment.get('line'),
                        )
                    elif value.isidentifier():
                        oid_manager.bind_alias(name, value, scope)
                    _refresh_legacy_scope_maps()
                    continue

                call = payload
                callee = str(call.get('symbol') or '').strip()
                params = func_params.get(callee)
                if params:
                    caller = _call_func_name(call) or 'global'
                    for idx, arg in enumerate(call.get('args', []) or []):
                        if idx >= len(params):
                            break
                        arg_var = _clean_var(_arg_text(arg))
                        if arg_var and arg_var.isidentifier():
                            oid_manager.bind_parameter(caller, callee, params[idx], arg_var)
                _write_ctx_from_call(call)
                _refresh_legacy_scope_maps()
                _emit_ctx_finding_for_call(call)

        _build_c_ctx_object_state()

        # Step 1: build obj_profile and obj_key_bits from factory calls
        # Use existing _early_var_str_map for string variable resolution (built above)
        _var_str_map: dict = _early_var_str_map

        # [Task 36] Build line→[var_names] map for tuple-assignment languages (e.g. Go)
        # Go: block, err := aes.NewCipher(key)  → assigned_to=None, but var_assignments has
        # {'name': 'block', 'value': 'Cipher', 'line': 27}
        _line_varassign: dict = {}  # line_no → list of var names assigned on that line
        for _lva in features.get('var_assignments', []):
            _lva_line = _lva.get('line')
            _lva_name = _lva.get('name', '')
            if _lva_line and _lva_name:
                _line_varassign.setdefault(_lva_line, []).append(_lva_name)
            _lva_func = _normalize_func_name(_lva.get('function', ''))
            _lva_key = _scope_key(_lva_func, _lva_name)
            _python_bits = _python_key_bits_from_assignment(_lva)
            if isinstance(_python_bits, int):
                _record_key_bits(_lva_key, _python_bits, _lva_line)

        for _call in _calls_raw:
            _sym = _call.get('symbol', '')
            _asgn = _call.get('assigned_to')
            _call_func = _call_func_name(_call)
            _args = _call.get('args', [])
            # [Task 36] Fallback: if assigned_to is None (Go tuple assignments),
            # use the first non-underscore var assigned on the same line.
            if not _asgn:
                _call_line = _call.get('line')
                if _call_line:
                    _line_vars = _line_varassign.get(_call_line, [])
                    for _lv in _line_vars:
                        if _lv and _lv != '_' and _lv != 'err':
                            _asgn = _lv
                            break
            # Profile propagation: if this call symbol has a concrete profile and is assigned
            if _asgn:
                _asgn_key = _scope_key(_call_func, _asgn)
                _pid = _scanner_ref._identify_kb_api_by_symbol(_sym, lang)
                # Exclude UTIL profiles (factory utilities that don't identify a specific algorithm)
                if (_pid and _scanner_ref._is_concrete_algorithm(_pid)
                        and not str(_pid).startswith('UTIL.')):
                    _record_profile(_asgn_key, _pid, _call.get('line'))
                    # [Task 36] Also capture key_bits from algorithm_mapper if available
                    # e.g., EVP_aes_256_cbc → key_bits=256
                    _kbits_info = _scanner_ref.algorithm_mapper.get_algorithm(_sym)
                    if _kbits_info and isinstance(getattr(_kbits_info, 'key_bits', None), int):
                        _record_key_bits(_asgn_key, _kbits_info.key_bits, _call.get('line'))
                    for _arg in _args:
                        if isinstance(_arg, dict) and isinstance(_arg.get('length_bytes'), int):
                            _bits_from_arg = int(_arg['length_bytes']) * 8
                            if _bits_from_arg in VALID_KEY_BITS:
                                _record_key_bits(_asgn_key, _bits_from_arg, _call.get('line'))
                                break
                        if isinstance(_arg, dict) and _arg.get('type') == 'identifier':
                            _arg_name = str(_arg.get('text') or _arg.get('value') or '').strip()
                            _prop_bits = _lookup_key_bits(_call_func, _arg_name, _call.get('line'))
                            if isinstance(_prop_bits, int):
                                _record_key_bits(_asgn_key, _prop_bits, _call.get('line'))
                                break
                # [Task 36] Also try string arg as algorithm name (Java JCA pattern):
                # e.g., KeyGenerator.getInstance("AES") → extract "AES" → profile=ALG.AES
                # Also handles dynamic variables: String algo = "AES"; getInstance(algo)
                # Also handles object-arg propagation: gcm = cipher.NewGCM(block) → block's profile
                if _asgn_key not in _obj_profile and _asgn.lower() not in _obj_profile:
                    for _arg in _args:
                        if not isinstance(_arg, dict):
                            continue
                        _v = _arg.get('value') or _arg.get('text', '')
                        # Propagate from object arg (e.g., cipher.NewGCM(block) where block=ALG.AES)
                        if (isinstance(_v, str) and _v and _arg.get('type') == 'identifier'):
                            _prop_pid = _lookup_profile(_call_func, _v, _call.get('line'))
                            if _prop_pid and not str(_prop_pid).startswith('UTIL.'):
                                _record_profile(_asgn_key, _prop_pid, _call.get('line'))
                                _prop_bits = _lookup_key_bits(_call_func, _v, _call.get('line'))
                                if isinstance(_prop_bits, int):
                                    _record_key_bits(_asgn_key, _prop_bits, _call.get('line'))
                                break
                            # Resolve identifier variables to their string values
                            _resolved = _var_str_map.get(_v.lower())
                            if _resolved:
                                _v = _resolved
                        if isinstance(_v, str) and 1 <= len(_v) <= 30 and not _v.startswith('"'):
                            _alg_name = _v.split('/')[0].strip().upper()
                            _ainfo = _scanner_ref.algorithm_mapper.get_algorithm_by_name(_alg_name)
                            if _ainfo and _scanner_ref._is_concrete_algorithm(_ainfo.profile_id):
                                _record_profile(_asgn_key, _ainfo.profile_id, _call.get('line'))
                                for _bits_arg in _args:
                                    if isinstance(_bits_arg, dict) and isinstance(_bits_arg.get('length_bytes'), int):
                                        _bits_from_arg = int(_bits_arg['length_bytes']) * 8
                                        if _bits_from_arg in VALID_KEY_BITS:
                                            _record_key_bits(_asgn_key, _bits_from_arg, _call.get('line'))
                                            break
                                    if isinstance(_bits_arg, dict) and _bits_arg.get('type') == 'identifier':
                                        _id_name = str(_bits_arg.get('text') or _bits_arg.get('value') or '').strip()
                                        _prop_bits = _lookup_key_bits(_call_func, _id_name, _call.get('line'))
                                        if isinstance(_prop_bits, int):
                                            _record_key_bits(_asgn_key, _prop_bits, _call.get('line'))
                                            break
                                break
            # Key-bits propagation: track init(N) / initialize(N)
            if '.' in _sym:
                _recv_lc = _sym.split('.')[0].lower()
                _meth_lc = _sym.split('.')[-1].lower()
                if _meth_lc in INIT_METHODS:
                    for _arg in _args:
                        if not isinstance(_arg, dict):
                            continue
                        # Support both 'value' (Python) and 'text' (Java) numeric arg formats
                        _v = _arg.get('value')
                        if _v is None:
                            try:
                                _v = int(_arg.get('text', ''))
                            except (ValueError, TypeError):
                                pass
                        if isinstance(_v, int) and _v in VALID_KEY_BITS:
                            _record_key_bits(_scope_key(_call_func, _recv_lc), _v, _call.get('line'))
                            break

        # Step 1b: also parse var_assignments for "new XYZ()" constructor patterns
        # e.g., KyberKeyPairGenerator kyberGen = new KyberKeyPairGenerator()
        # → obj_profile['kybergen'] = ALG.KYBER (if KB has KyberKeyPairGenerator.__init__)
        _var_assignments = features.get('var_assignments', [])
        for _va in _var_assignments:
            _vname = _va.get('name', '')
            _vval = _va.get('value', '')
            _vfunc = _normalize_func_name(_va.get('function', ''))
            if not _vname or not _vval:
                continue
            _vname_lc = _vname.lower()
            _vname_key = _scope_key(_vfunc, _vname_lc)
            if _lookup_profile(_vfunc, _vname_lc, _va.get('line')) is not None:
                continue  # already resolved
            # Match "new XYZ()" → extract XYZ and look up XYZ.__init__ in KB
            if isinstance(_vval, str) and _vval.strip().startswith('new '):
                _class_part = _vval.strip()[4:].split('(')[0].strip()
                if _class_part:
                    # Try lookup with __init__ suffix
                    _ctor_sym = _class_part + '.__init__'
                    _pid = _scanner_ref._identify_kb_api_by_symbol(_ctor_sym, lang)
                    if not _pid:
                        # Try just the class name lookup
                        _pid = _scanner_ref._identify_kb_api_by_symbol(_class_part, lang)
                    if not _pid:
                        # Try known Java init method names for this class (BC pattern):
                        # KyberKeyPairGenerator has "KyberKeyPairGenerator.init" in KB
                        _class_lc = _class_part.lower()
                        _am = _scanner_ref.algorithm_mapper
                        for _lib_maps in _am.algorithm_maps.values():
                            _candidate_key = _class_lc + '.init'
                            if _candidate_key in _lib_maps:
                                _ainfo = _am._dict_to_algorithm_info(_lib_maps[_candidate_key])
                                if _ainfo and not str(_ainfo.profile_id).startswith('UTIL.'):
                                    _pid = _ainfo.profile_id
                                    break
                    if _pid and not str(_pid).startswith('UTIL.') and _scanner_ref._is_concrete_algorithm(_pid):
                        _record_profile(_vname_key, _pid, _va.get('line'))

        # Step 1c: C/procedural context-binding propagation
        # Pattern: EncryptInit_ex(ctx_var, algo_var, ...)
        #   where algo_var is in _obj_profile with a concrete profile
        #   → propagate algo_var's profile to ctx_var.
        # Also handles inline nested calls: EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), ...)
        # Runs repeatedly until stable (handles multi-hop chaining).
        _ctx_bind_changed = True
        _ctx_bind_iters = 0
        while _ctx_bind_changed and _ctx_bind_iters < 10:
            _ctx_bind_changed = False
            _ctx_bind_iters += 1
            for _call in _calls_raw:
                _call_func = _call_func_name(_call)
                _args = _call.get('args', [])
                if len(_args) < 2:
                    continue
                # First arg must be an identifier (the context var)
                _ctx_arg = _args[0]
                if not isinstance(_ctx_arg, dict) or _ctx_arg.get('type') != 'identifier':
                    continue
                _ctx_var = (_ctx_arg.get('text') or _ctx_arg.get('value') or '').lower()
                if not _ctx_var or _ctx_var in NULL_LIKE_TOKENS:
                    continue
                _ctx_var_key = _scope_key(_call_func, _ctx_var)
                if _lookup_profile(_call_func, _ctx_var, _call.get('line')) is not None:
                    continue  # already has a profile, don't overwrite
                # Looking for a subsequent arg that resolves to a concrete profile
                _bound_pid = None
                for _carg in _args[1:]:
                    if not isinstance(_carg, dict):
                        continue
                    _ctype = _carg.get('type', '')
                    _ctext = (_carg.get('text') or _carg.get('value') or '').lower()
                    if not _ctext or _ctext in NULL_LIKE_TOKENS:
                        continue
                    # Case A: identifier that is already in _obj_profile
                    if _ctype == 'identifier':
                        _pid_from_arg = _lookup_profile(_call_func, _ctext, _call.get('line'))
                        if _pid_from_arg and not str(_pid_from_arg).startswith('UTIL.'):
                            _bound_pid = _pid_from_arg
                            break
                    # Case B: nested call_expression (e.g. EVP_aes_128_gcm() inline)
                    if _ctype in ('call_expression', 'call'):
                        _nested_sym = _carg.get('text', '')
                        # Strip trailing () for KB lookup
                        _nested_clean = _nested_sym.rstrip(')').rstrip('(').strip()
                        if _nested_clean:
                            _npid = _scanner_ref._identify_kb_api_by_symbol(_nested_clean, lang)
                            if _npid and not str(_npid).startswith('UTIL.') and _scanner_ref._is_concrete_algorithm(_npid):
                                _bound_pid = _npid
                                break
                if _bound_pid:
                    _record_profile(_ctx_var_key, _bound_pid, _call.get('line'))
                    # Also propagate key_bits if the algo var has them
                    for _carg2 in _args[1:]:
                        if not isinstance(_carg2, dict):
                            continue
                        _ctext2 = (_carg2.get('text') or _carg2.get('value') or '').lower()
                        if _ctext2:
                            _kbits = _lookup_key_bits(_call_func, _ctext2, _call.get('line'))
                            if _kbits:
                                _record_key_bits(_ctx_var_key, _kbits, _call.get('line'))
                            break
                    _ctx_bind_changed = True

        # Step 1d: C/procedural object-key propagation for APIs that materialize
        # a key schedule/state object via an out-parameter, e.g.
        #   AES_set_encrypt_key(..., 256, &aes)
        # followed by
        #   AES_ige_encrypt(..., &aes, ...)
        # These variables are often plain stack declarations rather than heap
        # allocators, so ObjectIDManager will not necessarily allocate them.
        if lang == 'c' and isinstance(kb, dict):
            _api_meta_map = _build_api_meta_map(kb.get('api_mappings', []) or [])

            def _clean_c_obj_arg(_value: Any) -> str:
                _text = str(_value or '').strip()
                while _text.startswith(('*', '&')):
                    _text = _text[1:].strip()
                if '[' in _text:
                    _text = _text.split('[', 1)[0].strip()
                return _text

            for _call in _calls_raw:
                _sym = str(_call.get('symbol') or '').strip()
                if not _sym:
                    continue
                _meta = _api_meta_map.get(_sym.lower(), {})
                _semantic = _meta.get('semantic', {}) if isinstance(_meta.get('semantic', {}), dict) else {}
                _key_spec = _semantic.get('key', {}) if isinstance(_semantic.get('key', {}), dict) else {}
                _pid = str(_semantic.get('profile_id') or '')
                if not _is_concrete_profile_id(_pid):
                    continue
                _bits_idx = _semantic_bits_index(_meta)
                _obj_idx = None
                if isinstance(_semantic.get('ctx'), dict) and isinstance(_semantic['ctx'].get('index'), int):
                    _obj_idx = int(_semantic['ctx']['index'])
                elif isinstance(_key_spec.get('index'), int):
                    _obj_idx = int(_key_spec['index'])
                _args = _call.get('args', []) or []
                if not isinstance(_bits_idx, int) or not isinstance(_obj_idx, int):
                    continue
                if _bits_idx >= len(_args) or _obj_idx >= len(_args):
                    continue
                _obj_arg = _args[_obj_idx]
                _obj_name = ''
                if isinstance(_obj_arg, dict):
                    _obj_name = _clean_c_obj_arg(_obj_arg.get('text') or _obj_arg.get('value') or '')
                else:
                    _obj_name = _clean_c_obj_arg(_obj_arg)
                if not _obj_name:
                    continue
                _bits_arg = _args[_bits_idx]
                _raw_bits = ''
                if isinstance(_bits_arg, dict):
                    _raw_bits = str(_bits_arg.get('text') or _bits_arg.get('value') or '').strip()
                else:
                    _raw_bits = str(_bits_arg or '').strip()
                try:
                    _bits = int(_raw_bits, 0)
                except (TypeError, ValueError):
                    _bits = _c_expr_helpers.get('resolve_bits_expr', lambda *_: None)(_raw_bits, _call_func_name(_call))
                if isinstance(_bits, int):
                    if _bits <= 64:
                        _bits *= 8
                    if _bits in VALID_KEY_BITS:
                        _record_profile(_scope_key(_call_func_name(_call), _obj_name.lower()), _pid, _call.get('line'))
                        _record_key_bits(_scope_key(_call_func_name(_call), _obj_name.lower()), _bits, _call.get('line'))

        # Step 2: propagate to candidates
        if _obj_profile or _obj_key_bits:
            _api_meta_map = _build_api_meta_map(kb.get('api_mappings', []) or []) if isinstance(kb, dict) else {}

            def _clean_c_obj_arg(_value: Any) -> str:
                _text = str(_value or '').strip()
                while _text.startswith(('*', '&')):
                    _text = _text[1:].strip()
                if '[' in _text:
                    _text = _text.split('[', 1)[0].strip()
                return _text

            for _cand in candidates:
                _cand_func = _candidate_func_name(_cand)
                _csym = _cand.symbol
                if '.' not in _csym:
                    # [Task 36] C/procedural: check if first call arg is a context var in _obj_profile
                    # e.g., EVP_EncryptUpdate(ctx, ...) → inherit ctx's profile
                    if _cand.profile_id is None and _obj_profile:
                        _cand_args_c = _call_args_map.get((_csym, _cand.location.line), [])
                        if _cand_args_c:
                            _first_arg = _cand_args_c[0]
                            if isinstance(_first_arg, dict) and _first_arg.get('type') == 'identifier':
                                _ctx_name = (_first_arg.get('text') or _first_arg.get('value') or '').lower()
                                if _ctx_name and _ctx_name not in NULL_LIKE_TOKENS:
                                    _ctx_pid = _lookup_profile(_cand_func, _ctx_name, _cand.location.line)
                                    if _ctx_pid and not str(_ctx_pid).startswith('UTIL.'):
                                        _cand.profile_id = _ctx_pid
                                        # Also propagate key_bits from ctx
                                        _ctx_kbits = _lookup_key_bits(_cand_func, _ctx_name, _cand.location.line)
                                        if _ctx_kbits:
                                            _existing_kbits = any(
                                                isinstance(v, int) and v in VALID_KEY_BITS
                                                for v in _cand.literal_args.values()
                                            )
                                            if not _existing_kbits:
                                                _cand.literal_args['_ctx_key_bits'] = _ctx_kbits

                    # [Task 40] C/procedural object-key propagation:
                    # APIs like AES_ige_encrypt(..., &aes, ...) and
                    # CRYPTO_ctr128_encrypt(..., &aes, ...) carry the effective
                    # key_bits through an object parameter recorded earlier by
                    # AES_set_*_key(..., bits, &aes). Use semantic.key.index to
                    # recover that object-bound key length even when the direct
                    # call itself exposes no numeric key-size argument.
                    _cand_args_c = _call_args_map.get((_csym, _cand.location.line), [])
                    _meta = _api_meta_map.get(str(_csym or '').strip().lower(), {})
                    _semantic = _meta.get('semantic', {}) if isinstance(_meta.get('semantic', {}), dict) else {}
                    _key_spec = _semantic.get('key', {}) if isinstance(_semantic.get('key', {}), dict) else {}
                    _key_index = _key_spec.get('index') if isinstance(_key_spec.get('index'), int) else None
                    if isinstance(_key_index, int) and 0 <= _key_index < len(_cand_args_c):
                        _key_arg = _cand_args_c[_key_index]
                        _key_name = ''
                        if isinstance(_key_arg, dict):
                            _key_name = _clean_c_obj_arg(_key_arg.get('text') or _key_arg.get('value') or '')
                        else:
                            _key_name = _clean_c_obj_arg(_key_arg)
                        if _key_name:
                            _ctx_kbits = _lookup_key_bits(_cand_func, _key_name.lower(), _cand.location.line)
                            if _ctx_kbits and not any(
                                isinstance(v, int) and v in VALID_KEY_BITS
                                for v in _cand.literal_args.values()
                            ):
                                _cand.literal_args['_ctx_key_bits'] = _ctx_kbits
                    _bits_idx = _semantic_bits_index(_meta)
                    if isinstance(_bits_idx, int) and 0 <= _bits_idx < len(_cand_args_c):
                        _bits_arg = _cand_args_c[_bits_idx]
                        _raw_bits = ''
                        if isinstance(_bits_arg, dict):
                            _raw_bits = str(_bits_arg.get('text') or _bits_arg.get('value') or '').strip()
                        else:
                            _raw_bits = str(_bits_arg or '').strip()
                        _resolved_bits = _c_expr_helpers.get('resolve_bits_expr', lambda *_: None)(_raw_bits, _cand_func)
                        if isinstance(_resolved_bits, int) and not any(
                            isinstance(v, int) and v in VALID_KEY_BITS
                            for v in _cand.literal_args.values()
                        ):
                            _cand.literal_args['_ctx_key_bits'] = _resolved_bits
                    continue
                _crecv = _csym.split('.')[0].lower()
                _cmeth = _csym.split('.')[-1].lower()
                if not _is_java_static_class_call(_csym):
                    _profile_options = _lookup_profile_options(_cand_func, _crecv, _cand.location.line)
                    if len(_profile_options) > 1:
                        _cand.literal_args['_possible_profiles'] = _profile_options
                    # Propagate profile_id only for instance/receiver calls.
                    _inherited_pid = _lookup_profile(_cand_func, _crecv, _cand.location.line)
                    if _inherited_pid:
                        _cand.profile_id = _inherited_pid
                    # Propagate key_bits for operation and init methods when receiver's key_bits known
                    if _cmeth in GEN_METHODS or _cmeth in INIT_METHODS:
                        _key_bits_options = _lookup_key_bits_options(_cand_func, _crecv, _cand.location.line)
                        if len(_key_bits_options) > 1:
                            _cand.literal_args['_possible_key_bits'] = _key_bits_options
                        _kbits = _lookup_key_bits(_cand_func, _crecv, _cand.location.line)
                        if not _kbits and _cmeth in INIT_METHODS:
                            for _arg in _call_args_map.get((_csym, _cand.location.line), []):
                                if not isinstance(_arg, dict):
                                    continue
                                if isinstance(_arg.get('length_bytes'), int):
                                    _candidate_bits = int(_arg['length_bytes']) * 8
                                    if _candidate_bits in VALID_KEY_BITS:
                                        _kbits = _candidate_bits
                                        break
                                if _arg.get('type') == 'identifier':
                                    _arg_name = str(_arg.get('text') or _arg.get('value') or '').lower()
                                    if _arg_name:
                                        _kbits = _lookup_key_bits(_cand_func, _arg_name, _cand.location.line)
                                        if _kbits:
                                            break
                        if _kbits:
                            # Inject key_bits into literal_args if not already set
                            _existing_kbits = any(
                                isinstance(v, int) and v in VALID_KEY_BITS
                                for v in _cand.literal_args.values()
                            )
                            if not _existing_kbits:
                                _cand.literal_args['_ctx_key_bits'] = _kbits

    # 3. Phase 2: 符号执行（可选）
    if use_symbolic and candidates:
        print(f"[Phase 2] 符号执行分析...")
        findings = analyze_candidates(candidates, code, lang, kb)
        findings = reconcile_symbolic_findings(
            findings=findings,
            line_to_func=_line_to_func if '_line_to_func' in locals() else {},
            obj_profile=_obj_profile if '_obj_profile' in locals() else {},
            obj_key_bits=_obj_key_bits if '_obj_key_bits' in locals() else {},
            valid_key_bits=set(VALID_KEY_BITS),
            key_bits_line_window=KEY_BITS_LINE_WINDOW,
        )
        if '_c_ctx_findings' in locals() and _c_ctx_findings:
            existing_by_key = {_finding_key(finding): finding for finding in findings}
            for ctx_finding in _c_ctx_findings:
                key = _finding_key(ctx_finding)
                if key in existing_by_key:
                    existing = existing_by_key[key]
                    existing_bits = getattr(existing, 'key_bits', None)
                    ctx_bits = getattr(ctx_finding, 'key_bits', None)
                    if existing_bits is None and isinstance(ctx_bits, int):
                        setattr(existing, 'key_bits', ctx_bits)
                        setattr(existing, 'key_bits_reason', getattr(ctx_finding, 'key_bits_reason', None))
                        existing_evidence = getattr(existing, 'evidence', None)
                        if not isinstance(existing_evidence, dict):
                            existing_evidence = {}
                            setattr(existing, 'evidence', existing_evidence)
                        existing_evidence['source'] = 'pipeline_v2_c_object_ctx'
                        if getattr(ctx_finding, 'wrapper_chain', None):
                            setattr(existing, 'wrapper_chain', list(getattr(ctx_finding, 'wrapper_chain', []) or []))
                    existing_chain = list(getattr(existing, 'wrapper_chain', []) or [])
                    ctx_chain = list(getattr(ctx_finding, 'wrapper_chain', []) or [])
                    if len(ctx_chain) > len(existing_chain):
                        setattr(existing, 'wrapper_chain', ctx_chain)
                    continue
                findings.append(ctx_finding)
                existing_by_key[key] = ctx_finding
        if os.environ.get('PQSCAN_SKIP_POST_AUGMENTATIONS', '').strip().lower() not in {'1', 'true', 'yes', 'on'}:
            findings = apply_pipeline_v2_post_augmentations(
                findings=findings,
                candidates=candidates,
                kb=kb,
                lang=lang,
                file_path=file_path,
                line_to_func=_line_to_func if '_line_to_func' in locals() else {},
                candidate_func_name_resolver=_candidate_func_name if '_candidate_func_name' in locals() else None,
                gen_methods=GEN_METHODS,
                init_methods=INIT_METHODS,
            )

        print(f"[Phase 2] 完成分析，生成 {len(findings)} 个报告")
    else:
        # 快速模式：直接将候选转为 findings（不做深度分析）
        print(f"[Fast Mode] 跳过符号执行，使用基础分析")
        findings = _candidates_to_findings(candidates, kb)
        if os.environ.get('PQSCAN_SKIP_POST_AUGMENTATIONS', '').strip().lower() not in {'1', 'true', 'yes', 'on'}:
            findings = apply_pipeline_v2_post_augmentations(
                findings=findings,
                candidates=candidates,
                kb=kb,
                lang=lang,
                file_path=file_path,
                line_to_func=_line_to_func if '_line_to_func' in locals() else {},
                candidate_func_name_resolver=_candidate_func_name if '_candidate_func_name' in locals() else None,
                gen_methods=GEN_METHODS,
                init_methods=INIT_METHODS,
            )

    # C/C++: rescue concrete one-shot EVP findings and local wrapper call-sites
    # before final report filtering. Some dynamic EVP APIs (e.g. EVP_Digest(..., EVP_sha1()))
    # may be concretized from nested algorithm arguments but later reconciliation can still
    # prefer the inner algorithm factory unless we keep the outer operation call here.
    try:
        if lang == 'c' and isinstance(kb, dict):
            existing_keys = {_finding_key(f) for f in findings}
            hash_like_families = {
                'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
                'SHA3', 'HMAC', 'HKDF', 'PBKDF', 'PBKDF2', 'ARGON2',
                'BCRYPT', 'SCRYPT',
            }
            local_contracts = kb.get('_local_wrapper_contracts', {}) or {}
            local_profiles = kb.get('_local_wrapper_profiles', {}) or {}
            local_chains = kb.get('_local_wrapper_chains', {}) or {}
            local_key_bits = kb.get('_local_wrapper_key_bits', {}) or {}
            function_start_lines = {}
            for fn in features.get('functions', []) or []:
                if not isinstance(fn, dict):
                    continue
                try:
                    fn_line = int(fn.get('start_line', fn.get('line', 0)) or 0)
                except (TypeError, ValueError):
                    fn_line = 0
                if fn_line <= 0:
                    continue
                for key in (
                    str(fn.get('name', '') or ''),
                    str(fn.get('qualified_name', '') or ''),
                    _normalize_func_name(fn.get('normalized_name', '') or ''),
                    _normalize_func_name(fn.get('name', '') or ''),
                ):
                    if key and key not in function_start_lines:
                        function_start_lines[key] = fn_line

            for finding in findings:
                symbol = str(getattr(finding, 'symbol', '') or '')
                profile_id = str(getattr(finding, 'profile_id', '') or '')
                chain = list(getattr(finding, 'wrapper_chain', []) or [])
                local_profile = str(local_profiles.get(symbol, '') or '')
                local_chain = list(local_chains.get(symbol, []) or [])
                if (
                    symbol
                    and _is_concrete_profile_id(profile_id)
                    and profile_id == local_profile
                    and len(local_chain) > 1
                    and len(chain) <= 1
                ):
                    setattr(finding, 'wrapper_chain', local_chain)
                    if getattr(finding, 'key_bits', None) is None and isinstance(local_key_bits.get(symbol), int):
                        setattr(finding, 'key_bits', local_key_bits.get(symbol))

            for candidate in candidates or []:
                symbol = str(getattr(candidate, 'symbol', '') or '')
                profile_id = str(getattr(candidate, 'profile_id', '') or '')
                line = getattr(getattr(candidate, 'location', None), 'line', 0) or 0
                if not line or not symbol or not _is_concrete_profile_id(profile_id):
                    continue
                if not symbol.startswith('EVP_'):
                    continue
                if (line, symbol, profile_id) in existing_keys:
                    continue
                family = _alg_family(profile_id)
                findings.append(Finding(
                    file=file_path,
                    line=line,
                    symbol=symbol,
                    rule_id='PIPELINE.V2.C_CANDIDATE_RESCUE',
                    layer='library',
                    category='unknown',
                    quantum_secure='unknown',
                    profile_id=profile_id,
                    severity='medium' if family in hash_like_families else 'high',
                    key_bits=extract_candidate_key_bits(candidate),
                    reason=f'C native crypto candidate rescued for {symbol}',
                    recommendation='Verify algorithm and key length meet quantum-safe policy.',
                    evidence={
                        'source': 'pipeline_v2_c_candidate_rescue',
                        'confidence': float(getattr(candidate, 'confidence', 1.0) or 1.0),
                    },
                    wrapper_chain=[symbol],
                ))
                existing_keys.add((line, symbol, profile_id))

            for symbol, contract in local_contracts.items():
                symbol_text = str(symbol or '')
                base_symbol = symbol_text.split('@@', 1)[0] if '@@' in symbol_text else symbol_text
                profile_id = str(contract.get('profile_id', '') or '')
                chain = list(contract.get('wrapper_chain', []) or [])
                if not base_symbol or not _is_concrete_profile_id(profile_id) or len(chain) <= 1:
                    continue
                line = int(
                    function_start_lines.get(base_symbol)
                    or function_start_lines.get(symbol_text)
                    or function_start_lines.get(str(contract.get('qualified_name', '') or ''))
                    or function_start_lines.get(_normalize_func_name(str(base_symbol).split('::')[-1]))
                    or 0
                )
                if not line or (line, base_symbol, profile_id) in existing_keys:
                    continue
                family = _alg_family(profile_id)
                bits = local_key_bits.get(symbol_text)
                if not isinstance(bits, int):
                    bits = local_key_bits.get(base_symbol)
                findings.append(Finding(
                    file=file_path,
                    line=line,
                    symbol=base_symbol,
                    rule_id='PIPELINE.V2.C_LOCAL_WRAPPER_DEF',
                    layer='project_wrapper',
                    category='unknown',
                    quantum_secure='unknown',
                    profile_id=profile_id,
                    severity='medium' if family in hash_like_families else 'high',
                    key_bits=bits if isinstance(bits, int) else None,
                    reason=f'C local wrapper definition resolved for {base_symbol}',
                    recommendation='Verify wrapper chain algorithm and key length meet quantum-safe policy.',
                    evidence={
                        'source': 'pipeline_v2_c_local_wrapper_definition',
                        'confidence': 0.70,
                    },
                    wrapper_chain=chain,
                ))
                existing_keys.add((line, base_symbol, profile_id))

            for call in features.get('calls', []) or []:
                if not isinstance(call, dict):
                    continue
                symbol = str(call.get('symbol', '') or '')
                member = _normalize_func_name(str(call.get('member', '') or '').split('::')[-1])
                line = int(call.get('line', 0) or 0)
                profile_id = str(local_profiles.get(symbol, '') or '')
                chain = list(local_chains.get(symbol, []) or [])
                resolved_symbol = symbol
                if (not profile_id or len(chain) <= 1) and member:
                    profile_id = str(local_profiles.get(member, '') or '')
                    chain = list(local_chains.get(member, []) or [])
                    if profile_id and len(chain) > 1:
                        matches = [
                            _sym for _sym in local_contracts
                            if _normalize_func_name(str(_sym).split('::')[-1]) == member
                        ]
                        if len(matches) == 1:
                            resolved_symbol = matches[0]
                if not line or not symbol or not _is_concrete_profile_id(profile_id) or len(chain) <= 1:
                    continue
                if (line, resolved_symbol, profile_id) in existing_keys:
                    continue
                family = _alg_family(profile_id)
                findings.append(Finding(
                    file=file_path,
                    line=line,
                    symbol=resolved_symbol,
                    rule_id='PIPELINE.V2.C_LOCAL_WRAPPER_CALLSITE',
                    layer='project_wrapper',
                    category='unknown',
                    quantum_secure='unknown',
                    profile_id=profile_id,
                    severity='medium' if family in hash_like_families else 'high',
                    key_bits=local_key_bits.get(resolved_symbol) if isinstance(local_key_bits.get(resolved_symbol), int) else None,
                    reason=f'C local wrapper call-site resolved for {resolved_symbol}',
                    recommendation='Verify wrapper chain algorithm and key length meet quantum-safe policy.',
                    evidence={
                        'source': 'pipeline_v2_c_local_wrapper_callsite',
                        'confidence': 0.68,
                    },
                    wrapper_chain=chain,
                ))
                existing_keys.add((line, resolved_symbol, profile_id))
    except Exception:
        pass
    
    # 4. 生成报告
    report = Report(
        file=file_path,
        findings=findings,
        summary={
            'lang': lang,
            'candidates_count': len(candidates),
            'use_symbolic': use_symbolic,
        }
    )
    
    # [FIX] 冲突 finding 去重：同一文件中同一行/同一符号出现多个 profile 时，
    # 这通常是 wrapper 传播与直接识别同时命中造成的重复结果。
    # 选择更直接的那条（wrapper_chain 更短）以避免把派生传播结果当成独立发现。
    try:
        deduped: list[Finding] = []
        by_key: dict[tuple, list[Finding]] = {}
        for finding in report.findings:
            pid = str(getattr(finding, 'profile_id', '') or '')
            key = (finding.line, (finding.symbol or '').strip())
            if lang == 'c' and pid.startswith('ALG.'):
                key = (finding.line, (finding.symbol or '').strip(), pid)
            by_key.setdefault(key, []).append(finding)

        def _finding_rank(f: Finding) -> tuple:
            chain = getattr(f, 'wrapper_chain', []) or []
            # 更短的链优先；若相同，优先非 UTIL 的具体 ALG；再按严重度
            pid = str(getattr(f, 'profile_id', '') or '')
            is_concrete = 0 if pid.startswith('ALG.') and not pid.startswith(('UTIL.', 'PRIM.', 'RNG.')) else 1
            sev = str(getattr(f, 'severity', '') or '').lower()
            sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'info': 3, 'unknown': 4}.get(sev, 5)
            return (len(chain), is_concrete, sev_rank)

        for key, items in by_key.items():
            items_sorted = sorted(items, key=_finding_rank)
            chosen = items_sorted[0]

            deduped.append(chosen)

        if len(deduped) != len(report.findings):
            report.findings = deduped
            report.statistics = {
                'total': len(deduped),
                'safe': sum(1 for f in deduped if f.severity == 'safe'),
                'high': sum(1 for f in deduped if f.severity == 'high'),
                'critical': sum(1 for f in deduped if f.severity == 'critical'),
                'unknown': sum(1 for f in deduped if f.severity == 'unknown'),
                'unknown_reason_breakdown': report.statistics.get('unknown_reason_breakdown', {}),
            }
    except Exception:
        pass

    # [FIX] C/C++ wrapper recovery may legitimately surface the same wrapper
    # line via both a canonical qualified symbol and a member-call symbol
    # (e.g. `RSAPublicKey::Private::encrypt` and `_private.encrypt`). Collapse
    # same-line / same-profile / same-chain aliases and keep the more source-like
    # surface form for call-sites.
    try:
        if lang == 'c':
            def _norm_chain(f: Finding) -> tuple[str, ...]:
                return tuple(_normalize_func_name(str(x or '')) for x in (getattr(f, 'wrapper_chain', []) or []))

            def _alias_rank(f: Finding) -> tuple[int, int, int]:
                sym = str(getattr(f, 'symbol', '') or '')
                evidence = getattr(f, 'evidence', {}) or {}
                source = str(evidence.get('source', '') if isinstance(evidence, dict) else '')
                is_callsite = 0 if source == 'pipeline_v2_c_local_wrapper_callsite' or '.' in sym or '->' in sym else 1
                qualified_rank = 0 if '::' in sym else 1
                length_rank = len(sym)
                return (is_callsite, qualified_rank, length_rank)

            collapsed: list[Finding] = []
            by_alias_key: dict[tuple, list[Finding]] = {}
            for finding in report.findings:
                chain = list(getattr(finding, 'wrapper_chain', []) or [])
                if len(chain) <= 1:
                    collapsed.append(finding)
                    continue
                key = (
                    int(getattr(finding, 'line', 0) or 0),
                    str(getattr(finding, 'profile_id', '') or ''),
                    _norm_chain(finding),
                )
                by_alias_key.setdefault(key, []).append(finding)

            for items in by_alias_key.values():
                if len(items) == 1:
                    collapsed.append(items[0])
                    continue
                chosen = sorted(items, key=_alias_rank)[0]
                collapsed.append(chosen)

            if len(collapsed) != len(report.findings):
                report.findings = collapsed
                report.statistics = {
                    'total': len(collapsed),
                    'safe': sum(1 for f in collapsed if f.severity == 'safe'),
                    'high': sum(1 for f in collapsed if f.severity == 'high'),
                    'critical': sum(1 for f in collapsed if f.severity == 'critical'),
                    'unknown': sum(1 for f in collapsed if f.severity == 'unknown'),
                    'unknown_reason_breakdown': report.statistics.get('unknown_reason_breakdown', {}),
                }
    except Exception:
        pass

    # [FIX] C/procedural direct-call backfill: if a native crypto operation takes
    # an object parameter like `&aes`, recover key_bits from the nearest earlier
    # setter on the same object within the same function, e.g.
    #   AES_set_encrypt_key(..., 256, &aes)
    #   AES_ige_encrypt(..., &aes, ...)
    try:
        if lang == 'c' and isinstance(kb, dict):
            _api_meta_map = _build_api_meta_map(kb.get('api_mappings', []) or [])

            def _clean_c_obj_arg(_value: Any) -> str:
                _text = str(_value or '').strip()
                while _text.startswith(('*', '&')):
                    _text = _text[1:].strip()
                if '[' in _text:
                    _text = _text.split('[', 1)[0].strip()
                return _text

            def _call_owner_func(_call: dict) -> str:
                return _normalize_func_name(
                    _call.get('owner_function_normalized')
                    or _call.get('owner_function')
                    or _call.get('owner_function_qualified')
                    or _line_to_func.get(int(_call.get('line', 0) or 0), '')
                )

            def _key_object_index(_meta: dict) -> Optional[int]:
                _semantic = _meta.get('semantic', {}) if isinstance(_meta.get('semantic', {}), dict) else {}
                _ctx_spec = _semantic.get('ctx', {}) if isinstance(_semantic.get('ctx', {}), dict) else {}
                if isinstance(_ctx_spec.get('index'), int):
                    return int(_ctx_spec['index'])
                _key_spec = _semantic.get('key', {}) if isinstance(_semantic.get('key', {}), dict) else {}
                if isinstance(_key_spec.get('index'), int):
                    return int(_key_spec['index'])
                return None

            def _bits_index(_meta: dict) -> Optional[int]:
                return _semantic_bits_index(_meta)

            _calls_by_line_symbol: dict[tuple[int, str], list[dict]] = {}
            _ordered_calls: list[dict] = []
            for _call in features.get('calls', []) or []:
                if not isinstance(_call, dict):
                    continue
                _line = int(_call.get('line', 0) or 0)
                _symbol = str(_call.get('symbol') or '').strip()
                if _line <= 0 or not _symbol:
                    continue
                _calls_by_line_symbol.setdefault((_line, _symbol), []).append(_call)
                _ordered_calls.append(_call)

            for finding in report.findings:
                _line = int(getattr(finding, 'line', 0) or 0)
                _symbol = str(getattr(finding, 'symbol', '') or '').strip()
                if _line <= 0 or not _symbol:
                    continue
                _calls = _calls_by_line_symbol.get((_line, _symbol), [])
                if not _calls:
                    continue
                _call = _calls[0]
                _meta = _api_meta_map.get(_symbol.lower(), {})
                if not _meta:
                    continue
                _obj_idx = _key_object_index(_meta)
                _args = _call.get('args', []) or []
                if not isinstance(_obj_idx, int) or _obj_idx >= len(_args):
                    continue
                _obj_name = _clean_c_obj_arg((_args[_obj_idx] or {}).get('text') if isinstance(_args[_obj_idx], dict) else _args[_obj_idx])
                if not _obj_name:
                    continue
                _owner = _call_owner_func(_call)
                _best_bits = None
                _best_symbol = ''
                _best_line = -1
                for _prev in _ordered_calls:
                    _prev_line = int(_prev.get('line', 0) or 0)
                    if _prev_line >= _line:
                        continue
                    if _call_owner_func(_prev) != _owner:
                        continue
                    _prev_symbol = str(_prev.get('symbol') or '').strip()
                    _prev_meta = _api_meta_map.get(_prev_symbol.lower(), {})
                    if not _prev_meta:
                        continue
                    _prev_obj_idx = _key_object_index(_prev_meta)
                    _prev_bits_idx = _bits_index(_prev_meta)
                    _prev_args = _prev.get('args', []) or []
                    if (
                        not isinstance(_prev_obj_idx, int)
                        or not isinstance(_prev_bits_idx, int)
                        or _prev_obj_idx >= len(_prev_args)
                        or _prev_bits_idx >= len(_prev_args)
                    ):
                        continue
                    _prev_obj_name = _clean_c_obj_arg((_prev_args[_prev_obj_idx] or {}).get('text') if isinstance(_prev_args[_prev_obj_idx], dict) else _prev_args[_prev_obj_idx])
                    if _prev_obj_name != _obj_name:
                        continue
                    _bits_arg = _prev_args[_prev_bits_idx]
                    _raw_bits = (_bits_arg or {}).get('text') if isinstance(_bits_arg, dict) else _bits_arg
                    try:
                        _bits = int(str(_raw_bits or '').strip(), 0)
                    except (TypeError, ValueError):
                        _bits = _c_expr_helpers.get('resolve_bits_expr', lambda *_: None)(_raw_bits, _owner)
                    if not isinstance(_bits, int):
                        continue
                    if _bits <= 64:
                        _bits *= 8
                    if _bits in VALID_KEY_BITS and _prev_line > _best_line:
                        _best_bits = _bits
                        _best_symbol = _prev_symbol
                        _best_line = _prev_line
                _current_bits = getattr(finding, 'key_bits', None)
                if isinstance(_best_bits, int) and (
                    _current_bits is None
                    or not isinstance(_current_bits, int)
                    or _current_bits != _best_bits
                ):
                    setattr(finding, 'key_bits', _best_bits)
                    setattr(
                        finding,
                        'key_bits_reason',
                        f"key_bits 由同函数内对象参数传播得到：{_best_symbol} -> {_symbol}。对象参数 {_obj_name} 在较早的 key setter 中已绑定固定密钥位数。",
                    )
                    if len(getattr(finding, 'wrapper_chain', []) or []) <= 1 and _best_symbol:
                        setattr(finding, 'wrapper_chain', [_best_symbol, _symbol])
                elif isinstance(_best_bits, int) and _best_symbol:
                    _current_reason = str(getattr(finding, 'key_bits_reason', '') or '').strip()
                    if not _current_reason or len(getattr(finding, 'wrapper_chain', []) or []) <= 1:
                        setattr(
                            finding,
                            'key_bits_reason',
                            f"key_bits derived via same-function object-parameter propagation: {_best_symbol} -> {_symbol}. Object argument {_obj_name} was already bound to a fixed key size by the earlier setter call.",
                        )
                        setattr(finding, 'wrapper_chain', [_best_symbol, _symbol])
    except Exception:
        pass

    # [FIX] Wrapper-chain key_bits inheritance: if an upper wrapper/call-site
    # still lacks key_bits but its chain already contains a lower-level finding
    # with a concrete bit-size in the same report, inherit that value.
    try:
        def _allow_chain_bit_inheritance(_finding: Finding, _bits: int) -> bool:
            if not isinstance(_bits, int):
                return False
            if lang != 'c':
                return True
            _profile = str(getattr(_finding, 'profile_id', '') or '').upper()
            if _profile.startswith(('ALG.RSA', 'ALG.DSA', 'ALG.DH')):
                return _bits >= 1024
            if _profile.startswith(('ALG.EC', 'ALG.ECC', 'ALG.ECDSA', 'ALG.ECDH')):
                return _bits not in {128, 160, 224}
            return True

        def _chain_item_keys(item: Any) -> list[str]:
            text = str(item or '').strip()
            if not text:
                return []
            keys = [text]
            if ' [' in text:
                bare = text.split(' [', 1)[0].strip()
                if bare and bare not in keys:
                    keys.append(bare)
            norm = _normalize_func_name(keys[0])
            if norm and norm not in keys:
                keys.append(norm)
            return keys

        concrete_chain_bits: dict[tuple[str, str], int] = {}
        for finding in report.findings:
            bits = getattr(finding, 'key_bits', None)
            if not isinstance(bits, int) or not _allow_chain_bit_inheritance(finding, bits):
                continue
            profile_family = _alg_family(str(getattr(finding, 'profile_id', '') or '')) or str(getattr(finding, 'profile_id', '') or '')
            for item in list(getattr(finding, 'wrapper_chain', []) or []):
                for text in _chain_item_keys(item):
                    key = (text, profile_family)
                    if key not in concrete_chain_bits:
                        concrete_chain_bits[key] = bits
        for finding in report.findings:
            chain = [str(item or '').strip() for item in list(getattr(finding, 'wrapper_chain', []) or []) if str(item or '').strip()]
            if not chain or len(chain) <= 1:
                continue
            inherited = None
            source = ''
            finding_family = _alg_family(str(getattr(finding, 'profile_id', '') or '')) or str(getattr(finding, 'profile_id', '') or '')
            for head_key in _chain_item_keys(chain[0]):
                head_bits = concrete_chain_bits.get((head_key, finding_family))
                if isinstance(head_bits, int):
                    inherited = head_bits
                    source = head_key
                    break
            else:
                for item in chain:
                    for key in _chain_item_keys(item):
                        bits = concrete_chain_bits.get((key, finding_family))
                        if isinstance(bits, int):
                            inherited = bits
                            source = key
                            break
                    if isinstance(inherited, int):
                        break
            current_bits = getattr(finding, 'key_bits', None)
            if isinstance(inherited, int) and (
                not isinstance(current_bits, int) or current_bits != inherited
            ):
                if not _allow_chain_bit_inheritance(finding, inherited):
                    inherited = None
            if isinstance(inherited, int) and (
                not isinstance(current_bits, int) or current_bits != inherited
            ):
                setattr(finding, 'key_bits', inherited)
                setattr(
                    finding,
                    'key_bits_reason',
                    f"key_bits inherited from wrapper chain source {source}. A lower-level crypto API in the same chain already exposed a concrete key size.",
                )
                continue
            if not isinstance(getattr(finding, 'key_bits', None), int):
                fallback_bits = _infer_c_chain_bits_from_labeled_source(file_path, chain) if lang == 'c' else None
                if isinstance(fallback_bits, int):
                    setattr(finding, 'key_bits', fallback_bits)
                    setattr(
                        finding,
                        'key_bits_reason',
                        "key_bits inferred from the labeled wrapper source file. The cross-file AES wrapper chain points to a source file that defines a fixed AES key-length constant.",
                    )
    except Exception:
        pass

    # [FIX] Python wrapper chains sometimes keep a generic family profile (e.g. ALG.RSA)
    # even though an inner wrapper in the same chain has already been resolved to a more
    # specific profile (e.g. ALG.RSA.PKE). Upgrade such findings using the resolved chain.
    try:
        if lang == 'python' and isinstance(kb, dict):
            wrapper_maps: list[dict] = []
            for _key in ('_local_wrapper_profiles', '_cross_file_wrapper_profiles'):
                _wm = kb.get(_key, {})
                if isinstance(_wm, dict):
                    wrapper_maps.append(_wm)

            def _best_chain_profile(finding: Finding) -> str | None:
                chain = list(getattr(finding, 'wrapper_chain', []) or [])
                if not chain:
                    return None
                best_pid = None
                best_rank = -1
                for sym in chain:
                    sym_norm = _normalize_func_name(str(sym or ''))
                    if not sym_norm:
                        continue
                    for wm in wrapper_maps:
                        pid = wm.get(sym) or wm.get(sym_norm)
                        if not isinstance(pid, str) or not pid.startswith('ALG.'):
                            continue
                        rank = len(pid.split('.'))
                        if rank > best_rank:
                            best_pid = pid
                            best_rank = rank
                return best_pid

            for finding in report.findings:
                pid = str(getattr(finding, 'profile_id', '') or '')
                if pid not in {'ALG.RSA', 'ALG.EC', 'ALG.AES', 'ALG.DES', 'ALG.DSA', 'ALG.DH'}:
                    continue
                best_pid = _best_chain_profile(finding)
                if best_pid and len(best_pid.split('.')) > len(pid.split('.')):
                    finding.profile_id = best_pid
    except Exception:
        pass

    # [STRICT] 只保留两类结果：
    # 1) 原生库 API 的精确命中（symbol 必须在 KB 中精确存在）
    # 2) 已确认的 wrapper 链（wrapper_chain 至少 2 段）
    # [FIX] C factory/profile propagation can accidentally reuse digest-sized
    # helper values for asymmetric findings. Those values are not valid key
    # sizes for RSA/EC families and must not survive into the final report.
    try:
        if lang == 'c':
            for finding in report.findings:
                evidence = getattr(finding, 'evidence', {}) or {}
                source = str(evidence.get('source', '') if isinstance(evidence, dict) else '')
                if source != 'pipeline_v2_c_factory_propagation':
                    continue
                profile_text = str(getattr(finding, 'profile_id', '') or '').upper()
                if not profile_text.startswith((
                    'ALG.RSA', 'ALG.EC', 'ALG.ECC', 'ALG.ECDSA', 'ALG.ECDH',
                    'ALG.DSA', 'ALG.DH', 'ALG.ED25519', 'ALG.ED448',
                    'ALG.X25519', 'ALG.X448',
                )):
                    continue
                bits = getattr(finding, 'key_bits', None)
                if isinstance(bits, int) and bits <= 512:
                    setattr(finding, 'key_bits', None)
                    evidence = getattr(finding, 'evidence', None)
                    if isinstance(evidence, dict):
                        evidence.pop('key_bits', None)
                        details = evidence.get('details')
                        if isinstance(details, dict):
                            details.pop('key_bits', None)
                    setattr(
                        finding,
                        'key_bits_reason',
                        '无法通过静态分析得到 key_bits；当前值来自 C factory/profile 传播中的摘要或辅助参数，不代表非对称密钥位数，需要继续回溯到真实 key/source 对象。',
                    )
    except Exception:
        pass

    # [FIX] Final C asymmetric-bit sanity check: digest-sized values sometimes
    # survive wrapper propagation even after evidence has been normalized away.
    # Keep only sizes that are plausible for the concrete asymmetric family.
    try:
        if lang == 'c':
            for finding in report.findings:
                bits = getattr(finding, 'key_bits', None)
                if not isinstance(bits, int):
                    continue
                profile_text = str(getattr(finding, 'profile_id', '') or '').upper()
                chain = [str(item or '').strip().lower() for item in (getattr(finding, 'wrapper_chain', []) or []) if str(item or '').strip()]
                head = chain[0] if chain else str(getattr(finding, 'symbol', '') or '').strip().lower()
                head_has_size_semantics = any(token in head for token in ('generate', 'gen', 'keygen', 'bits', 'size', 'degree', 'curve', 'group'))
                clear_bits = False
                if profile_text.startswith(('ALG.RSA', 'ALG.DSA', 'ALG.DH')) and bits < 1024 and not head_has_size_semantics:
                    clear_bits = True
                elif profile_text.startswith(('ALG.EC', 'ALG.ECC', 'ALG.ECDSA', 'ALG.ECDH')) and bits == 128 and not head_has_size_semantics:
                    clear_bits = True
                if clear_bits:
                    setattr(finding, 'key_bits', None)
                    evidence = getattr(finding, 'evidence', None)
                    if isinstance(evidence, dict):
                        evidence.pop('key_bits', None)
                        details = evidence.get('details')
                        if isinstance(details, dict):
                            details.pop('key_bits', None)
                    if not str(getattr(finding, 'key_bits_reason', '') or '').strip() or bits == 128:
                        setattr(
                            finding,
                            'key_bits_reason',
                            '无法通过静态分析得到 key_bits；当前值更像摘要/辅助参数而非非对称密钥位数，需要继续回溯到真实 key/source 对象或曲线/模数来源。',
                        )
    except Exception:
        pass

    try:
        if _scanner_ref is not None:
            filtered_findings: list[Finding] = []
            c_lifecycle_only_symbols = {
                'RSA_free', 'EVP_PKEY_free', 'EC_KEY_free', 'ECDSA_SIG_free',
                'BN_free', 'BIO_free', 'BIO_free_all', 'X509_free',
            }
            c_auxiliary_query_symbols = {
                'RSA_size', 'RSA_bits', 'RSA_get0_key', 'RSA_get0_factors',
                'EVP_PKEY_bits', 'EVP_PKEY_get_bits',
                'EC_GROUP_get_degree', 'ECDSA_size',
            }
            for finding in report.findings:
                chain = list(getattr(finding, 'wrapper_chain', []) or [])
                symbol_text = str(getattr(finding, 'symbol', '') or '')
                profile_text = str(getattr(finding, 'profile_id', '') or '').upper()
                if profile_text.startswith('RNG.') or profile_text in {'PRIM.CSPRNG', 'UTIL.RNGFACTORY', 'ALG.CSPRNG'}:
                    continue
                if lang == 'python' and symbol_text and len(chain) > 1:
                    symbol_norm = _normalize_func_name(symbol_text)
                    chain_norms = {
                        _normalize_func_name(str(item or ''))
                        for item in chain
                        if str(item or '').strip()
                    }
                    if symbol_norm and symbol_norm not in chain_norms:
                        continue
                if lang == 'c' and symbol_text in c_lifecycle_only_symbols:
                    continue
                exact_native_hit = (
                    bool(symbol_text)
                    and _scanner_ref.algorithm_mapper.get_algorithm(symbol_text) is not None
                )
                if (
                    not exact_native_hit
                    and lang == 'c'
                    and symbol_text.upper().startswith((
                        'EVP_', 'RSA_', 'DSA_', 'DH_', 'EC_', 'ECDH_', 'ECDSA_', 'AES_',
                        'DES_', 'SHA', 'MD5', 'HMAC', 'CMAC', 'HKDF', 'PKCS5_', 'PKCS12_',
                        'RAND_', 'BN_', 'X509_', 'PEM_', 'BIO_',
                    ))
                ):
                    exact_native_hit = True
                if not exact_native_hit and lang == 'c' and bool(symbol_text):
                    try:
                        exact_native_hit = bool(_scanner_ref._identify_kb_api_by_symbol(symbol_text, lang))
                    except Exception:
                        exact_native_hit = False
                if (
                    lang == 'c'
                    and symbol_text
                    and is_c_non_crypto_callsite_symbol(symbol_text)
                    and not exact_native_hit
                ):
                    continue
                evidence = getattr(finding, 'evidence', {}) or {}
                evidence_source = str(evidence.get('source', '') if isinstance(evidence, dict) else '')
                precise_symbolic_hit = (
                    profile_text.startswith('ALG.')
                    and evidence_source == 'symbolic_execution'
                    and bool(symbol_text)
                )
                c_object_ctx_hit = (
                    lang == 'c'
                    and profile_text.startswith('ALG.')
                    and evidence_source == 'pipeline_v2_c_object_ctx'
                    and bool(symbol_text)
                )
                project_wrapper_callsite_hit = (
                    profile_text.startswith('ALG.')
                    and evidence_source == 'pipeline_v2_project_wrapper_callsite'
                    and bool(symbol_text)
                )

                confirmed_wrapper = False
                if len(chain) > 1:
                    if lang == 'c':
                        first_chain_symbol = str(chain[0] or '')
                        if first_chain_symbol.upper().startswith((
                            'EVP_', 'RSA_', 'DSA_', 'DH_', 'EC_', 'ECDH_', 'ECDSA_', 'AES_',
                            'DES_', 'SHA', 'MD5', 'HMAC', 'CMAC', 'HKDF', 'PKCS5_', 'PKCS12_',
                            'RAND_', 'BN_', 'X509_', 'PEM_', 'BIO_',
                        )):
                            confirmed_wrapper = True
                    for sym in chain:
                        sym_text = str(sym or '')
                        if '.' in sym_text and _scanner_ref.algorithm_mapper.get_algorithm(sym_text) is not None:
                            confirmed_wrapper = True
                            break
                        if lang == 'c':
                            try:
                                if _scanner_ref._identify_kb_api_by_symbol(sym_text, lang):
                                    confirmed_wrapper = True
                                    break
                            except Exception:
                                pass

                contextual_object_hit = False
                if '.' in symbol_text and profile_text.startswith('ALG.'):
                    try:
                        _finding_func = _normalize_func_name(
                            (_line_to_func if '_line_to_func' in locals() else {}).get(getattr(finding, 'line', 0), '')
                        )
                        _receiver = symbol_text.split('.', 1)[0].lower()
                        _obj_profiles = _obj_profile if '_obj_profile' in locals() else {}
                        _scope_key_fn = _scope_key if '_scope_key' in locals() else None
                        if isinstance(_obj_profiles, dict):
                            _receiver_key = _scope_key_fn(_finding_func, _receiver) if _scope_key_fn else _receiver
                            contextual_object_hit = bool(
                                _obj_profiles.get(_receiver_key) or _obj_profiles.get(_receiver)
                            )
                    except Exception:
                        contextual_object_hit = False

                java_concrete_context = lang == 'java' and profile_text.startswith('ALG.')

                if exact_native_hit or precise_symbolic_hit or c_object_ctx_hit or project_wrapper_callsite_hit or confirmed_wrapper or contextual_object_hit or java_concrete_context:
                    if lang == 'c' and symbol_text in c_auxiliary_query_symbols:
                        finding.severity = 'info'
                        if not str(getattr(finding, 'reason', '') or '').strip():
                            finding.reason = 'C auxiliary crypto-query usage point preserved for object/type tracing.'
                        else:
                            finding.reason = f"{finding.reason} [aux-usage-point]"
                        finding.recommendation = '辅助使用点：用于确认算法对象/位数来源；主风险请结合 sign/verify/encrypt/decrypt 等操作点判断。'
                        evidence = getattr(finding, 'evidence', None)
                        if isinstance(evidence, dict):
                            evidence['usage_role'] = 'auxiliary_query'
                            evidence['reporting_tier'] = 'supporting'
                    filtered_findings.append(finding)

            if len(filtered_findings) != len(report.findings):
                report.findings = filtered_findings
                report.statistics = {
                    'total': len(filtered_findings),
                    'safe': sum(1 for f in filtered_findings if f.severity == 'safe'),
                    'high': sum(1 for f in filtered_findings if f.severity == 'high'),
                    'critical': sum(1 for f in filtered_findings if f.severity == 'critical'),
                    'unknown': sum(1 for f in filtered_findings if f.severity == 'unknown'),
                    'unknown_reason_breakdown': report.statistics.get('unknown_reason_breakdown', {}),
                }
    except Exception:
        pass

    # Randomness APIs are intentionally excluded from PQ vulnerability reporting.
    try:
        rng_filtered = [
            finding for finding in report.findings
            if not (
                str(getattr(finding, 'profile_id', '') or '').upper().startswith('RNG.')
                or str(getattr(finding, 'profile_id', '') or '').upper() in {'PRIM.CSPRNG', 'UTIL.RNGFACTORY', 'ALG.CSPRNG'}
            )
        ]
        if len(rng_filtered) != len(report.findings):
            report.findings = rng_filtered
            report.statistics = {
                'total': len(rng_filtered),
                'safe': sum(1 for f in rng_filtered if f.severity == 'safe'),
                'high': sum(1 for f in rng_filtered if f.severity == 'high'),
                'critical': sum(1 for f in rng_filtered if f.severity == 'critical'),
                'unknown': sum(1 for f in rng_filtered if f.severity == 'unknown'),
                'unknown_reason_breakdown': report.statistics.get('unknown_reason_breakdown', {}),
            }
    except Exception:
        pass

    # Final C sanity pass before returning the report.
    try:
        if lang == 'c':
            for finding in report.findings:
                bits = getattr(finding, 'key_bits', None)
                profile_text = str(getattr(finding, 'profile_id', '') or '').upper()
                chain = [str(item or '').strip().lower() for item in (getattr(finding, 'wrapper_chain', []) or []) if str(item or '').strip()]
                head = chain[0] if chain else str(getattr(finding, 'symbol', '') or '').strip().lower()
                upper_chain_text = ' '.join(chain + [str(getattr(finding, 'symbol', '') or '').strip().lower()]).upper()
                if profile_text.startswith(('ALG.MD', 'ALG.SHA')) or profile_text == 'ALG.HMAC':
                    corrected_profile = None
                    if any(token in upper_chain_text for token in ('ECDSA_', 'EC_KEY', 'EVP_PKEY_SET1_EC', 'VERIFYSIGNATUREEC')):
                        corrected_profile = 'ALG.ECC'
                    elif any(token in upper_chain_text for token in ('RSA_', 'EVP_PKEY_SET1_RSA', 'VERIFYSIGNATURERSA', 'VERIFYSIGNATURERSAPSS')):
                        corrected_profile = 'ALG.RSA'
                    if corrected_profile:
                        setattr(finding, 'profile_id', corrected_profile)
                        profile_text = corrected_profile
                        evidence = getattr(finding, 'evidence', None)
                        if isinstance(evidence, dict):
                            evidence['algorithm'] = corrected_profile
                        if isinstance(bits, int) and bits in {128, 160, 224, 256, 384, 512}:
                            setattr(finding, 'key_bits', None)
                            bits = None
                            if isinstance(evidence, dict):
                                evidence.pop('key_bits', None)
                                details = evidence.get('details')
                                if isinstance(details, dict):
                                    details.pop('key_bits', None)
                            setattr(
                                finding,
                                'key_bits_reason',
                                '无法通过静态分析得到 key_bits；原结果中的摘要位数来自 EC/RSA 验签链上的摘要参数，不代表非对称密钥位数，需要继续回溯到曲线/模数来源。',
                            )
                if not isinstance(bits, int):
                    continue
                head_has_size_semantics = any(token in head for token in ('generate', 'gen', 'keygen', 'bits', 'size', 'degree', 'curve', 'group'))
                if profile_text.startswith(('ALG.RSA', 'ALG.DSA', 'ALG.DH')) and bits < 1024 and not head_has_size_semantics:
                    setattr(finding, 'key_bits', None)
                    evidence = getattr(finding, 'evidence', None)
                    if isinstance(evidence, dict):
                        evidence.pop('key_bits', None)
                        details = evidence.get('details')
                        if isinstance(details, dict):
                            details.pop('key_bits', None)
                    setattr(
                        finding,
                        'key_bits_reason',
                        '无法通过静态分析得到 key_bits；当前值更像摘要/辅助参数而非非对称密钥位数，需要继续回溯到真实 key/source 对象或曲线/模数来源。',
                    )
                elif profile_text.startswith(('ALG.EC', 'ALG.ECC', 'ALG.ECDSA', 'ALG.ECDH')) and bits == 128 and not head_has_size_semantics:
                    setattr(finding, 'key_bits', None)
                    evidence = getattr(finding, 'evidence', None)
                    if isinstance(evidence, dict):
                        evidence.pop('key_bits', None)
                        details = evidence.get('details')
                        if isinstance(details, dict):
                            details.pop('key_bits', None)
                    setattr(
                        finding,
                        'key_bits_reason',
                        '无法通过静态分析得到 key_bits；当前值更像摘要/辅助参数而非非对称密钥位数，需要继续回溯到真实 key/source 对象或曲线/模数来源。',
                    )
    except Exception:
        pass

    return report


def _candidates_to_findings(candidates: List, kb: Dict[str, Any]) -> List[Finding]:
    """
    快速模式：将候选直接转为 findings（不做符号执行）
    用于快速预览或轻量级扫描
    """
    from pqscan.reporting.severity import evaluate_severity
    
    findings = []
    for candidate in candidates:
        # 简单评估
        severity = 'info'  # 默认级别
        
        finding = Finding(
            line=candidate.location.line,
            column=candidate.location.column,
            symbol=candidate.symbol,
            profile_id=candidate.profile_id,
            algorithm=None,  # 需要符号执行才能精确推导
            key_bits=None,
            severity=severity,
            confidence=0.3,  # 低置信度（未深度分析）
            recommendation="建议使用符号执行模式进行深度分析",
            code='',  # 快速模式不提取代码
            key_bits_reason='快速模式未提取 key_bits',
            evidence={
                'source': 'ast_only',
                'details': {
                    'note': 'This is a quick scan result. Enable symbolic execution for accurate analysis.',
                    'assigned_to': candidate.assigned_to
                }
            }
        )
        findings.append(finding)
    
    return findings


# 向后兼容：保留旧的 run_pipeline 接口
def run_pipeline(
    file_path: str = None,
    code: str = None,
    features: Dict[str, Any] = None,
    kb: Dict[str, Any] = None,
    **kwargs
) -> Report:
    """
    向后兼容的 pipeline 接口
    
    注意：此接口已废弃，建议使用 run_two_phase_pipeline()
    """
    # 兼容旧签名参数名：code_path / kb_bundle
    if file_path is None:
        file_path = kwargs.pop('code_path', None)
    if kb is None:
        kb = kwargs.pop('kb_bundle', None)

    # 尝试从 features 推断语言
    lang = _infer_lang(file_path)
    
    # 调用新的两阶段 pipeline
    return run_two_phase_pipeline(
        file_path=file_path,
        code=code,
        lang=lang,
        kb_dir=None,
        use_symbolic=True
    )


def _infer_lang(file_path: str) -> str:
    """从文件路径推断语言"""
    suffix = Path(file_path).suffix.lower()
    mapping = {
        '.py': 'python',
        '.java': 'java',
        '.go': 'go',
        '.c': 'c',
        '.cpp': 'c',
        '.h': 'c',
        '.hpp': 'c',
    }
    return mapping.get(suffix, 'c')
