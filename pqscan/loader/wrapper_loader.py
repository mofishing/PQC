#!/usr/bin/env python3
"""
封装契约加载器（Wrapper Contract Loader）

功能：
1. 加载手工预定义的封装契约（kb/wrappers/*.json）
2. 加载自动派生的封装契约（kb/derived/*.json）
3. 转换为与 apis 同构的格式
4. 合并到 api_mappings 中

架构：
- 封装规则 = apis 规则 + derived_meta
- 复用现有的匹配、参数抽取、ctx 追踪流程
- 优先级：direct APIs > wrapper contracts > symbolic execution
"""

import json
import pathlib
from typing import Dict, Any, List, Optional
import re

from pqscan.loader.utils import strip_json_comments


class WrapperContractLoader:
    """封装契约加载器"""
    
    def __init__(self, kb_dir: pathlib.Path, verbose: bool = False):
        """
        初始化加载器
        
        Args:
            kb_dir: KB 根目录
            verbose: 是否输出详细信息
        """
        self.kb_dir = pathlib.Path(kb_dir)
        self.verbose = verbose
        
        # 封装契约目录
        self.wrappers_dir = self.kb_dir / "wrappers"
        self.derived_dir = self.kb_dir / "derived"
    
    def load_wrappers(self, language: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        加载封装契约
        
        Args:
            language: 语言过滤（c/cpp/java/python/go/rust）
        
        Returns:
            封装契约列表（已转换为 apis 同构格式）
        """
        wrappers = []
        
        # 加载手工预定义的契约
        manual_wrappers = self._load_from_dir(self.wrappers_dir, language, source="manual")
        wrappers.extend(manual_wrappers)
        
        # 加载自动派生的契约
        auto_wrappers = self._load_from_dir(self.derived_dir, language, source="auto")
        wrappers.extend(auto_wrappers)
        
        if self.verbose:
            print(f"[WrapperContractLoader] 加载了 {len(manual_wrappers)} 个手工契约")
            print(f"[WrapperContractLoader] 加载了 {len(auto_wrappers)} 个自动派生契约")
            print(f"[WrapperContractLoader] 总计: {len(wrappers)} 个封装契约")
        
        return wrappers
    
    def _load_from_dir(
        self, 
        dir_path: pathlib.Path, 
        language: Optional[str],
        source: str
    ) -> List[Dict[str, Any]]:
        """
        从目录加载契约
        
        Args:
            dir_path: 目录路径
            language: 语言过滤
            source: 来源标记（manual/auto）
        
        Returns:
            契约列表
        """
        if not dir_path.exists():
            if self.verbose:
                print(f"[WrapperContractLoader] 目录不存在: {dir_path}")
            return []
        
        wrappers = []
        
        # 如果指定了语言，只加载该语言的文件
        if language:
            lang_dir = dir_path / language
            if lang_dir.exists():
                wrappers.extend(self._load_json_files(lang_dir, source))
        else:
            # 加载所有语言
            for lang_dir in dir_path.iterdir():
                if lang_dir.is_dir():
                    wrappers.extend(self._load_json_files(lang_dir, source))
        
        return wrappers
    
    def _load_json_files(self, dir_path: pathlib.Path, source: str) -> List[Dict[str, Any]]:
        """
        从目录加载所有 JSON 文件
        
        Args:
            dir_path: 目录路径
            source: 来源标记
        
        Returns:
            契约列表
        """
        wrappers = []
        
        for json_file in dir_path.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # 移除注释
                    content = strip_json_comments(content)
                    data = json.loads(content)
                
                # 处理 wrappers 数组
                if "wrappers" in data and isinstance(data["wrappers"], list):
                    for wrapper in data["wrappers"]:
                        # 确保 derived_meta.source 正确
                        if "derived_meta" not in wrapper:
                            wrapper["derived_meta"] = {}
                        wrapper["derived_meta"]["source"] = source
                        
                        # 转换为 apis 同构格式
                        api_entry = self._convert_to_api_format(wrapper)
                        wrappers.append(api_entry)
                
                if self.verbose:
                    print(f"[WrapperContractLoader] 加载: {json_file.name} ({len(data.get('wrappers', []))} 个契约)")
            
            except Exception as e:
                print(f"[WrapperContractLoader] 错误: 无法加载 {json_file}: {e}")
        
        return wrappers
    
    def _convert_to_api_format(self, wrapper: Dict[str, Any]) -> Dict[str, Any]:
        """
        将封装契约转换为 apis 同构格式
        
        封装契约字段：
        - api_id, language, library, function, func_params
        - semantic (profile_id, operation, key_bits, ...)
        - derived_meta (source, wraps, infer_depth, confidence, ...)
        
        APIs 格式字段：
        - api, symbols, language, library
        - semantic (profile_id, operation, key_bits, ...)
        - _wrapper_meta (封装特有信息)
        
        Args:
            wrapper: 封装契约
        
        Returns:
            APIs 同构格式的条目
        """
        # 基础字段映射
        api_entry = {
            "api": wrapper.get("function", ""),
            "symbols": [wrapper.get("function", "")],
            "language": wrapper.get("language", ""),
            "library": wrapper.get("library", ""),
            "semantic": wrapper.get("semantic", {}),
        }
        
        # 如果有 func_params，添加到 semantic
        if "func_params" in wrapper:
            api_entry["func_params"] = wrapper["func_params"]
        
        # 如果有 imports，添加
        if "imports" in wrapper:
            api_entry["imports"] = wrapper["imports"]
        
        # 将 derived_meta 重命名为 _wrapper_meta（避免与 apis 字段冲突）
        if "derived_meta" in wrapper:
            api_entry["_wrapper_meta"] = wrapper["derived_meta"]
            
            # 标记这是一个封装契约
            api_entry["_is_wrapper"] = True
            
            # 添加置信度（用于优先级排序）
            confidence = wrapper["derived_meta"].get("confidence", "probable")
            api_entry["_wrapper_confidence"] = confidence
        
        # 如果有 api_id，保留（用于调试）
        if "api_id" in wrapper:
            api_entry["_wrapper_api_id"] = wrapper["api_id"]
        
        return api_entry
    
    def merge_with_api_mappings(
        self,
        api_mappings: List[Dict[str, Any]],
        wrappers: List[Dict[str, Any]],
        priority: str = "api_first"
    ) -> List[Dict[str, Any]]:
        """
        合并封装契约到 api_mappings
        
        Args:
            api_mappings: 原始 API 映射列表
            wrappers: 封装契约列表
            priority: 优先级策略
                - "api_first": APIs 优先（默认）
                - "wrapper_first": 封装契约优先
                - "both": 两者都保留
        
        Returns:
            合并后的 API 映射列表
        """
        if priority == "both":
            # 简单合并
            return api_mappings + wrappers
        
        # 构建 API 名称索引
        api_names = set()
        for entry in api_mappings:
            api_name = entry.get("api", "")
            if api_name:
                api_names.add(api_name)
        
        # 根据优先级合并
        merged = list(api_mappings)  # 复制原列表
        
        for wrapper in wrappers:
            api_name = wrapper.get("api", "")
            
            if priority == "api_first":
                # API 优先：只添加不冲突的封装契约
                if api_name not in api_names:
                    merged.append(wrapper)
            
            elif priority == "wrapper_first":
                # 封装契约优先：替换冲突的 API
                if api_name in api_names:
                    # 移除原 API
                    merged = [e for e in merged if e.get("api") != api_name]
                merged.append(wrapper)
        
        if self.verbose:
            print(f"[WrapperContractLoader] 合并策略: {priority}")
            print(f"[WrapperContractLoader] 原 API 数量: {len(api_mappings)}")
            print(f"[WrapperContractLoader] 封装契约数量: {len(wrappers)}")
            print(f"[WrapperContractLoader] 合并后数量: {len(merged)}")
        
        return merged


def load_with_wrappers(
    kb_dir: pathlib.Path,
    language: str = "c",
    priority: str = "api_first",
    verbose: bool = False
) -> Dict[str, Any]:
    """
    加载 KB 并包含封装契约
    
    这是一个便利函数，集成了 loader_v2 和 WrapperContractLoader
    
    Args:
        kb_dir: KB 根目录
        language: 语言
        priority: 合并优先级（api_first/wrapper_first/both）
        verbose: 是否输出详细信息
    
    Returns:
        完整的 KB 数据（包含封装契约）
    """
    from pqscan.loader.loader_v2 import load_kb_v2
    
    # 1. 加载标准 KB
    kb = load_kb_v2(kb_dir, language)
    
    # 2. 加载封装契约
    loader = WrapperContractLoader(kb_dir, verbose=verbose)
    wrappers = loader.load_wrappers(language)
    
    # 3. 合并
    merged_mappings = loader.merge_with_api_mappings(
        kb["api_mappings"],
        wrappers,
        priority=priority
    )
    
    # 4. 更新 KB
    kb["api_mappings"] = merged_mappings
    kb["wrapper_contracts"] = wrappers  # 保留原始契约列表（用于调试）
    kb["wrapper_count"] = len(wrappers)
    
    return kb


def test_wrapper_loader():
    """测试封装契约加载器"""
    print("=" * 60)
    print("封装契约加载器测试")
    print("=" * 60)
    
    # 查找 KB 目录
    kb_dir = pathlib.Path(__file__).parent.parent / "kb"
    
    if not kb_dir.exists():
        print(f"错误: KB 目录不存在: {kb_dir}")
        return
    
    # 测试 1: 加载封装契约
    print("\n[测试 1] 加载封装契约")
    loader = WrapperContractLoader(kb_dir, verbose=True)
    wrappers = loader.load_wrappers(language="c")
    
    print(f"\n加载了 {len(wrappers)} 个封装契约")
    
    if wrappers:
        print("\n前 3 个契约:")
        for i, wrapper in enumerate(wrappers[:3], 1):
            print(f"\n{i}. {wrapper.get('api', 'N/A')}")
            print(f"   Language: {wrapper.get('language', 'N/A')}")
            print(f"   Library: {wrapper.get('library', 'N/A')}")
            if "_wrapper_meta" in wrapper:
                meta = wrapper["_wrapper_meta"]
                print(f"   Source: {meta.get('source', 'N/A')}")
                print(f"   Wraps: {meta.get('wraps', [])}")
                print(f"   Confidence: {meta.get('confidence', 'N/A')}")
    
    # 测试 2: 集成到 loader_v2
    print("\n" + "=" * 60)
    print("[测试 2] 集成到 loader_v2")
    print("=" * 60)
    
    kb = load_with_wrappers(kb_dir, language="c", priority="api_first", verbose=True)
    
    print(f"\nKB 统计:")
    print(f"  API mappings: {len(kb['api_mappings'])}")
    print(f"  Wrapper contracts: {kb['wrapper_count']}")
    print(f"  Common profiles: {len(kb.get('common_profiles', {}).get('rules', []))}")
    print(f"  Merged rules: {len(kb.get('merged_rules', []))}")
    
    # 测试 3: 检查封装契约是否正确转换
    print("\n" + "=" * 60)
    print("[测试 3] 检查封装契约格式")
    print("=" * 60)
    
    wrapper_entries = [e for e in kb["api_mappings"] if e.get("_is_wrapper")]
    print(f"\n找到 {len(wrapper_entries)} 个封装契约条目")
    
    if wrapper_entries:
        print("\n示例封装契约条目:")
        entry = wrapper_entries[0]
        print(json.dumps(entry, indent=2, ensure_ascii=False))
    
    print("\n" + "=" * 60)
    print("✓ 测试完成")
    print("=" * 60)


if __name__ == '__main__':
    test_wrapper_loader()
