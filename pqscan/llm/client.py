#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   client
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/19 10:48    1.0         LLMClient
"""

# pqscan/llm/client.py
from typing import Optional, Dict, Any
import json
from .router import chat_completion, LLMRouteError
from .cache import DiskCache
from .schema import validate_classification

class LLMConfig:
    def __init__(self, provider: str = "openai", model: str = "gpt-4o-mini",
                 temperature: float = 0.1, timeout: int = 45, cache_ttl: int = 86400, extra: Optional[Dict[str,Any]] = None):
        """
        provider:
          - "openai"/"azure_openai"/"ollama": 真调用
          - "mock": 直接返回 mock 结果,用于离线/测试
          - "off"/"disabled": 关闭 LLM,返回 None，由上层启发式兜底
        extra:
          - {"mock_classification": {...}, "mock_extract": {...}, ...}
        """
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.extra = extra or {}

class LLMClient:
    def __init__(self, config: Optional[LLMConfig] = None):
        self.cfg = config or LLMConfig()
        self.cache = DiskCache(ttl_seconds=self.cfg.cache_ttl)

    def _strict_json(self, text: str) -> Optional[Dict[str,Any]]:
        s = text.find("{"); e = text.rfind("}")
        if 0 <= s < e:
            try: return json.loads(text[s:e+1])
            except Exception: return None
        return None

    def _ask(self, sys: str, user: str) -> Optional[Dict[str,Any]]:
        # mock / disabled 直接短路
        prov = (self.cfg.provider or "").lower()
        if prov in ("off", "disabled"):
            return None
        if prov == "mock":
            # 优先返回 mock_classification / mock_extract，若没有则返回空字典以便上层判断
            # 由调用方法（classify_crypto / extract_params）各自决定取哪个键
            return {}  # 实际取值在 classify_crypto/extract_params 里完成

        cached = self.cache.get(self.cfg.provider, self.cfg.model, sys, user)
        if cached is not None: return cached
        try:
            out = chat_completion(
                provider=self.cfg.provider, model=self.cfg.model,
                messages=[{"role":"system","content": sys}, {"role":"user","content": user}],
                temperature=self.cfg.temperature, timeout=self.cfg.timeout, extra=self.cfg.extra
            )
            js = self._strict_json(out)
            if js is not None:
                self.cache.put(self.cfg.provider, self.cfg.model, sys, user, js)
            return js
        except LLMRouteError:
            return None

    def classify_crypto(self, system_prompt: str, user_prompt: str) -> Optional[Dict[str, Any]]:
        # mock 支持
        if (self.cfg.provider or "").lower() == "mock":
            mock = self.cfg.extra.get("mock_classification")
            return mock.copy() if isinstance(mock, dict) else None

        js = self._ask(system_prompt, user_prompt)
        if not js:
            return None
        ok, reason = validate_classification(js)
        return js if ok else None

    def extract_params(self, system_prompt: str, user_prompt: str) -> Optional[Dict[str, Any]]:
        """
        返回附加结构（例如：mode/padding/nonce/iv长度/常量列表/是否自带抗量子注释等）
        Schema 留给 prompts.json 指定（非强校验）。
        """
        # mock 支持
        if (self.cfg.provider or "").lower() == "mock":
            mock = self.cfg.extra.get("mock_extract")
            return mock.copy() if isinstance(mock, dict) else None

        return self._ask(system_prompt, user_prompt)
