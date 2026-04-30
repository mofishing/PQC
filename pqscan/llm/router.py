#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   router.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/19 16:42    1.0         None
"""
# pqscan/llm/router.py
from typing import List, Dict, Any, Optional
import os, time, requests

class LLMRouteError(Exception): ...

def _post_json(url: str, headers: Dict[str,str], payload: Dict[str,Any], timeout: int) -> Dict[str,Any]:
    r = requests.post(url, headers=headers, json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()

def chat_completion(provider: str, model: str, messages: List[Dict[str,str]], temperature: float = 0.1,
                    timeout: int = 45, extra: Optional[Dict[str,Any]] = None, max_retries: int = 2) -> Any | None:
    """
    统一返回 assistant 文本。失败抛 LLMRouteError。
    支持 provider: openai
    """
    provider = (provider or "openai").lower()
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            if provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
                if not api_key: raise LLMRouteError("OPENAI_API_KEY missing")
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                data = {"model": model, "messages": messages, "temperature": temperature}
                js = _post_json("https://api.openai.com/v1/chat/completions", headers, data, timeout)
                return js["choices"][0]["message"]["content"]

            if provider == "ollama":
                # 本地大模型（如 qwen2, llama3 等）
                url = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434/api/chat")
                data = {"model": model, "messages": messages, "options": {"temperature": temperature}}
                js = _post_json(url, {"Content-Type": "application/json"}, data, timeout)
                return js["message"]["content"]

            raise LLMRouteError(f"Unknown provider: {provider}")
        except Exception as e:
            last_err = e
            if attempt < max_retries:
                time.sleep(1.2 * (attempt+1))
            else:
                raise LLMRouteError(str(last_err))
    return None
