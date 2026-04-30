#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   cache.py   
@Contact :   mypandamail@163.com
@Author  :   mooo
@Modify Time      @Version    @Description
------------      --------    -----------
2025/9/19 16:43    1.0         None
"""
# pqscan/llm/cache.py
from typing import Optional, Dict, Any
import hashlib, json, os, threading, time

class DiskCache:
    def __init__(self, path: str = ".pqscan_llm_cache.jsonl", ttl_seconds: Optional[int] = None):
        self.path = path
        self.ttl = ttl_seconds
        self._lock = threading.Lock()
        # in-memory index: key -> {"ts":..., "v":...}
        # loaded once at init to avoid scanning file on every get
        self._index = {}
        if not os.path.exists(self.path):
            open(self.path, "a", encoding="utf-8").close()
        else:
            # load existing entries (last-wins) into memory index
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        k = obj.get("k")
                        if k:
                            self._index[k] = {"ts": obj.get("ts", 0), "v": obj.get("v")}
            except Exception:
                # best-effort: if loading fails, keep index empty and fall back to file reads
                self._index = {}

    def _key(self, provider: str, model: str, sys: str, user: str) -> str:
        h = hashlib.sha256((provider + "\n" + model + "\n" + sys + "\n" + user).encode("utf-8")).hexdigest()
        return h

    def get(self, provider: str, model: str, sys: str, user: str) -> Optional[Dict[str,Any]]:
        k = self._key(provider, model, sys, user)
        now = time.time()
        # fast path: check in-memory index
        entry = None
        with self._lock:
            entry = self._index.get(k)
        if entry is not None:
            if self.ttl and now - entry.get("ts", 0) > self.ttl:
                return None
            return entry.get("v")

        # fallback: scan file (in case index was not loaded or corrupted)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if obj.get("k") == k:
                        if self.ttl and now - obj.get("ts", 0) > self.ttl:
                            return None
                        # update index for future calls
                        with self._lock:
                            self._index[k] = {"ts": obj.get("ts", 0), "v": obj.get("v")}
                        return obj.get("v")
        except Exception:
            return None
        return None

    def put(self, provider: str, model: str, sys: str, user: str, value: Dict[str,Any]):
        k = self._key(provider, model, sys, user)
        rec = {"k": k, "ts": time.time(), "v": value}
        # append to file for persistence and update in-memory index
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                # if file write fails, still update memory index to avoid losing cache within process
                pass
            self._index[k] = {"ts": rec["ts"], "v": rec["v"]}
