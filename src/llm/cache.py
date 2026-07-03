import time
import hashlib
import structlog
from collections import OrderedDict
from typing import Optional

logger = structlog.get_logger()


class LLMCache:
    def __init__(self, max_size: int = 500, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    def _make_key(self, system_prompt: str, user_prompt: str) -> str:
        raw = f"{system_prompt}||{user_prompt}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, system_prompt: str, user_prompt: str) -> Optional[dict]:
        key = self._make_key(system_prompt, user_prompt)
        if key not in self._cache:
            return None
        ts, result = self._cache[key]
        if time.time() - ts > self.ttl_seconds:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        logger.info("llm_cache_hit", key=key[:12])
        return result

    def set(self, system_prompt: str, user_prompt: str, result: dict):
        key = self._make_key(system_prompt, user_prompt)
        self._cache[key] = (time.time(), result)
        self._cache.move_to_end(key)
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def clear(self):
        self._cache.clear()
        logger.info("llm_cache_cleared")

    @property
    def size(self) -> int:
        return len(self._cache)
