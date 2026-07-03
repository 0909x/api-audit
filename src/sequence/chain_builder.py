import structlog
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()


@dataclass
class ApiCallChain:
    session_id: str
    records: list = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)


class ChainBuilder:
    def __init__(self, window_seconds: int = 1800, max_length: int = 128, cleanup_interval: int = 300):
        self.window_seconds = window_seconds
        self.max_length = max_length
        self._chains: dict[str, ApiCallChain] = OrderedDict()
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = cleanup_interval

    def append(self, record: RequestRecord):
        session_id = record.session_id or self._default_session_id(record)
        now = time.time()

        with self._lock:
            self._cleanup_if_needed(now)

            if session_id not in self._chains:
                self._chains[session_id] = ApiCallChain(session_id=session_id)

            chain = self._chains[session_id]
            chain.records.append(record)
            chain.last_updated = now

            if len(chain.records) > self.max_length:
                chain.records = chain.records[-self.max_length:]

    def get_chain(self, session_id: str) -> Optional[ApiCallChain]:
        with self._lock:
            chain = self._chains.get(session_id)
            if chain and (time.time() - chain.last_updated) <= self.window_seconds:
                return chain
            if chain:
                del self._chains[session_id]
            return None

    def get_or_create_chain(self, session_id: str) -> ApiCallChain:
        chain = self.get_chain(session_id)
        if chain is None:
            chain = ApiCallChain(session_id=session_id)
            with self._lock:
                self._chains[session_id] = chain
        return chain

    def _cleanup_if_needed(self, now: float):
        if now - self._last_cleanup < self._cleanup_interval:
            return
        expired = []
        for sid, chain in self._chains.items():
            if now - chain.last_updated > self.window_seconds:
                expired.append(sid)
        for sid in expired:
            del self._chains[sid]
        self._last_cleanup = now

    def _default_session_id(self, record: RequestRecord) -> str:
        return record.source_ip or "unknown"

    @property
    def active_session_count(self) -> int:
        with self._lock:
            return len(self._chains)
