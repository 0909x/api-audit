import structlog
import re
import time
from collections import defaultdict
from typing import Optional
from src.ingestion.models import RequestRecord
from src.sequence.chain_builder import ApiCallChain

logger = structlog.get_logger()


SENSITIVE_KEYWORDS = [
    "admin", "config", "debug", "backup", "internal", "secret",
    "token", "key", "password", "credential", "ssn", "cert",
]

SENSITIVE_PATHS = re.compile(
    r"(/admin|/config|/debug|/backup|/internal|/actuator|/swagger|/api-docs)",
    re.IGNORECASE,
)

RESOURCE_ID_PATTERN = re.compile(r"/(\d{4,})")


def extract_user_id(record: RequestRecord) -> str:
    user = record.query_params.get("user", "")
    if user:
        return user
    auth = record.headers.get("authorization", "") if record.headers else ""
    if auth:
        if auth.startswith("Bearer "):
            return auth[7:12]
        return auth[:8]
    return ""


def extract_resource_ids(path: str) -> list[str]:
    return RESOURCE_ID_PATTERN.findall(path)


class RuleEngine:
    def __init__(
        self,
        frequency_threshold: int = 20,
        frequency_window: int = 10,
        abuse_frequency_multiplier: float = 10.0,
        max_client_error_ratio: float = 0.4,
    ):
        self.frequency_threshold = frequency_threshold
        self.frequency_window = frequency_window
        self.abuse_frequency_multiplier = abuse_frequency_multiplier
        self.max_client_error_ratio = max_client_error_ratio
        self._ip_freq: dict[str, list[float]] = defaultdict(list)
        self._session_user: dict[str, str] = {}
        self._session_resource_access: dict[str, dict] = {}

    def check(self, record: RequestRecord, chain: ApiCallChain) -> str:
        if self._check_sensitive_path(record):
            return "abuse"

        if self._check_bola(record, chain):
            return "bola"

        if self._check_frequency(record):
            return "abuse"

        if self._check_rapid_errors(chain):
            return "traversal"

        if self._check_blacklisted_params(record):
            return "abuse"

        return ""

    def _check_sensitive_path(self, record: RequestRecord) -> bool:
        if SENSITIVE_PATHS.search(record.path):
            logger.info("rule_match_sensitive_path", path=record.path)
            return True
        return False

    def _check_bola(self, record: RequestRecord, chain: ApiCallChain) -> bool:
        user_id = extract_user_id(record)
        session_id = record.session_id or ""
        if user_id:
            self._session_user[session_id] = user_id
        resource_ids = extract_resource_ids(record.path)
        if not resource_ids:
            return False
        current_user = self._session_user.get(session_id, "")
        if not current_user:
            return False
        if session_id not in self._session_resource_access:
            self._session_resource_access[session_id] = {}
        access_map = self._session_resource_access[session_id]
        for rid in resource_ids:
            key = (record.method, record.path, rid)
            if key not in access_map:
                access_map[key] = current_user
            elif access_map[key] != current_user:
                logger.info("rule_match_bola", session=session_id, user=current_user, resource=rid, path=record.path)
                return True
        return False

    def _check_frequency(self, record: RequestRecord) -> bool:
        key = record.source_ip or record.session_id or "unknown"
        now = time.time()
        self._ip_freq[key] = [t for t in self._ip_freq.get(key, []) if now - t < self.frequency_window]
        self._ip_freq[key].append(now)

        if len(self._ip_freq[key]) > self.frequency_threshold:
            logger.info("rule_match_frequency", key=key, count=len(self._ip_freq[key]))
            return True
        return False

    def _check_rapid_errors(self, chain: ApiCallChain) -> bool:
        if len(chain.records) < 5:
            return False
        recent = chain.records[-10:]
        error_count = sum(1 for r in recent if r.status_code and 400 <= r.status_code < 500)
        ratio = error_count / len(recent)
        if ratio >= self.max_client_error_ratio:
            logger.info("rule_match_rapid_errors", ratio=ratio)
            return True
        return False

    def _check_blacklisted_params(self, record: RequestRecord) -> bool:
        all_params = list(record.query_params.keys()) + list(record.query_params.values())
        path_segments = record.path.lower().split("/")
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in " ".join(all_params).lower() or keyword in " ".join(path_segments):
                logger.info("rule_match_blacklist_param", keyword=keyword, path=record.path)
                return True
        return False

    def frequency_check_result(self, record: RequestRecord) -> Optional[dict]:
        key = record.source_ip or record.session_id or "unknown"
        now = time.time()
        self._ip_freq[key] = [t for t in self._ip_freq.get(key, []) if now - t < self.frequency_window]
        self._ip_freq[key].append(now)
        count = len(self._ip_freq[key])
        if count > self.frequency_threshold:
            return {"triggered": True, "count": count, "threshold": self.frequency_threshold}
        return None
