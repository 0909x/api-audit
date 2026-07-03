import structlog
import threading
from datetime import datetime, timedelta
from typing import Optional
from src.engine.alert import Alert

logger = structlog.get_logger()


class AlertStore:
    def __init__(self, max_alerts: int = 10000, retention_hours: int = 24):
        self.max_alerts = max_alerts
        self.retention_hours = retention_hours
        self._alerts: list[Alert] = []
        self._lock = threading.Lock()

    def add(self, alert: Alert):
        with self._lock:
            self._alerts.append(alert)
            self._cleanup_if_needed()

    def get_all(self, limit: int = 100, offset: int = 0) -> list[Alert]:
        with self._lock:
            sorted_alerts = sorted(
                self._alerts, key=lambda a: a.timestamp, reverse=True
            )
            return sorted_alerts[offset:offset + limit]

    def get_by_id(self, alert_id: str) -> Optional[Alert]:
        with self._lock:
            for a in self._alerts:
                if a.alert_id == alert_id:
                    return a
            return None

    def get_by_session_id(self, session_id: str) -> Optional[Alert]:
        with self._lock:
            for a in reversed(self._alerts):
                if a.session_id == session_id:
                    return a
            return None

    def get_preliminary_by_session_id(self, session_id: str) -> Optional[Alert]:
        with self._lock:
            for a in reversed(self._alerts):
                if a.session_id == session_id and a.is_preliminary:
                    return a
            return None

    def has_confirmed_alert(self, session_id: str, anomaly_type: str) -> bool:
        with self._lock:
            for a in self._alerts:
                if a.session_id == session_id and a.anomaly_type == anomaly_type and a.is_confirmed:
                    return True
            return False

    def upgrade_alert(self, alert_id: str, llm_result: dict) -> bool:
        with self._lock:
            for a in self._alerts:
                if a.alert_id == alert_id and a.is_preliminary:
                    a.status = "confirmed"
                    a.confidence = llm_result.get("confidence", a.confidence)
                    cot = llm_result.get("chain_of_thought", "")
                    if cot:
                        a.explanation.chain_of_thought = cot
                    reasoning = llm_result.get("reasoning", "")
                    if reasoning:
                        a.explanation.summary = reasoning
                    if a.explanation.chain_of_thought:
                        a.explanation.summary = a.explanation.chain_of_thought[:80] + "…" if len(a.explanation.chain_of_thought or "") > 80 else a.explanation.chain_of_thought
                    logger.info("alert_upgraded", alert_id=alert_id, confidence=a.confidence)
                    return True
            return False

    def has_session_alert(self, session_id: str, anomaly_type: str) -> bool:
        """Check if a session already has an alert of the given type (for dedup)."""
        with self._lock:
            for a in self._alerts:
                if a.session_id == session_id and a.anomaly_type == anomaly_type:
                    return True
            return False

    def get_by_severity(self, severity: str, limit: int = 50) -> list[Alert]:
        with self._lock:
            filtered = [a for a in self._alerts if a.severity == severity]
            return sorted(filtered, key=lambda a: a.timestamp, reverse=True)[:limit]

    def get_recent(self, minutes: int = 60) -> list[Alert]:
        cutoff = datetime.now() - timedelta(minutes=minutes)
        with self._lock:
            recent = []
            for a in self._alerts:
                try:
                    ts = datetime.strptime(
                        a.timestamp.split("+")[0], "%Y-%m-%dT%H:%M:%S"
                    )
                    if ts >= cutoff:
                        recent.append(a)
                except ValueError:
                    recent.append(a)
            return sorted(recent, key=lambda a: a.timestamp, reverse=True)

    def count(self) -> dict:
        with self._lock:
            total = len(self._alerts)
            by_severity = {}
            by_type = {}
            by_status = {}
            for a in self._alerts:
                by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
                by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1
                by_status[a.status] = by_status.get(a.status, 0) + 1
            return {
                "total": total,
                "by_severity": by_severity,
                "by_type": by_type,
                "by_status": by_status,
            }

    def _cleanup_if_needed(self):
        if len(self._alerts) <= self.max_alerts:
            return
        cutoff = datetime.now() - timedelta(hours=self.retention_hours)
        self._alerts = [
            a for a in self._alerts
            if not self._is_expired(a, cutoff)
        ]
        while len(self._alerts) > self.max_alerts:
            self._alerts.pop(0)

    def _is_expired(self, alert: Alert, cutoff: datetime) -> bool:
        try:
            ts = datetime.strptime(alert.timestamp.split("+")[0], "%Y-%m-%dT%H:%M:%S")
            return ts < cutoff
        except ValueError:
            return False
