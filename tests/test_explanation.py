import pytest
from datetime import datetime
from src.sequence.chain_builder import ApiCallChain
from src.ingestion.models import RequestRecord
from src.engine.explanation import generate_alert
from src.engine.risk_scorer import compute_severity, compute_risk_score
from src.engine.alert_store import AlertStore
from src.engine.alert import Alert, AlertExplanation, RawFeatures


def make_chain(session_id="sess_test", records=None) -> ApiCallChain:
    chain = ApiCallChain(session_id=session_id)
    if records:
        chain.records = records
    return chain


class TestGenerateAlert:
    def test_normal_alert(self):
        chain = make_chain(records=[RequestRecord(method="GET", path="/api/v1/login")])
        llm_result = {"is_anomaly": False, "anomaly_type": "normal", "confidence": 0.9, "reasoning": "正常调用"}
        alert = generate_alert(chain, llm_result, alert_index=1)
        assert alert.anomaly_type == "normal"
        assert alert.severity == "info"
        assert alert.explanation.summary != ""

    def test_traversal_alert(self):
        chain = make_chain(session_id="sess_trav", records=[
            RequestRecord(method="GET", path="/api/v1/users/10001", status_code=200),
            RequestRecord(method="GET", path="/api/v1/users/10002", status_code=404),
            RequestRecord(method="GET", path="/api/v1/users/10003", status_code=404),
        ])
        llm_result = {
            "is_anomaly": True,
            "anomaly_type": "traversal",
            "confidence": 0.85,
            "reasoning": "检测到参数遍历",
            "chain_of_thought": "分析参数：id从10001到10003递增，404占比高",
        }
        alert = generate_alert(chain, llm_result, alert_index=2)
        assert alert.anomaly_type == "traversal"
        assert alert.severity == "high"
        assert alert.confidence == 0.85
        assert alert.explanation.chain_of_thought != ""
        assert len(alert.explanation.key_indicators) > 0
        assert alert.raw_features.param_pattern == "sequential_increment" or alert.raw_features.param_pattern == ""

    def test_bola_alert(self):
        chain = make_chain(session_id="sess_bola", records=[
            RequestRecord(method="POST", path="/api/v1/login"),
            RequestRecord(method="GET", path="/api/v1/orders/12345"),
        ])
        llm_result = {"is_anomaly": True, "anomaly_type": "bola", "confidence": 0.9, "reasoning": "检测到越权"}
        alert = generate_alert(chain, llm_result, alert_index=3)
        assert alert.anomaly_type == "bola"
        assert alert.severity == "critical"
        assert alert.explanation.summary == "检测到越权"

    def test_abuse_alert(self):
        chain = make_chain(session_id="sess_abuse", records=[
            RequestRecord(method="GET", path=f"/api/v1/export/{i}", status_code=200)
            for i in range(50)
        ])
        llm_result = {"is_anomaly": True, "anomaly_type": "abuse", "confidence": 0.75, "reasoning": "检测到接口滥用"}
        alert = generate_alert(chain, llm_result, alert_index=4)
        assert alert.anomaly_type == "abuse"
        assert alert.raw_features.request_count == 50

    def test_alert_id_format(self):
        chain = make_chain(records=[RequestRecord(method="GET", path="/")])
        llm_result = {"is_anomaly": False, "anomaly_type": "normal", "confidence": 0.0, "reasoning": ""}
        alert = generate_alert(chain, llm_result, alert_index=42)
        assert alert.alert_id.startswith("ALT-")
        assert alert.alert_id.endswith("-042")


class TestRiskScorer:
    def test_severity_critical(self):
        alert = Alert(anomaly_type="bola", confidence=0.9, severity="critical")
        assert compute_severity(alert) == "critical"

    def test_severity_high(self):
        alert = Alert(anomaly_type="traversal", confidence=0.7, severity="high")
        assert compute_severity(alert) == "high"

    def test_risk_score_normal(self):
        alert = Alert(anomaly_type="normal", confidence=0.9)
        score = compute_risk_score(alert)
        assert score == 0.0

    def test_risk_score_bola(self):
        alert = Alert(anomaly_type="bola", confidence=0.8)
        score = compute_risk_score(alert)
        assert 0.7 < score <= 1.0


class TestAlertStore:
    def test_add_and_get(self):
        store = AlertStore()
        alert = Alert(alert_id="ALT-001", anomaly_type="traversal", severity="high")
        store.add(alert)
        assert store.get_by_id("ALT-001") is not None
        assert len(store.get_all()) == 1

    def test_count(self):
        store = AlertStore()
        store.add(Alert(alert_id="A1", anomaly_type="bola", severity="critical"))
        store.add(Alert(alert_id="A2", anomaly_type="traversal", severity="high"))
        stats = store.count()
        assert stats["total"] == 2
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_type"]["traversal"] == 1

    def test_get_recent(self):
        store = AlertStore()
        store.add(Alert(alert_id="R1", anomaly_type="bola", severity="critical"))
        recent = store.get_recent(minutes=60)
        assert len(recent) == 1

    def test_max_alerts_eviction(self):
        store = AlertStore(max_alerts=3, retention_hours=24)
        for i in range(5):
            store.add(Alert(alert_id=f"EV{i}", anomaly_type="normal", severity="info"))
        stats = store.count()
        assert stats["total"] <= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
