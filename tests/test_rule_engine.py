import time
import pytest
from src.ingestion.models import RequestRecord
from src.sequence.chain_builder import ApiCallChain, ChainBuilder
from src.engine.rule_engine import RuleEngine


def make_record(method="GET", path="/api/v1/users", status_code=200, session_id="sess_1", source_ip="10.0.0.1"):
    return RequestRecord(
        method=method,
        path=path,
        status_code=status_code,
        session_id=session_id,
        source_ip=source_ip,
    )


class TestRuleEngine:
    def test_sensitive_path_match(self):
        engine = RuleEngine()
        record = make_record(path="/admin/config")
        assert engine._check_sensitive_path(record) is True

    def test_sensitive_path_normal(self):
        engine = RuleEngine()
        record = make_record(path="/api/v1/users")
        assert engine._check_sensitive_path(record) is False

    def test_frequency_exceeds_threshold(self):
        engine = RuleEngine(frequency_threshold=3, frequency_window=10)
        record = make_record()
        engine._check_frequency(record)
        engine._check_frequency(record)
        engine._check_frequency(record)
        result = engine._check_frequency(record)
        assert result is True

    def test_frequency_below_threshold(self):
        engine = RuleEngine(frequency_threshold=10, frequency_window=10)
        for _ in range(3):
            engine._check_frequency(make_record())
        assert engine._check_frequency(make_record()) is False

    def test_rapid_errors_detected(self):
        engine = RuleEngine(max_client_error_ratio=0.4)
        chain = ApiCallChain(session_id="sess_1")
        for _ in range(3):
            chain.records.append(make_record(status_code=404))
        for _ in range(2):
            chain.records.append(make_record(status_code=200))
        assert engine._check_rapid_errors(chain) is True

    def test_rapid_errors_normal(self):
        engine = RuleEngine(max_client_error_ratio=0.4)
        chain = ApiCallChain(session_id="sess_1")
        for _ in range(1):
            chain.records.append(make_record(status_code=404))
        for _ in range(4):
            chain.records.append(make_record(status_code=200))
        assert engine._check_rapid_errors(chain) is False

    def test_blacklisted_params(self):
        engine = RuleEngine()
        record = make_record(path="/api/v1/secret")
        assert engine._check_blacklisted_params(record) is True

    def test_normal_params(self):
        engine = RuleEngine()
        record = RequestRecord(method="GET", path="/api/v1/users", query_params={"page": "1"})
        assert engine._check_blacklisted_params(record) is False

    def test_integrated_check_trigger(self):
        engine = RuleEngine(frequency_threshold=2, frequency_window=10)
        chain = ApiCallChain(session_id="sess_1")
        record = make_record(path="/admin")
        assert engine.check(record, chain) == "abuse"

    def test_chain_builder_integration(self):
        builder = ChainBuilder(window_seconds=3600, max_length=128)
        for i in range(5):
            builder.append(make_record(path=f"/api/v1/users/{i}", session_id="sess_int"))
        chain = builder.get_chain("sess_int")
        assert chain is not None
        assert len(chain.records) == 5

    def test_chain_timeout(self):
        builder = ChainBuilder(window_seconds=0.1, max_length=128)
        builder.append(make_record(session_id="sess_timeout"))
        time.sleep(0.2)
        chain = builder.get_chain("sess_timeout")
        assert chain is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
