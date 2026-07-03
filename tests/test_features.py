import pytest
from src.features.param_features import (
    identify_param_type,
    shannon_entropy,
    detect_sequential_pattern,
    extract_params,
)
from src.features.access_patterns import (
    calc_sequence_length,
    calc_num_client_error,
    compute_all_features,
)
from src.ingestion.models import RequestRecord


class TestParamFeatures:
    def test_identify_uuid(self):
        assert identify_param_type("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_identify_email(self):
        assert identify_param_type("user@example.com") == "email"

    def test_identify_id(self):
        assert identify_param_type("12345") == "id"
        assert identify_param_type("9999") == "id"

    def test_identify_other(self):
        assert identify_param_type("hello") == "other"
        assert identify_param_type("abc") == "other"

    def test_shannon_entropy_uniform(self):
        values = ["a", "b", "c", "d"]
        ent = shannon_entropy(values)
        assert ent == 2.0

    def test_shannon_entropy_same(self):
        values = ["a", "a", "a", "a"]
        ent = shannon_entropy(values)
        assert ent == 0.0

    def test_shannon_entropy_empty(self):
        assert shannon_entropy([]) == 0.0

    def test_detect_sequential_increment(self):
        values = ["100", "101", "102", "103", "104"]
        result = detect_sequential_pattern(values)
        assert result == "sequential_increment"

    def test_detect_sequential_decrement(self):
        values = ["10", "9", "8", "7"]
        result = detect_sequential_pattern(values)
        assert result == "sequential_decrement"

    def test_detect_not_sequential(self):
        values = ["100", "200", "50", "999"]
        result = detect_sequential_pattern(values)
        assert result is None

    def test_detect_too_few(self):
        assert detect_sequential_pattern(["1", "2"]) is None

    def test_detect_non_numeric(self):
        assert detect_sequential_pattern(["a", "b", "c"]) is None

    def test_extract_params_query(self):
        record = RequestRecord(method="GET", path="/api/v1/users", query_params={"id": "123", "page": "2"})
        params = extract_params(record)
        assert "query:id" in params
        assert "query:page" in params

    def test_extract_params_path(self):
        record = RequestRecord(method="GET", path="/api/v1/users/12345")
        params = extract_params(record)
        path_keys = [k for k in params if k.startswith("path:")]
        assert len(path_keys) > 0


class TestAccessPatterns:
    def test_sequence_length(self):
        records = [RequestRecord(method="GET", path=f"/api/{i}") for i in range(5)]
        assert calc_sequence_length(records) == 5
        assert calc_sequence_length([]) == 0

    def test_client_error_ratio(self):
        records = [
            RequestRecord(method="GET", path="/a", status_code=404),
            RequestRecord(method="GET", path="/b", status_code=200),
            RequestRecord(method="GET", path="/c", status_code=403),
            RequestRecord(method="GET", path="/d", status_code=200),
        ]
        ratio = calc_num_client_error(records)
        assert ratio == 0.5

    def test_client_error_empty(self):
        assert calc_num_client_error([]) == 0.0

    def test_compute_all_features(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/login"),
            RequestRecord(method="GET", path="/api/v1/users/123", status_code=200),
            RequestRecord(method="GET", path="/api/v1/users/124", status_code=404),
        ]
        features = compute_all_features(records)
        assert "sequence_length" in features
        assert "num_client_error" in features
        assert "param_reuse_ratio" in features
        assert features["sequence_length"] == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
