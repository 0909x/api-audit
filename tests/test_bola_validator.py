import pytest
from src.engine.bola_validator import BOLAValidator
from src.ingestion.models import RequestRecord


class TestBOLAValidator:
    def test_extract_resource_id(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/users/12345"),
            RequestRecord(method="GET", path="/api/v1/orders/67890"),
        ]
        result = BOLAValidator.extract_resource_id(records)
        assert result == "12345"

    def test_extract_no_resource(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/login"),
        ]
        result = BOLAValidator.extract_resource_id(records)
        assert result is None

    def test_detect_bola_candidates(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/users/100"),
            RequestRecord(method="GET", path="/api/v1/users/200"),
            RequestRecord(method="GET", path="/api/v1/login"),
        ]
        candidates = BOLAValidator.detect_bola_candidates(records)
        assert len(candidates) == 2
        assert candidates[0]["resource_id"] == "100"
        assert candidates[1]["resource_id"] == "200"

    def test_detect_duplicate_ids(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/users/100"),
            RequestRecord(method="GET", path="/api/v1/users/100"),
        ]
        candidates = BOLAValidator.detect_bola_candidates(records)
        assert len(candidates) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
