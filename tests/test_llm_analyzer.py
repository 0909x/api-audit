import pytest
from src.llm.siliconflow_client import parse_model_output
from src.llm.prompts import build_user_prompt, format_acc, format_features
from src.llm.cache import LLMCache
from src.sequence.chain_builder import ApiCallChain
from src.ingestion.models import RequestRecord


class TestParseModelOutput:
    def test_normal_json(self):
        raw = '{"is_anomaly": false, "anomaly_type": "normal", "confidence": 0.9, "reasoning": "正常调用"}'
        result = parse_model_output(raw)
        assert result["is_anomaly"] is False
        assert result["anomaly_type"] == "normal"

    def test_with_think_tag(self):
        raw = "<think>分析调用序列：频率正常，参数分布正常</think>{\"is_anomaly\": true, \"anomaly_type\": \"traversal\", \"confidence\": 0.85, \"reasoning\": \"检测到遍历\"}"
        result = parse_model_output(raw)
        assert result["is_anomaly"] is True
        assert result["anomaly_type"] == "traversal"
        assert "chain_of_thought" in result

    def test_parse_error_fallback(self):
        raw = "一些无法解析的纯文本输出"
        result = parse_model_output(raw)
        assert result["is_anomaly"] is False
        assert result["anomaly_type"] == "parse_error"

    def test_empty_output(self):
        result = parse_model_output("")
        assert result["anomaly_type"] == "parse_error"


class TestPrompts:
    def test_build_user_prompt(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/users"),
            RequestRecord(method="POST", path="/api/v1/login"),
        ]
        acc_text = format_acc(records)
        acg_text = "((GET /api/v1/users, POST /api/v1/login))"
        param_summary = "参数总数: 2, 熵值: 0.5"
        access_summary = "sequence_length: 2"

        prompt = build_user_prompt(acc_text, acg_text, param_summary, access_summary)
        assert "调用序列（ACC）" in prompt
        assert "调用关系图（ACG）" in prompt
        assert "参数特征摘要" in prompt
        assert "访问模式统计" in prompt
        assert "GET /api/v1/users" in prompt

    def test_format_acc(self):
        records = [
            RequestRecord(method="GET", path="/api/v1/users"),
            RequestRecord(method="POST", path="/api/v1/login"),
        ]
        result = format_acc(records)
        assert "[GET /api/v1/users]" in result
        assert "[POST /api/v1/login]" in result
        assert "->" in result


class TestLLMCache:
    def test_set_and_get(self):
        cache = LLMCache(max_size=10, ttl_seconds=3600)
        cache.set("sp1", "up1", {"result": "ok"})
        result = cache.get("sp1", "up1")
        assert result == {"result": "ok"}

    def test_cache_miss(self):
        cache = LLMCache()
        result = cache.get("sp1", "nonexistent")
        assert result is None

    def test_cache_eviction(self):
        cache = LLMCache(max_size=2, ttl_seconds=3600)
        cache.set("sp1", "up1", {"r": 1})
        cache.set("sp2", "up2", {"r": 2})
        cache.set("sp3", "up3", {"r": 3})
        assert cache.get("sp1", "up1") is None
        assert cache.get("sp3", "up3") == {"r": 3}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
