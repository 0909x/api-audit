import structlog
from typing import Optional
from src.sequence.chain_builder import ApiCallChain
from src.features.access_patterns import compute_all_features
from src.features.param_features import extract_params, shannon_entropy
from src.llm.siliconflow_client import SiliconFlowClient
from src.llm.cache import LLMCache
from src.llm.prompts import SYSTEM_PROMPT, build_user_prompt, format_acc, format_features

logger = structlog.get_logger()


class LLMAnalyzer:
    def __init__(self, client: SiliconFlowClient, cache: Optional[LLMCache] = None):
        self.client = client
        self.cache = cache or LLMCache()

    def analyze(self, chain: ApiCallChain, spec_summary: str = "", spec_detail: str = "") -> dict:
        if not chain.records:
            return {"is_anomaly": False, "anomaly_type": "normal", "confidence": 0.0, "reasoning": "空的调用序列"}

        acc_text = format_acc(chain.records)
        from src.sequence.graph_builder import build_acg
        acg_text = build_acg(chain)

        param_summary = self._summarize_params(chain.records)
        features = compute_all_features(chain.records)
        access_pattern_summary = format_features(features)

        user_prompt = build_user_prompt(acc_text, acg_text, param_summary, access_pattern_summary, spec_summary, spec_detail)

        cached = self.cache.get(SYSTEM_PROMPT, user_prompt)
        if cached is not None:
            return cached

        result = self.client.analyze(SYSTEM_PROMPT, user_prompt)

        if result.get("anomaly_type") not in ("parse_error", "api_error", "circuit_breaker_open"):
            self.cache.set(SYSTEM_PROMPT, user_prompt, result)

        return result

    async def analyze_async(self, chain: ApiCallChain, spec_summary: str = "", spec_detail: str = "") -> dict:
        if not chain.records:
            return {"is_anomaly": False, "anomaly_type": "normal", "confidence": 0.0, "reasoning": "空的调用序列"}

        acc_text = format_acc(chain.records)
        from src.sequence.graph_builder import build_acg
        acg_text = build_acg(chain)

        param_summary = self._summarize_params(chain.records)
        features = compute_all_features(chain.records)
        access_pattern_summary = format_features(features)

        user_prompt = build_user_prompt(acc_text, acg_text, param_summary, access_pattern_summary, spec_summary, spec_detail)

        cached = self.cache.get(SYSTEM_PROMPT, user_prompt)
        if cached is not None:
            return cached

        result = await self.client.analyze_async(SYSTEM_PROMPT, user_prompt)

        if result.get("anomaly_type") not in ("parse_error", "api_error", "circuit_breaker_open"):
            self.cache.set(SYSTEM_PROMPT, user_prompt, result)

        return result

    def _summarize_params(self, records: list) -> str:
        if not records:
            return "无参数数据"
        all_params = {}
        for r in records:
            all_params.update(extract_params(r))

        value_list = list(all_params.values())
        entropy = shannon_entropy(value_list) if value_list else 0.0

        path_params = [k for k in all_params if k.startswith("path:")]
        query_params = [k for k in all_params if k.startswith("query:")]

        from src.features.param_features import identify_param_type
        param_types = {}
        for k, v in all_params.items():
            t = identify_param_type(v)
            param_types[t] = param_types.get(t, 0) + 1

        return (f"参数总数: {len(all_params)}, 路径参数: {len(path_params)}, "
                f"查询参数: {len(query_params)}, 熵值: {entropy}, "
                f"类型分布: {param_types}")
