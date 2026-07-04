import re
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
        sequence_summary = self._build_sequence_summary(chain.records, features)

        user_prompt = build_user_prompt(acc_text, acg_text, param_summary, access_pattern_summary,
                                        spec_summary, spec_detail, sequence_summary)

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
        sequence_summary = self._build_sequence_summary(chain.records, features)

        user_prompt = build_user_prompt(acc_text, acg_text, param_summary, access_pattern_summary,
                                        spec_summary, spec_detail, sequence_summary)

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

    def _build_sequence_summary(self, records: list, features: dict) -> str:
        from collections import Counter
        from src.features.access_patterns import calc_endpoint_freq, calc_param_monotonicity
        monotonicity = features.get("param_monotonicity", calc_param_monotonicity(records))
        freq = features.get("endpoint_freq", calc_endpoint_freq(records))
        total = len(records)
        lines = []
        lines.append(f"总请求数: {total}")
        dist = freq.get("distribution", {})
        if dist:
            dist_str = ", ".join(f"{ep} ({cnt}次)" for ep, cnt in list(dist.items())[:5])
            lines.append(f"端点频率分布: {dist_str}")
        top_ep = freq.get("top_endpoint", "")
        top_ratio = freq.get("top_endpoint_ratio", 0.0)
        if top_ep:
            lines.append(f"最高占比端点: {top_ep} ({top_ratio*100:.0f}%)")
        lines.append(f"参数单调递增指数: {monotonicity} (0-1, 越高越可疑)")
        if top_ratio >= 0.8 and monotonicity >= 0.8:
            lines.append("可疑标记: 单一端点占比极高且参数单调递增，高度疑似参数遍历")
        elif monotonicity >= 0.8:
            lines.append("可疑标记: 参数值严格单调递增，存在遍历嫌疑")
        elif top_ratio >= 0.8 and total >= 2:
            lines.append("可疑标记: 单个端点请求过于集中")

        call_keys = Counter((r.method, r.path, str(r.query_params), str(r.body)) for r in records)
        top_call_count = call_keys.most_common(1)[0][1]
        if top_call_count >= 5:
            lines.append(f"可疑标记: 同一端点相同参数重复调用 {top_call_count} 次，疑似接口滥用")

        bola_flags = self._detect_cross_session_bola(records)
        for flag in bola_flags:
            lines.append(f"可疑标记: {flag}")

        return "\n".join(lines)

    @staticmethod
    def _detect_cross_session_bola(records: list) -> list[str]:
        sessions = []
        current_user = None
        current_resources = set()

        for r in records:
            if r.method == "POST" and "/login" in r.path:
                if current_user is not None and current_resources:
                    sessions.append({"user": current_user, "resources": current_resources})
                current_user = r.query_params.get("user", "unknown")
                current_resources = set()
            elif r.method == "POST" and "/logout" in r.path:
                if current_user is not None and current_resources:
                    sessions.append({"user": current_user, "resources": current_resources})
                current_user = None
                current_resources = set()
            elif current_user is not None:
                for seg in r.path.strip("/").split("/"):
                    m = re.search(r'(\d{4,})$', seg)
                    if m:
                        current_resources.add(m.group(1))
                for k, v in r.query_params.items():
                    m = re.search(r'(\d{4,})', v)
                    if m:
                        current_resources.add(m.group(1))
                if r.body:
                    for m in re.finditer(r'(\d{4,})', r.body):
                        current_resources.add(m.group(1))

        if current_user is not None and current_resources:
            sessions.append({"user": current_user, "resources": current_resources})

        flags = []
        for i, s1 in enumerate(sessions):
            for s2 in sessions[i+1:]:
                if s1["user"] != s2["user"]:
                    common = s1["resources"] & s2["resources"]
                    if common:
                        for res in sorted(common):
                            flags.append(f"资源ID {res} 被用户 {s1['user']} 和 {s2['user']} 同时访问，存在BOLA(越权)嫌疑")
        return flags
