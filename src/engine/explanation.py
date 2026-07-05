import structlog
from datetime import datetime
from typing import Optional
from src.sequence.chain_builder import ApiCallChain
from src.features.access_patterns import compute_all_features
from src.features.param_features import (
    extract_params,
    shannon_entropy,
    detect_sequential_pattern,
)
from src.engine.alert import (
    Alert,
    AlertExplanation,
    RawFeatures,
    SEVERITY_MAP,
)

logger = structlog.get_logger()


def generate_alert(
    chain: ApiCallChain,
    llm_result: dict,
    alert_index: int = 1,
    status: str = "confirmed",
) -> Alert:
    features = compute_all_features(chain.records)
    anomaly_type = llm_result.get("anomaly_type", "normal")
    confidence = llm_result.get("confidence", 0.0)
    now = datetime.now()

    chain_of_thought = llm_result.get("chain_of_thought", "")
    reasoning = llm_result.get("reasoning", "")

    key_indicators = _extract_indicators(chain, features)

    endpoints = list(set(
        r.normalized_endpoint() for r in chain.records[-10:]
    ))

    all_params = {}
    for r in chain.records:
        all_params.update(extract_params(r))
    value_list = list(all_params.values())
    entropy = shannon_entropy(value_list) if value_list else 0.0

    error_count = sum(1 for r in chain.records if r.status_code and 400 <= r.status_code < 500)
    total = len(chain.records)
    not_found_ratio = error_count / total if total > 0 else 0.0

    param_pattern = ""
    if anomaly_type == "traversal":
        vals = list(all_params.values())
        pattern = detect_sequential_pattern(vals)
        if pattern:
            param_pattern = pattern

    first_record = chain.records[0] if chain.records else None
    source_ip = first_record.source_ip or "0.0.0.0" if first_record and first_record.source_ip else "0.0.0.0"

    intervals = []
    for i in range(1, len(chain.records)):
        delta = (chain.records[i].timestamp - chain.records[i - 1].timestamp).total_seconds()
        intervals.append(max(delta, 0))
    time_window = sum(intervals) if intervals else 0.0

    return Alert(
        alert_id=f"ALT-{now.strftime('%Y%m%d')}-{alert_index:03d}",
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
        status=status,
        severity=SEVERITY_MAP.get(anomaly_type, "medium"),
        anomaly_type=anomaly_type,
        confidence=confidence,
        session_id=chain.session_id,
        source_ip=source_ip,
        affected_endpoints=endpoints,
        explanation=AlertExplanation(
            summary=reasoning,
            chain_of_thought=chain_of_thought,
            key_indicators=key_indicators,
            risk_assessment=reasoning,
        ),
        raw_features=RawFeatures(
            request_count=total,
            time_window_sec=round(time_window, 2),
            param_entropy=round(entropy, 4),
            not_found_ratio=round(not_found_ratio, 4),
            param_pattern=param_pattern,
        ),
        raw_llm_output=llm_result.get("_raw_output", ""),
    )


def _extract_indicators(chain: ApiCallChain, features: dict) -> list[str]:
    indicators = []

    if features.get("sequence_length", 0) > 0:
        indicators.append(f"请求总量: {features['sequence_length']}次")

    duration = features.get("inter_api_access_duration", {})
    if duration.get("mean", 0) > 0:
        indicators.append(f"平均请求间隔: {duration['mean']:.1f}s")

    if features.get("num_client_error", 0) > 0.3:
        indicators.append(f"4xx错误占比: {features['num_client_error']:.0%}")

    uniqueness = features.get("api_access_uniqueness", 1.0)
    if uniqueness < 0.3:
        indicators.append(f"接口唯一性低: {uniqueness:.0%}（可能集中在少量端点）")

    monotonicity = features.get("param_monotonicity", 0.0)
    if monotonicity > 0:
        indicators.append(f"参数单调递增指数: {monotonicity}")

    return indicators
