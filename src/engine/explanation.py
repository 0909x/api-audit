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
    ALERT_TYPE_LABELS,
    RECOMMENDATIONS,
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

    key_indicators = _extract_indicators(chain, features, anomaly_type)
    summary = _generate_summary(chain, anomaly_type, features, reasoning)
    risk = _generate_risk_assessment(anomaly_type, features, reasoning)
    recommendation = RECOMMENDATIONS.get(anomaly_type, "建议审查相关API调用行为。")

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
            summary=summary,
            chain_of_thought=chain_of_thought,
            key_indicators=key_indicators,
            risk_assessment=risk,
            recommendation=recommendation,
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


def _extract_indicators(chain: ApiCallChain, features: dict, anomaly_type: str) -> list[str]:
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

    if anomaly_type == "traversal":
        indicators.append("参数呈线性递增/均匀分布（遍历攻击典型特征）")
    elif anomaly_type == "bola":
        indicators.append("不同Token访问同一资源ID（越权访问典型特征）")
    elif anomaly_type == "abuse":
        indicators.append("调用频率远超正常业务范围")

    return indicators


def _generate_summary(chain: ApiCallChain, anomaly_type: str, features: dict, reasoning: str) -> str:
    session = chain.session_id[:16] if chain.session_id else "未知"
    total = features.get("sequence_length", 0)
    label = ALERT_TYPE_LABELS.get(anomaly_type, anomaly_type)

    if anomaly_type == "normal":
        return f"会话'{session}'的{total}次调用未发现异常行为。"

    duration = features.get("inter_api_access_duration", {})
    window = duration.get("mean", 0) * total if duration.get("mean") else 0

    if anomaly_type == "traversal":
        return (f"检测到会话'{session}'在{window:.0f}秒内对同一端点发起{total}次请求，"
                f"参数呈遍历特征，符合参数遍历攻击模式。")
    elif anomaly_type == "bola":
        return (f"检测到会话'{session}'的调用序列中存在跨用户资源访问行为，"
                f"不同身份使用各自Token访问了相同的资源ID，符合BOLA越权特征。")
    elif anomaly_type == "abuse":
        return (f"检测到会话'{session}'在短时间内发起{total}次调用请求，"
                f"频率和时序超出正常业务范围。")

    return f"会话'{session}'检测到可疑行为: {reasoning}"


def _generate_risk_assessment(anomaly_type: str, features: dict, reasoning: str) -> str:
    if anomaly_type == "bola":
        return ("攻击者可能通过遍历用户ID或资源ID，获取未授权的敏感数据。"
                "BOLA是OWASP API Top 10排名第一的风险，可能导致大规模数据泄露。")
    elif anomaly_type == "traversal":
        return ("攻击者可能正在批量枚举用户ID或订单ID，试图获取未授权的用户信息。"
                "该行为可能导致用户隐私数据泄露或业务数据被爬取。")
    elif anomaly_type == "abuse":
        return ("异常高频的接口调用可能导致后端服务过载，影响正常用户使用。"
                "同时也可能是数据爬取或撞库攻击的前兆。")
    return reasoning
