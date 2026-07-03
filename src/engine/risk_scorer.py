from src.engine.alert import Alert


def compute_severity(alert: Alert) -> str:
    if alert.anomaly_type == "bola":
        return "critical"
    if alert.anomaly_type == "traversal":
        return "high" if alert.confidence >= 0.7 else "medium"
    if alert.anomaly_type == "abuse":
        return "high" if alert.confidence >= 0.8 else "medium"
    return "info"


def compute_risk_score(alert: Alert) -> float:
    base = alert.confidence

    type_multiplier = {
        "bola": 1.0,
        "traversal": 0.8,
        "abuse": 0.6,
        "normal": 0.0,
    }.get(alert.anomaly_type, 0.3)

    features = alert.raw_features
    feature_boost = 0.0

    if features.not_found_ratio > 0.5:
        feature_boost += 0.15
    if features.param_pattern in ("sequential_increment", "sequential_decrement"):
        feature_boost += 0.15
    if features.request_count > 50:
        feature_boost += 0.1

    score = base * type_multiplier + feature_boost
    return round(min(score, 1.0), 4)
