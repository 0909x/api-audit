import structlog
from statistics import mean, stdev
from typing import Optional
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()


def calc_inter_api_access_duration(records: list[RequestRecord]) -> dict:
    if len(records) < 2:
        return {"mean": 0.0, "stdev": 0.0, "values": []}
    intervals = []
    for i in range(1, len(records)):
        delta = (records[i].timestamp - records[i - 1].timestamp).total_seconds()
        intervals.append(max(delta, 0))
    if not intervals:
        return {"mean": 0.0, "stdev": 0.0, "values": []}
    m = mean(intervals)
    s = stdev(intervals) if len(intervals) > 1 else 0.0
    return {"mean": round(m, 4), "stdev": round(s, 4), "values": intervals}


def calc_api_access_uniqueness(records: list[RequestRecord]) -> float:
    if not records:
        return 0.0
    unique_endpoints = set(r.normalized_endpoint() for r in records)
    return round(len(unique_endpoints) / len(records), 4)


def calc_sequence_length(records: list[RequestRecord]) -> int:
    return len(records)


def calc_num_client_error(records: list[RequestRecord]) -> float:
    if not records:
        return 0.0
    error_count = sum(1 for r in records if r.status_code and 400 <= r.status_code < 500)
    return round(error_count / len(records), 4)


def calc_param_reuse_ratio(records: list[RequestRecord]) -> float:
    if len(records) < 2:
        return 0.0
    from src.features.param_features import extract_params

    param_sets = []
    for r in records:
        params = extract_params(r)
        param_sets.append(set(f"{k}={v}" for k, v in params.items()))

    reuse_count = 0
    total_pairs = 0
    for i in range(len(param_sets) - 1):
        if param_sets[i] and param_sets[i + 1]:
            intersection = param_sets[i] & param_sets[i + 1]
            union = param_sets[i] | param_sets[i + 1]
            if union:
                reuse_count += len(intersection)
                total_pairs += len(union)

    if total_pairs == 0:
        return 0.0
    return round(reuse_count / total_pairs, 4)


def compute_all_features(records: list[RequestRecord]) -> dict:
    return {
        "inter_api_access_duration": calc_inter_api_access_duration(records),
        "api_access_uniqueness": calc_api_access_uniqueness(records),
        "sequence_length": calc_sequence_length(records),
        "num_client_error": calc_num_client_error(records),
        "param_reuse_ratio": calc_param_reuse_ratio(records),
    }
