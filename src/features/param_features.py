import math
import re
import structlog
from collections import Counter
from typing import Optional
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()

ID_PATTERN = re.compile(r"^\d{4,}$")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def identify_param_type(value: str) -> str:
    if UUID_PATTERN.match(value):
        return "uuid"
    if EMAIL_PATTERN.match(value):
        return "email"
    if ID_PATTERN.match(value):
        return "id"
    return "other"


def extract_params(record: RequestRecord) -> dict[str, str]:
    params = {}
    path_segments = record.path.rstrip("/").split("/")
    for seg in path_segments:
        if seg and not seg.startswith("api") and not seg.startswith("v1"):
            params[f"path:{seg}"] = seg

    for k, v in record.query_params.items():
        params[f"query:{k}"] = v

    return params


def shannon_entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    n = len(values)
    freq = Counter(values)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return round(entropy, 4)


def param_value_distribution(records: list[RequestRecord], param_key: str) -> dict:
    values = []
    for rec in records:
        params = extract_params(rec)
        if param_key in params:
            values.append(params[param_key])
    if not values:
        return {"count": 0, "unique": 0, "entropy": 0.0, "values": []}
    return {
        "count": len(values),
        "unique": len(set(values)),
        "entropy": shannon_entropy(values),
        "values": values,
    }


def track_param_propagation(records: list[RequestRecord]) -> list[dict]:
    propagations = []
    prev_params = {}
    for rec in records:
        current_params = extract_params(rec)
        for key, val in current_params.items():
            if key in prev_params and prev_params[key] != val:
                propagations.append({
                    "param": key,
                    "from": prev_params[key],
                    "to": val,
                    "at": rec.normalized_endpoint(),
                })
        prev_params.update(current_params)
    return propagations


def find_path_params(endpoint: str) -> list[str]:
    return re.findall(r"\{(\w+)\}", endpoint)


def detect_sequential_pattern(values: list[str], tolerance: float = 0.1) -> Optional[str]:
    if len(values) < 3:
        return None
    numeric_values = []
    for v in values:
        try:
            numeric_values.append(int(v))
        except ValueError:
            try:
                numeric_values.append(float(v))
            except ValueError:
                return None

    if len(numeric_values) < 3:
        return None

    diffs = [numeric_values[i + 1] - numeric_values[i] for i in range(len(numeric_values) - 1)]
    if not diffs:
        return None
    avg_diff = sum(diffs) / len(diffs)
    if avg_diff == 0:
        return None

    consistent = all(abs(d - avg_diff) / abs(avg_diff) < tolerance for d in diffs)
    if consistent:
        return "sequential_increment" if avg_diff > 0 else "sequential_decrement"
    return None
