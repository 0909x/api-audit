"""XGBoost baseline for comparison with LLM-based detection.

Usage:
    python -m src.evaluation.xgboost_baseline
"""
import structlog
import numpy as np
from src.evaluation.dataset import DatasetGenerator, samples_to_chain
from src.evaluation.metrics import EvalResult, confusion_matrix_summary
from src.features.access_patterns import compute_all_features
from src.ingestion.models import RequestRecord

logger = structlog.get_logger()

ANOMALY_LABELS = {"bola", "traversal", "abuse", "mixed"}


def _extract_feature_vector(records: list) -> list[float]:
    features = compute_all_features(records)
    return [
        features.get("sequence_length", 0),
        features.get("num_client_error", 0.0),
        features.get("api_access_uniqueness", 1.0),
        features.get("inter_api_access_duration", {}).get("mean", 0.0),
        features.get("inter_api_access_duration", {}).get("std", 0.0),
        float(sum(1 for r in records if r.status_code and r.status_code >= 500)) / max(len(records), 1),
    ]


def _extract_records_from_sample(sample) -> list:
    chain = samples_to_chain(sample)
    return chain.records


def build_dataset(samples_per_type: int = 20):
    gen = DatasetGenerator(seed=42)
    samples = gen.generate(samples_per_type=samples_per_type)
    X, y = [], []
    for s in samples:
        records = _extract_records_from_sample(s)
        X.append(_extract_feature_vector(records))
        y.append(1 if s.label in ANOMALY_LABELS else 0)
    return np.array(X), np.array(y), samples


def build_dataset_from_samples(samples: list, to_chain=samples_to_chain) -> tuple:
    X, y = [], []
    for s in samples:
        chain = to_chain(s)
        records = chain.records
        X.append(_extract_feature_vector(records))
        y.append(1 if s.label in ANOMALY_LABELS else 0)
    return np.array(X), np.array(y), samples


def run_xgboost_eval(samples_per_type: int = 20,
                     samples: Optional[list] = None,
                     to_chain=samples_to_chain):
    from xgboost import XGBClassifier
    from sklearn.model_selection import train_test_split

    if samples is not None:
        X, y, samps = build_dataset_from_samples(samples, to_chain)
    else:
        X, y, samps = build_dataset(samples_per_type)
    X_train, X_test, y_train, y_test, samps_train, samps_test = train_test_split(
        X, y, samples, test_size=0.3, random_state=42, stratify=y
    )

    model = XGBClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.1,
        random_state=42, eval_metric="logloss",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    result = EvalResult()
    for actual, predicted, sample in zip(y_test, y_pred, samps_test):
        if actual == 1 and predicted == 1:
            result.tp += 1
        elif actual == 0 and predicted == 1:
            result.fp += 1
        elif actual == 0 and predicted == 0:
            result.tn += 1
        else:
            result.fn += 1
        result.details.append({
            "session_id": sample.session_id,
            "actual": sample.label,
            "predicted": "anomaly" if predicted else "normal",
        })

    return result, model


def main():
    print("=" * 70)
    print("XGBoost Baseline 评测 (对比 LLM 检测)")
    print("=" * 70)

    result, model = run_xgboost_eval(samples_per_type=50)
    print(confusion_matrix_summary({"XGBoost Baseline": result}))
    print(f"\nFeature importance:")
    feature_names = [
        "sequence_length", "client_error_ratio", "api_uniqueness",
        "interval_mean", "interval_std", "server_error_ratio",
    ]
    for name, imp in sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1], reverse=True,
    ):
        print(f"  {name:<25} {imp:.4f}")


if __name__ == "__main__":
    main()
