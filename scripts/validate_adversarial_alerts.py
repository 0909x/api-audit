"""
验证24个对抗样本的告警字段是否完整、正确。
用法: D:\anaconda\envs\api-audit\python.exe scripts\validate_adversarial_alerts.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.evaluation.adversarial_dataset import AdversarialGenerator
from src.evaluation.real_dataset import real_samples_to_chain
from src.engine.llm_analyzer import LLMAnalyzer
from src.engine.explanation import generate_alert
from src.llm.siliconflow_client import SiliconFlowClient
from src.llm.cache import LLMCache
from config.settings import settings

ANOMALY_TYPES = {"bola", "traversal", "abuse", "mixed"}

def check_field(obj, path, check_fn):
    parts = path.split(".")
    val = obj
    for p in parts:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            val = getattr(val, p, None)
        if val is None:
            return False, f"{path} is None"
    try:
        check_fn(val)
        return True, ""
    except (AssertionError, TypeError, ValueError) as e:
        return False, f"{path} check failed: {e}, value={val!r}"

FIELD_CHECKS = [
    ("alert_id", lambda v: v.startswith("ALT-")),
    ("timestamp", lambda v: len(v) > 10),
    ("status", lambda v: v in ("confirmed",)),
    ("severity", lambda v: v in ("critical", "high", "medium", "info")),
    ("anomaly_type", lambda v: v in ("bola", "traversal", "abuse", "normal")),
    ("confidence", lambda v: 0.0 <= v <= 1.0),
    ("session_id", lambda v: len(v) > 0),
    ("source_ip", lambda v: isinstance(v, str)),
    ("affected_endpoints", lambda v: isinstance(v, list)),
    ("explanation.summary", lambda v: isinstance(v, str) and len(v) > 0),
    ("explanation.chain_of_thought", lambda v: isinstance(v, str)),
    ("explanation.key_indicators", lambda v: isinstance(v, list) and len(v) > 0),
    ("explanation.risk_assessment", lambda v: isinstance(v, str) and len(v) > 0),
    ("raw_features.request_count", lambda v: v >= 0),
    ("raw_features.time_window_sec", lambda v: v >= 0),
    ("raw_features.param_entropy", lambda v: v >= 0),
    ("raw_features.not_found_ratio", lambda v: 0.0 <= v <= 1.0),
]

# Ensure recommendation field does NOT exist
def check_no_recommendation(alert):
    assert not hasattr(alert.explanation, "recommendation"), "recommendation field should not exist"

errors = []

print("=" * 70)
print("  对抗样本告警字段验证")
print("=" * 70)

gen = AdversarialGenerator(seed=42)
samples = gen.generate(samples_per_type=4)
print(f"  样本总数: {len(samples)}\n")

for idx, sample in enumerate(samples):
    chain = real_samples_to_chain(sample)
    is_anom = sample.label in ANOMALY_TYPES
    sub = sample.sub_type or ""
    sid = sample.session_id[:30]
    print(f"  #{idx+1:02d} {sid:30s} label={sample.label:12s} sub={sub:20s}", end="")

    # Build fake llm_result based on actual label
    fake_result = {
        "is_anomaly": is_anom,
        "anomaly_type": sample.sub_type or sample.label if is_anom else "normal",
        "confidence": 0.85,
        "reasoning": f"检测到{sub or sample.label}异常访问模式" if is_anom else "正常调用序列",
        "chain_of_thought": f"分析{len(chain.records)}个请求后得出结论" if is_anom else "",
    }

    alert = generate_alert(chain, fake_result, alert_index=idx+1, status="confirmed")

    sample_ok = True
    for field_path, check_fn in FIELD_CHECKS:
        ok, msg = check_field(alert, field_path, check_fn)
        if not ok:
            errors.append(f"  #{idx+1:02d} {sid} FAIL {msg}")
            sample_ok = False

    # Check recommendation does NOT exist
    if hasattr(alert.explanation, "recommendation"):
        errors.append(f"  #{idx+1:02d} {sid} FAIL explanation.recommendation still exists")
        sample_ok = False

    if sample_ok:
        print("  OK")
    else:
        print("  FAIL")

print()
print("=" * 70)
print(f"  验证结果: {len(samples) - len(errors)}/{len(samples)} 通过")
if errors:
    print(f"  失败: {len(errors)} 个问题")
    for e in errors:
        print(e)
else:
    print("  全部字段验证通过!")
print("=" * 70)
