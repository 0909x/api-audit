"""
只对24个对抗样本执行LLM测试，验证检出率。
用法: D:\anaconda\envs\api-audit\python.exe scripts\eval_adversarial_only.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.evaluation.adversarial_dataset import AdversarialGenerator
from src.evaluation.real_dataset import real_samples_to_chain
from src.evaluation.metrics import EvalResult, confusion_matrix_summary
from src.engine.llm_analyzer import LLMAnalyzer
from src.engine.explanation import generate_alert
from src.llm.siliconflow_client import SiliconFlowClient
from src.llm.cache import LLMCache
from config.settings import settings

ANOMALY_TYPES = {"bola", "traversal", "abuse", "mixed"}

def classify_by_llm(sample, analyzer):
    chain = real_samples_to_chain(sample)
    spec_summary = getattr(sample, "spec_summary", "")
    spec_detail = getattr(sample, "spec_detail", "")
    result = analyzer.analyze(chain, spec_summary=spec_summary, spec_detail=spec_detail)
    at = result.get("anomaly_type", "normal")
    if at in ("parse_error", "api_error", "circuit_breaker_open", "normal"):
        return "normal", result
    return "anomaly", result

print("=" * 60)
print("  对抗样本 LLM 测试")
print("=" * 60)

gen = AdversarialGenerator(seed=42)
samples = gen.generate(samples_per_type=4)
print(f"  样本数: {len(samples)}")

llm_client = SiliconFlowClient(
    api_key=settings.siliconflow_api_key,
    base_url=settings.siliconflow_api_url,
    model=settings.llm_model,
    temperature=settings.llm_temperature,
    max_tokens=settings.llm_max_tokens,
    max_retries=settings.llm_max_retries,
)
analyzer = LLMAnalyzer(client=llm_client, cache=LLMCache(max_size=200, ttl_seconds=3600))

results = EvalResult()
type_confusions = []

for idx, sample in enumerate(samples):
    chain = real_samples_to_chain(sample)
    is_anom = sample.label in ANOMALY_TYPES
    sub = sample.sub_type or ""
    sid = sample.session_id[:30]

    print(f"\n#{idx+1:02d} {sid:30s} label={sample.label}", end="")

    pred, llm_result = classify_by_llm(sample, analyzer)
    pred_anom = pred == "anomaly"

    if is_anom and pred_anom:
        results.tp += 1
    elif not is_anom and pred_anom:
        results.fp += 1
    elif not is_anom and not pred_anom:
        results.tn += 1
    else:
        results.fn += 1

    llm_type = llm_result.get("anomaly_type", "?")
    confidence = llm_result.get("confidence", 0.0)
    reasoning = llm_result.get("reasoning", "")[:80]

    match_mark = "OK" if (is_anom == pred_anom) else "MISS"
    print(f"  pred={llm_type} conf={confidence:.2f} {match_mark}")
    print(f"    {reasoning}")

    if is_anom and pred_anom and llm_type != sample.sub_type and llm_type != sample.label:
        type_confusions.append(f"  #{idx+1:02d} {sid}: expected={sub or sample.label}, got={llm_type}")

    # Generate alert to verify fields
    alert = generate_alert(chain, llm_result, alert_index=idx+1, status="confirmed")
    field_issues = []
    if not alert.explanation.summary:
        field_issues.append("summary empty")
    if not alert.explanation.risk_assessment:
        field_issues.append("risk_assessment empty")
    if not alert.explanation.key_indicators:
        field_issues.append("key_indicators empty")
    if not alert.alert_id.startswith("ALT-"):
        field_issues.append("bad alert_id")
    if not (0.0 <= alert.confidence <= 1.0):
        field_issues.append("bad confidence")
    if hasattr(alert.explanation, "recommendation"):
        field_issues.append("recommendation still exists")
    if field_issues:
        print(f"    FIELD ERRORS: {', '.join(field_issues)}")

print("\n" + "=" * 60)
print(confusion_matrix_summary({"LLM on Adversarial": results}))

if type_confusions:
    print(f"\n类型混淆 ({len(type_confusions)}):")
    for c in type_confusions:
        print(c)
else:
    print("\n类型混淆: 0")
print("=" * 60)
