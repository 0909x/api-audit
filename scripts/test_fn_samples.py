"""
对之前漏报的2个FN样本进行针对性LLM测试。
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

gen = AdversarialGenerator(seed=42)
samples = gen.generate(samples_per_type=4)

fn_ids = ["adv_low_freq_0000", "adv_biz_anom_0000"]
targets = [s for s in samples if s.session_id in fn_ids]

llm_client = SiliconFlowClient(
    api_key=settings.siliconflow_api_key,
    base_url=settings.siliconflow_api_url,
    model=settings.llm_model,
    temperature=settings.llm_temperature,
    max_tokens=settings.llm_max_tokens,
    max_retries=settings.llm_max_retries,
)
analyzer = LLMAnalyzer(client=llm_client, cache=LLMCache(max_size=200, ttl_seconds=3600))

for sample in targets:
    chain = real_samples_to_chain(sample)
    spec_summary = getattr(sample, "spec_summary", "")
    spec_detail = getattr(sample, "spec_detail", "")
    result = analyzer.analyze(chain, spec_summary=spec_summary, spec_detail=spec_detail)

    at = result.get("anomaly_type", "?")
    conf = result.get("confidence", 0.0)
    reas = result.get("reasoning", "")
    cot = result.get("chain_of_thought", "")[:200]
    status = "OK (anomaly)" if at not in ("normal", "parse_error", "api_error", "circuit_breaker_open") else "MISS"
    print(f"\n{sample.session_id}  label={sample.label} -> pred={at} conf={conf:.2f} {status}")
    print(f"  chain_of_thought: {cot}")
    print(f"  reasoning: {reas}")

    alert = generate_alert(chain, result, alert_index=1, status="confirmed")
    print(f"  alert fields verified: summary={bool(alert.explanation.summary)} risk={bool(alert.explanation.risk_assessment)} indicators={bool(alert.explanation.key_indicators)}")
