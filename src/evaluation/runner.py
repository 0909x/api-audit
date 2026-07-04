import structlog
from src.evaluation.dataset import DatasetGenerator, Sample, samples_to_chain
from src.evaluation.real_dataset import RealDatasetGenerator, RealSample, real_samples_to_chain
from src.evaluation.metrics import EvalResult, confusion_matrix_summary
from src.engine.rule_engine import RuleEngine
from src.engine.llm_analyzer import LLMAnalyzer
from src.engine.pipeline import AuditPipeline
from src.llm.siliconflow_client import SiliconFlowClient
from src.llm.cache import LLMCache
from config.settings import settings

logger = structlog.get_logger()

ANOMALY_TYPES = {"bola", "traversal", "abuse", "mixed"}


def classify_by_rule(sample, engine: RuleEngine, to_chain) -> str:
    chain = to_chain(sample)
    for rec in chain.records:
        from src.ingestion.models import RequestRecord
        record = RequestRecord(
            method=rec.method, path=rec.path,
            query_params=rec.query_params,
            status_code=rec.status_code,
            session_id=rec.session_id,
        )
        if engine.check(record, chain):
            return "anomaly"
    return "normal"


def classify_by_llm(sample, analyzer: LLMAnalyzer, to_chain) -> str:
    chain = to_chain(sample)
    spec_summary = getattr(sample, "spec_summary", "")
    spec_detail = getattr(sample, "spec_detail", "")
    result = analyzer.analyze(chain, spec_summary=spec_summary, spec_detail=spec_detail)
    at = result.get("anomaly_type", "normal")
    if at in ("parse_error", "api_error", "circuit_breaker_open"):
        return "normal"
    if at != "normal":
        return "anomaly"
    from src.features.access_patterns import calc_param_monotonicity, calc_endpoint_freq
    monotonicity = calc_param_monotonicity(chain.records)
    if monotonicity >= 0.8:
        return "anomaly"
    freq = calc_endpoint_freq(chain.records)
    error_count = sum(1 for r in chain.records if r.status_code and 400 <= r.status_code < 500)
    if error_count == 0 and freq.get("top_endpoint_ratio", 0) >= 0.8 and len(chain.records) >= 2:
        return "anomaly"
    return "normal"


def classify_by_hybrid(sample, engine: RuleEngine, analyzer: LLMAnalyzer, to_chain) -> str:
    chain = to_chain(sample)
    rule_triggered = False
    for rec in chain.records:
        from src.ingestion.models import RequestRecord
        record = RequestRecord(
            method=rec.method, path=rec.path,
            query_params=rec.query_params,
            status_code=rec.status_code,
            session_id=rec.session_id,
        )
        if engine.check(record, chain):
            rule_triggered = True
            break
    if rule_triggered:
        return "anomaly"
    spec_summary = getattr(sample, "spec_summary", "")
    spec_detail = getattr(sample, "spec_detail", "")
    result = analyzer.analyze(chain, spec_summary=spec_summary, spec_detail=spec_detail)
    at = result.get("anomaly_type", "normal")
    if at not in ("parse_error", "api_error", "circuit_breaker_open", "normal"):
        return "anomaly"
    return "normal"


def is_actual_anomaly(sample) -> bool:
    return sample.label in ANOMALY_TYPES


def evaluate_strategy(samples: list, strategy: str,
                      engine=None, analyzer=None, to_chain=samples_to_chain) -> EvalResult:
    result = EvalResult()

    for sample in samples:
        actual = is_actual_anomaly(sample)

        if strategy == "rule":
            predicted = classify_by_rule(sample, engine, to_chain)
        elif strategy == "llm":
            predicted = classify_by_llm(sample, analyzer, to_chain)
        elif strategy == "hybrid":
            predicted = classify_by_hybrid(sample, engine, analyzer, to_chain)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

        pred_anomaly = predicted == "anomaly"

        if actual and pred_anomaly:
            result.tp += 1
        elif not actual and pred_anomaly:
            result.fp += 1
        elif not actual and not pred_anomaly:
            result.tn += 1
        else:
            result.fn += 1

        result.details.append({
            "session_id": sample.session_id,
            "actual": sample.label,
            "predicted": predicted,
            "sub_type": sample.sub_type,
        })

    return result


def run_full_evaluation(samples_per_type: int = 20, include_xgboost: bool = False,
                        use_real_specs: bool = True,
                        adversarial: bool = False) -> dict[str, EvalResult]:
    if use_real_specs:
        gen = RealDatasetGenerator(seed=42)
        samples = gen.generate(samples_per_type=samples_per_type)
        to_chain = real_samples_to_chain
        logger.info("using_real_spec_datasets", spec_count=len(gen.specs), total=len(samples))
    else:
        gen = DatasetGenerator(seed=42)
        samples = gen.generate(samples_per_type=samples_per_type)
        to_chain = samples_to_chain
        logger.info("using_synthetic_datasets", total=len(samples))

    if adversarial:
        from src.evaluation.adversarial_dataset import AdversarialGenerator
        adv_gen = AdversarialGenerator(seed=42)
        adv_samples = adv_gen.generate(samples_per_type=4)
        samples.extend(adv_samples)
        logger.info("adversarial_samples_added", count=len(adv_samples))

    rule_engine = RuleEngine(
        frequency_threshold=15,
        frequency_window=10,
        max_client_error_ratio=0.3,
    )

    llm_client = SiliconFlowClient(
        api_key=settings.siliconflow_api_key,
        base_url=settings.siliconflow_api_url,
        model=settings.llm_model,
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
        max_retries=settings.llm_max_retries,
    )
    llm_analyzer = LLMAnalyzer(client=llm_client, cache=LLMCache(max_size=200, ttl_seconds=3600))

    results = {}
    results["Rule Only"] = evaluate_strategy(samples, "rule", engine=rule_engine, to_chain=to_chain)
    logger.info("rule_eval_done", **results["Rule Only"].__dict__)

    results["LLM Only"] = evaluate_strategy(samples, "llm", analyzer=llm_analyzer, to_chain=to_chain)
    logger.info("llm_eval_done", **results["LLM Only"].__dict__)

    results["Hybrid (Rule+LLM)"] = evaluate_strategy(samples, "hybrid", engine=rule_engine,
                                                     analyzer=llm_analyzer, to_chain=to_chain)
    logger.info("hybrid_eval_done", **results["Hybrid (Rule+LLM)"].__dict__)

    if include_xgboost:
        try:
            from src.evaluation.xgboost_baseline import run_xgboost_eval
            if use_real_specs:
                xgb_result, _ = run_xgboost_eval(samples=samples, to_chain=to_chain)
            else:
                xgb_result, _ = run_xgboost_eval(samples_per_type=samples_per_type)
            results["XGBoost Baseline"] = xgb_result
            logger.info("xgboost_eval_done", **xgb_result.__dict__)
        except ImportError:
            logger.warning("xgboost_not_available")

    return results
