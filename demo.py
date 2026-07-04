"""
API安全审计工具 - 端到端演示脚本
用法:
  python demo.py                          # 规则引擎评测 (默认)
  python demo.py --samples 3              # 每类3个样本
  python demo.py --llm                    # 包含LLM分析 (需配置API Key)
  python demo.py --synthetic              # 使用合成数据集
  python demo.py --samples 3 --llm --synthetic
"""
import sys
import os
import time
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timedelta
from src.evaluation.real_dataset import RealDatasetGenerator, real_samples_to_chain
from src.evaluation.dataset import DatasetGenerator, samples_to_chain
from src.evaluation.metrics import confusion_matrix_summary
from src.engine.rule_engine import RuleEngine
from src.engine.llm_analyzer import LLMAnalyzer
from src.engine.explanation import generate_alert
from src.sequence.chain_builder import ApiCallChain
from src.ingestion.models import RequestRecord
from src.llm.siliconflow_client import SiliconFlowClient
from src.llm.cache import LLMCache
from config.settings import settings


def print_sep(title: str = ""):
    w = 70
    if title:
        print(f"\n{'=' * (w - len(title) - 4)}  {title}  {'=' * (w - len(title) - 4)}")
    else:
        print("=" * w)


def run_demo(samples_per_type: int = 2, use_llm: bool = False, use_synthetic: bool = False,
             adversarial: bool = False):
    print_sep("API安全审计工具 - 端到端演示")
    print(f"模式: {'合成数据' if use_synthetic else '真实OpenAPI规范'}")
    print(f"LLM分析: {'启用' if use_llm else '仅规则引擎'}")
    print(f"每类样本数: {samples_per_type}")
    print()

    # 1. 生成数据集
    print(">>> 生成数据集...")
    if use_synthetic:
        gen = DatasetGenerator(seed=42)
        samples = gen.generate(samples_per_type=samples_per_type)
        to_chain = samples_to_chain
        print(f"    合成数据集: {len(samples)} 个样本")
    else:
        gen = RealDatasetGenerator(seed=42)
        samples = gen.generate(samples_per_type=samples_per_type)
        to_chain = real_samples_to_chain
        print(f"    真实规范数据集: {len(samples)} 个样本 ({len(gen.specs)} 个规范)")

    if adversarial:
        from src.evaluation.adversarial_dataset import AdversarialGenerator
        adv_gen = AdversarialGenerator(seed=42)
        adv_samples = adv_gen.generate(samples_per_type=4)
        samples.extend(adv_samples)
        print(f"    追加LLM对抗数据集: {len(adv_samples)} 个样本")

    # 2. 初始化引擎
    rule_engine = RuleEngine(
        frequency_threshold=15,
        frequency_window=10,
        max_client_error_ratio=0.3,
    )

    llm_analyzer = None
    if use_llm:
        llm_client = SiliconFlowClient(
            api_key=settings.siliconflow_api_key,
            base_url=settings.siliconflow_api_url,
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            max_retries=settings.llm_max_retries,
        )
        llm_analyzer = LLMAnalyzer(client=llm_client, cache=LLMCache(max_size=200, ttl_seconds=3600))

    # 3. 分析每个样本
    ANOMALY_TYPES = {"bola", "traversal", "abuse", "mixed"}
    results = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    print()
    print_sep("逐样本分析结果")

    for idx, sample in enumerate(samples):
        chain = to_chain(sample)
        spec_info = getattr(sample, "spec_name", "")

        # 3a. 规则引擎检测
        rule_detected = False
        rule_type = ""
        for rec in chain.records:
            record = RequestRecord(
                method=rec.method, path=rec.path,
                query_params=rec.query_params,
                status_code=rec.status_code,
                session_id=rec.session_id,
            )
            r = rule_engine.check(record, chain)
            if r:
                rule_detected = True
                rule_type = r
                break

        # 3b. LLM 分析 (可选)
        llm_result = None
        if llm_analyzer:
            spec_summary = getattr(sample, "spec_summary", "")
            spec_detail = getattr(sample, "spec_detail", "")
            try:
                llm_result = llm_analyzer.analyze(chain, spec_summary=spec_summary, spec_detail=spec_detail)
            except Exception as e:
                llm_result = {"is_anomaly": False, "anomaly_type": "api_error", "confidence": 0.0, "reasoning": str(e)}

        # 3c. 打印结果
        is_anomaly = sample.label in ANOMALY_TYPES
        rule_pred = "anomaly" if rule_detected else "normal"
        llm_pred = "normal"
        if llm_result:
            at = llm_result.get("anomaly_type", "normal")
            llm_pred = "anomaly" if at not in ("normal", "parse_error", "api_error", "circuit_breaker_open") else "normal"

        # 更新统计
        if is_anomaly and rule_detected:
            results["tp"] += 1
        elif not is_anomaly and rule_detected:
            results["fp"] += 1
        elif not is_anomaly and not rule_detected:
            results["tn"] += 1
        else:
            results["fn"] += 1

        # 输出 (避免使用无法在Windows终端显示的Unicode字符)
        label_str = f"[{'异常' if is_anomaly else '正常'}] {sample.label}"
        if sample.sub_type and sample.sub_type != sample.label:
            label_str += f"({sample.sub_type})"
        match_str = "->" if rule_pred == ("anomaly" if is_anomaly else "normal") else "!!"
        llm_status = ""
        if llm_result:
            llm_match = llm_pred == ("anomaly" if is_anomaly else "normal")
            llm_mark = "->" if llm_match else "!!"
            llm_status = f" LLM={'检出' if llm_pred == 'anomaly' else '正常'}({llm_result.get('anomaly_type','?')}) {llm_mark}"

        print(f"\n#{idx+1:02d} {sample.session_id[:35]:35s} {label_str}")
        print(f"    规范: {spec_info}")
        print(f"    请求数: {len(chain.records)}  |  规则引擎: {rule_type or '正常'} {match_str}{llm_status}")

        # 显示前几个请求
        max_show = 4
        for ri, rec in enumerate(chain.records[:max_show]):
            qs = ""
            if rec.query_params:
                pairs = [f"{k}={v}" for k, v in rec.query_params.items()]
                qs = " ?" + "&".join(pairs[:3])
                if len(pairs) > 3:
                    qs += "..."
            print(f"      [{rec.method} {rec.path}{qs}]")
        if len(chain.records) > max_show:
            print(f"      ... 还有 {len(chain.records) - max_show} 个请求")

        if llm_result and llm_result.get("anomaly_type") not in ("normal", "parse_error", "api_error", "circuit_breaker_open"):
            conf = llm_result.get("confidence", 0.0)
            reas = llm_result.get("reasoning", "")
            print(f"    LLM告警: type={llm_result['anomaly_type']} confidence={conf:.2f}")
            if reas:
                print(f"    解释: {reas}")

    # 4. 汇总
    print()
    print_sep("评测汇总")
    from src.evaluation.metrics import EvalResult
    r = EvalResult()
    r.tp = results["tp"]
    r.fp = results["fp"]
    r.tn = results["tn"]
    r.fn = results["fn"]
    print(confusion_matrix_summary({"规则引擎": r}))

    # 5. 按类型细分
    print()
    print("按攻击类型细分:")
    type_results = {}
    for sample in samples:
        chain = to_chain(sample)
        is_anom = sample.label in ANOMALY_TYPES
        detected = any(
            rule_engine.check(RequestRecord(method=rec.method, path=rec.path,
                              query_params=rec.query_params, status_code=rec.status_code,
                              session_id=rec.session_id), chain)
            for rec in chain.records
        )
        key = sample.label if is_anom else "normal"
        if key not in type_results:
            type_results[key] = {"total": 0, "detected": 0}
        type_results[key]["total"] += 1
        if detected == is_anom:
            type_results[key]["detected"] += 1

    type_order = ["normal", "bola", "traversal", "abuse", "mixed"]
    for t in type_order:
        if t in type_results:
            tr = type_results[t]
            pct = tr["detected"] / tr["total"] * 100 if tr["total"] else 0
            print(f"  {t:<12s}: {tr['detected']}/{tr['total']} ({pct:.0f}%)")

    # 6. 生成告警样例
    print()
    print_sep("告警样例")
    alert_samples = [s for s in samples if s.label in ANOMALY_TYPES][:2]
    for s in alert_samples:
        chain = to_chain(s)
        llm_data = {"is_anomaly": True, "anomaly_type": s.sub_type or s.label, "confidence": 0.85,
                     "reasoning": f"检测到{s.sub_type or s.label}异常访问模式"}
        alert = generate_alert(chain, llm_data, alert_index=1, status="confirmed")
        print(f"  alert_id: {alert.alert_id}")
        print(f"  type: {alert.anomaly_type}  severity: {alert.severity}  confidence: {alert.confidence}")
        print(f"  summary: {alert.explanation.summary[:80]}...")
        print(f"  recommendation: {alert.explanation.recommendation[:80]}...")
        print()

    print_sep("演示完成")
    return r


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="API安全审计工具 - 端到端演示")
    parser.add_argument("--samples", type=int, default=2, help="每类样本数 (默认2)")
    parser.add_argument("--llm", action="store_true", help="启用LLM分析 (需配置API Key)")
    parser.add_argument("--synthetic", action="store_true", help="使用合成数据集 (默认使用真实OpenAPI规范)")
    parser.add_argument("--adversarial", action="store_true", help="追加LLM对抗数据集 (24个样本)")
    args = parser.parse_args()

    sys.exit(run_demo(samples_per_type=args.samples, use_llm=args.llm,
                      use_synthetic=args.synthetic, adversarial=args.adversarial))
