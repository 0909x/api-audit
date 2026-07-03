"""
API安全审计工具 - 评测脚本
运行对比实验：规则引擎 vs LLM vs 混合策略
输出指标对比表
"""
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.evaluation.runner import run_full_evaluation
from src.evaluation.metrics import confusion_matrix_summary


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=3, help="每类样本数 (默认3)")
    parser.add_argument("--llm-only", action="store_true", help="仅运行LLM依赖的策略")
    parser.add_argument("--include-xgboost", action="store_true", default=True,
                        help="包含XGBoost基线对比 (默认启用)")
    parser.add_argument("--synthetic", action="store_true",
                        help="使用合成数据集 (默认使用真实OpenAPI规范)")
    args = parser.parse_args()

    samples_per_type = args.samples

    print("=" * 70)
    print("API安全审计工具 - 对比评测")
    if args.synthetic:
        print("数据集: 合成数据 (模板生成)")
    else:
        print("数据集: 真实OpenAPI规范驱动")
    print(f"每类 {samples_per_type} 个样本, 每规范")
    print(f"策略: Rule Only / LLM Only / Hybrid (Rule+LLM) / XGBoost Baseline")
    print("=" * 70)

    start = time.time()
    results = run_full_evaluation(
        samples_per_type=samples_per_type,
        include_xgboost=args.include_xgboost,
        use_real_specs=not args.synthetic,
    )
    elapsed = time.time() - start

    print("\n" + confusion_matrix_summary(results))
    print(f"\n总耗时: {elapsed:.2f}s")
    print("=" * 70)

    print("\n对比分析:")
    for name, r in results.items():
        print(f"  {name:<25} F1={r.f1:.4f}  FPR={r.fpr:.4f}  Precision={r.precision:.4f}  Recall={r.recall:.4f}")

    best = max(results.items(), key=lambda x: x[1].f1)
    print(f"\n最佳策略: {best[0]} (F1={best[1].f1:.4f})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
