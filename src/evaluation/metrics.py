import structlog
from dataclasses import dataclass, field
from typing import Optional

logger = structlog.get_logger()


@dataclass
class EvalResult:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    details: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        if self.tp + self.fp == 0:
            return 0.0
        return round(self.tp / (self.tp + self.fp), 4)

    @property
    def recall(self) -> float:
        if self.tp + self.fn == 0:
            return 0.0
        return round(self.tp / (self.tp + self.fn), 4)

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return round(2 * p * r / (p + r), 4)

    @property
    def fpr(self) -> float:
        if self.fp + self.tn == 0:
            return 0.0
        return round(self.fp / (self.fp + self.tn), 4)

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        if total == 0:
            return 0.0
        return round((self.tp + self.tn) / total, 4)

    def merge(self, other: "EvalResult"):
        self.tp += other.tp
        self.fp += other.fp
        self.tn += other.tn
        self.fn += other.fn
        self.details.extend(other.details)

    def __str__(self) -> str:
        return (f"TP={self.tp} FP={self.fp} TN={self.tn} FN={self.fn} | "
                f"Precision={self.precision:.4f} Recall={self.recall:.4f} "
                f"F1={self.f1:.4f} FPR={self.fpr:.4f} Acc={self.accuracy:.4f}")


def from_dict(d: dict) -> EvalResult:
    return EvalResult(
        tp=d.get("tp", 0), fp=d.get("fp", 0),
        tn=d.get("tn", 0), fn=d.get("fn", 0),
    )


def confusion_matrix_summary(results: dict[str, EvalResult]) -> str:
    lines = []
    lines.append(f"{'Strategy':<30} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  "
                 f"{'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6}")
    lines.append("-" * 85)
    for name, r in results.items():
        lines.append(
            f"{name:<30} {r.tp:>4} {r.fp:>4} {r.tn:>4} {r.fn:>4}  "
            f"{r.precision:>6.4f} {r.recall:>6.4f} {r.f1:>6.4f} {r.fpr:>6.4f}"
        )
    return "\n".join(lines)
