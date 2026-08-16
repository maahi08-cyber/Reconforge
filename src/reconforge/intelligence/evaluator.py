"""Precision metrics for the Hunter Queue and researcher feedback."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QueueMetrics:
    total: int
    useful: int
    noisy: int
    duplicate: int
    not_applicable: int

    @property
    def useful_rate(self) -> float:
        return self.useful / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        bad = self.noisy + self.duplicate
        return bad / self.total if self.total else 0.0


def top_n_precision(labels: list[str], n: int) -> float:
    """Precision among the first n ranked queue items using useful as positive."""
    window = labels[: max(0, n)]
    if not window:
        return 0.0
    return sum(label == "useful" for label in window) / len(window)


def summarize(labels: list[str]) -> QueueMetrics:
    allowed = {"useful", "noisy", "duplicate", "n/a"}
    if any(label not in allowed for label in labels):
        raise ValueError("unknown queue label")
    return QueueMetrics(
        total=len(labels),
        useful=labels.count("useful"),
        noisy=labels.count("noisy"),
        duplicate=labels.count("duplicate"),
        not_applicable=labels.count("n/a"),
    )
