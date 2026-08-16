"""Benchmark reporting for Hunter Queue quality.

The benchmark intentionally measures *prioritization quality*, not raw finding
volume. Queue labels represent analyst outcomes, not automatic vulnerability
truth.
"""
from __future__ import annotations

from dataclasses import dataclass


ALLOWED_LABELS = frozenset({"useful", "noisy", "duplicate", "n/a"})


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    total: int
    useful: int
    noisy: int
    duplicate: int
    not_applicable: int
    top5_precision: float
    top10_precision: float
    top20_precision: float

    @property
    def useful_rate(self) -> float:
        return self.useful / self.total if self.total else 0.0

    @property
    def duplicate_rate(self) -> float:
        return self.duplicate / self.total if self.total else 0.0

    @property
    def not_applicable_rate(self) -> float:
        return self.not_applicable / self.total if self.total else 0.0


def _precision(labels: list[str], n: int) -> float:
    sample = labels[:n]
    return sum(label == "useful" for label in sample) / len(sample) if sample else 0.0


def build_report(labels: list[str]) -> BenchmarkReport:
    if any(label not in ALLOWED_LABELS for label in labels):
        raise ValueError("unsupported benchmark label")
    return BenchmarkReport(
        len(labels),
        labels.count("useful"),
        labels.count("noisy"),
        labels.count("duplicate"),
        labels.count("n/a"),
        _precision(labels, 5),
        _precision(labels, 10),
        _precision(labels, 20),
    )
