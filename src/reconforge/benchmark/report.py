"""Benchmark reporting for Hunter Queue quality."""
from __future__ import annotations

from dataclasses import dataclass


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


def _precision(labels: list[str], n: int) -> float:
    sample = labels[:n]
    return sum(label == "useful" for label in sample) / len(sample) if sample else 0.0


def build_report(labels: list[str]) -> BenchmarkReport:
    allowed = {"useful", "noisy", "duplicate", "n/a"}
    if any(label not in allowed for label in labels):
        raise ValueError("unsupported benchmark label")
    return BenchmarkReport(
        len(labels), labels.count("useful"), labels.count("noisy"), labels.count("duplicate"), labels.count("n/a"),
        _precision(labels, 5), _precision(labels, 10), _precision(labels, 20),
    )
