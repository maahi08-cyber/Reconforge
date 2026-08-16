"""Precision metrics for ReconForge benchmark runs."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QueueMetrics:
    total_candidates: int
    useful: int
    duplicates: int
    na: int
    top5_precision: float
    top10_precision: float
    top20_precision: float
    useful_rate: float


def _precision(ranked: list[str], useful: set[str], n: int) -> float:
    if not ranked:
        return 0.0
    window = ranked[:n]
    return sum(item in useful for item in window) / len(window)


def measure_queue(ranked: list[str], useful: set[str], duplicates: set[str] | None = None, na: set[str] | None = None) -> QueueMetrics:
    duplicate_set = duplicates or set()
    na_set = na or set()
    total = len(ranked)
    useful_count = sum(item in useful for item in ranked)
    return QueueMetrics(
        total_candidates=total,
        useful=useful_count,
        duplicates=sum(item in duplicate_set for item in ranked),
        na=sum(item in na_set for item in ranked),
        top5_precision=_precision(ranked, useful, 5),
        top10_precision=_precision(ranked, useful, 10),
        top20_precision=_precision(ranked, useful, 20),
        useful_rate=(useful_count / total) if total else 0.0,
    )
