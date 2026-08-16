"""Explainable, conservative hypothesis scoring.

This module intentionally avoids a binary 'vulnerable/not vulnerable' verdict.
Positive evidence and negative evidence are kept separately so researchers can
inspect why a candidate was prioritized.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScoreResult:
    confidence: float
    exposure: float
    relevance: float
    corroboration: float
    novelty: float
    negative_penalty: float


def score(*, exposure: float, relevance: float, corroboration: float, novelty: float, negative_penalty: float = 0.0) -> ScoreResult:
    """Return a bounded, explainable score.

    Inputs are expected in [0, 1]. Corroboration is weighted more heavily than
    raw exposure because independent evidence is a primary false-positive guard.
    """
    values = (exposure, relevance, corroboration, novelty, negative_penalty)
    if any(not 0.0 <= value <= 1.0 for value in values):
        raise ValueError("all score components must be between 0 and 1")

    raw = (
        0.15 * exposure
        + 0.30 * relevance
        + 0.35 * corroboration
        + 0.20 * novelty
        - 0.30 * negative_penalty
    )
    confidence = max(0.0, min(100.0, raw * 100.0))
    return ScoreResult(confidence, exposure, relevance, corroboration, novelty, negative_penalty)
