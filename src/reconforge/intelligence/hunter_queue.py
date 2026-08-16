"""Researcher-facing prioritization queue.

The queue ranks hypotheses, not vulnerabilities. It intentionally favors
corroboration and security context over raw scanner severity.
"""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.models import Hypothesis


@dataclass(frozen=True, slots=True)
class QueueItem:
    rank: int
    hypothesis: Hypothesis
    priority: float
    rationale: tuple[str, ...]


def rank_hypotheses(hypotheses: list[Hypothesis], limit: int = 20) -> list[QueueItem]:
    scored: list[tuple[Hypothesis, float, tuple[str, ...]]] = []
    for item in hypotheses:
        evidence_count = len(item.contributions)
        negative_count = len(item.negative_evidence)
        corroboration = min(1.0, evidence_count / 6.0)
        penalty = min(1.0, negative_count / 3.0)
        priority = item.confidence * (0.55 + 0.45 * corroboration) * (1.0 - 0.45 * penalty)
        rationale = [f"confidence={item.confidence:.1f}", f"evidence={evidence_count}"]
        if negative_count:
            rationale.append(f"negative_evidence={negative_count}")
        scored.append((item, priority, tuple(rationale)))

    scored.sort(key=lambda row: row[1], reverse=True)
    return [QueueItem(index, item, priority, rationale) for index, (item, priority, rationale) in enumerate(scored[:limit], 1)]
