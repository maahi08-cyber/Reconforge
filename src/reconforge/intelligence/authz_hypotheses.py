"""Convert authorized differential evidence into ReconForge hypotheses."""
from __future__ import annotations

from reconforge.intelligence.differential import DifferentialResult
from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType


def build_authorization_hypothesis(result: DifferentialResult) -> Hypothesis:
    """Create a research hypothesis without claiming a confirmed vulnerability."""
    contributions = [
        EvidenceContribution(
            result.endpoint,
            reason,
            max(0.10, weight),
        )
        for reason, weight in _contributions(result)
    ]
    hypothesis = Hypothesis(
        result.endpoint,
        HypothesisType.AUTHORIZATION,
        contributions=contributions,
        confidence=min(100.0, result.signal_strength * 100.0),
        novelty=0.0,
    )
    hypothesis.status = "candidate" if result.signal_strength >= 0.45 else "monitor"
    return hypothesis


def _contributions(result: DifferentialResult) -> list[tuple[str, float]]:
    parts: list[tuple[str, float]] = []
    if result.status_changed:
        parts.append(("authorized-context status difference", 0.20))
    if result.body_changed:
        parts.append(("authorized-context response fingerprint difference", 0.25))
    if result.schema_changed:
        parts.append(("authorized-context schema difference", 0.20))
    if result.object_reference_overlap:
        parts.append(("researcher-supplied object-reference overlap", 0.30))
    if not parts:
        parts.append(("baseline differential comparison retained as low-signal evidence", 0.10))
    return parts
