"""Turn authorized differential evidence into a research hypothesis."""
from __future__ import annotations

from reconforge.intelligence.differential import DifferentialResult, ResponseFingerprint
from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType


def build_authorization_hypothesis(
    result: DifferentialResult,
    first: ResponseFingerprint,
    second: ResponseFingerprint,
) -> Hypothesis:
    """Create an authorization research question without declaring a flaw."""
    evidence_ids = {
        _fingerprint_id(first),
        _fingerprint_id(second),
    }
    contributions = [
        EvidenceContribution(evidence_id, reason, weight)
        for evidence_id, reason, weight in zip(
            sorted(evidence_ids),
            _reasons(result),
            _weights(result),
            strict=False,
        )
    ]
    if not contributions:
        contributions = [EvidenceContribution(_fingerprint_id(first), "authorized-context baseline comparison", 0.10)]

    hypothesis = Hypothesis(
        subject=result.endpoint,
        hypothesis_type=HypothesisType.AUTHORIZATION,
        contributions=contributions,
        confidence=min(100.0, result.signal_strength * 100.0),
        novelty=35.0 if result.object_reference_overlap else 20.0,
        status="candidate" if result.signal_strength >= 0.45 else "monitor",
    )
    return hypothesis


def _reasons(result: DifferentialResult) -> tuple[str, ...]:
    reasons: list[str] = []
    if result.status_changed:
        reasons.append("authorized-context HTTP status difference")
    if result.body_changed:
        reasons.append("authorized-context response fingerprint difference")
    if result.schema_changed:
        reasons.append("authorized-context response schema difference")
    if result.object_reference_overlap:
        reasons.append("researcher-supplied object reference overlap")
    return tuple(reasons)


def _weights(result: DifferentialResult) -> tuple[float, ...]:
    weights: list[float] = []
    if result.status_changed:
        weights.append(0.20)
    if result.body_changed:
        weights.append(0.25)
    if result.schema_changed:
        weights.append(0.20)
    if result.object_reference_overlap:
        weights.append(0.30)
    return tuple(weights)


def _fingerprint_id(fingerprint: ResponseFingerprint) -> str:
    return f"authctx:{fingerprint.status}:{fingerprint.body_hash[:16]}:{fingerprint.body_length}"
