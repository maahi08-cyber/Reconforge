"""Correlate client-side leak candidates with application context."""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.intelligence.secretintel import SecretCandidate


@dataclass(frozen=True, slots=True)
class LeakSignal:
    kind: str
    confidence: float
    priority: str
    rationale: str
    context: str
    redacted: str


def correlate_leaks(candidates: list[SecretCandidate], *, referenced_by_route: bool = False, authenticated_context: bool = False, public_bundle: bool = True) -> list[LeakSignal]:
    """Raise or lower prioritization using application context without exposing secrets."""
    signals: list[LeakSignal] = []
    for item in candidates:
        confidence = item.confidence
        reasons = [item.rationale]
        if referenced_by_route:
            confidence += 0.03
            reasons.append("bundle is linked to a discovered application route")
        if authenticated_context:
            confidence += 0.04
            reasons.append("bundle was observed in an authenticated application context")
        if public_bundle:
            reasons.append("client-side bundle is publicly retrievable")
        confidence = min(1.0, confidence)
        priority = "critical-review" if confidence >= 0.97 else "high-review" if confidence >= 0.85 else "review"
        signals.append(LeakSignal(item.kind, confidence, priority, "; ".join(reasons), item.context, item.redacted))
    return sorted(signals, key=lambda value: value.confidence, reverse=True)
