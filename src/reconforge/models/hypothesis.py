"""Security-research hypotheses derived from correlated observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class HypothesisType(StrEnum):
    AUTHORIZATION = "authorization"
    AUTHENTICATION = "authentication"
    EXPOSURE = "exposure"
    INPUT_SURFACE = "input_surface"
    BUSINESS_LOGIC = "business_logic"
    API = "api"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EvidenceContribution:
    observation_id: str
    reason: str
    weight: float


@dataclass(slots=True)
class Hypothesis:
    """A ranked research question, never an automatic vulnerability verdict."""

    subject: str
    hypothesis_type: HypothesisType
    contributions: list[EvidenceContribution] = field(default_factory=list)
    negative_evidence: list[EvidenceContribution] = field(default_factory=list)
    confidence: float = 0.0
    novelty: float = 0.0
    status: str = "candidate"

    def recompute(self) -> float:
        positive = sum(item.weight for item in self.contributions)
        negative = sum(item.weight for item in self.negative_evidence)
        # Saturating confidence prevents evidence-count inflation.
        raw = max(0.0, positive - negative)
        self.confidence = min(100.0, 100.0 * (1.0 - 2.718281828 ** (-raw / 25.0)))
        return self.confidence
