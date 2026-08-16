"""Researcher-facing investigation cards for the Hunter Queue."""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.models import Hypothesis


@dataclass(frozen=True, slots=True)
class InvestigationCard:
    title: str
    hypothesis: str
    confidence: float
    novelty: float
    why_now: str
    evidence: tuple[str, ...]
    manual_questions: tuple[str, ...]
    caveats: tuple[str, ...]


def build_card(hypothesis: Hypothesis) -> InvestigationCard:
    evidence = tuple(item.reason for item in hypothesis.contributions)
    caveats = tuple(item.reason for item in hypothesis.negative_evidence)
    questions = {
        "authorization": (
            "Does the same object behave differently across explicitly authorized identities or roles?",
            "Is the object reference controllable while ownership remains fixed to another identity?",
            "Does the operation enforce the same authorization boundary on read and mutation paths?",
        ),
        "business_logic": (
            "What states can this workflow legitimately enter?",
            "Can an authorized role perform a transition out of the expected order?",
            "Does repeating, skipping, or reversing a transition change the security boundary?",
        ),
        "input_surface": (
            "What trust boundary does this parameter cross?",
            "Is the value reflected, redirected, fetched, stored, or interpreted by another component?",
        ),
        "exposure": (
            "Is the exposed service intentionally public?",
            "What independent source confirms the service and its context?",
        ),
    }.get(hypothesis.hypothesis_type.value, (
        "What security boundary does this observation cross?",
        "What independent evidence would confirm or falsify the hypothesis?",
    ))
    title = f"Investigate {hypothesis.hypothesis_type.value}: {hypothesis.subject}"
    why_now = "High-confidence correlated evidence is available." if hypothesis.confidence >= 75 else "The signal crossed the current investigation threshold."
    return InvestigationCard(title, f"Possible {hypothesis.hypothesis_type.value} issue", hypothesis.confidence, hypothesis.novelty, why_now, evidence, questions, caveats)
