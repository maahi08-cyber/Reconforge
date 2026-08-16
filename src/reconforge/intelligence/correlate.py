"""Correlate observations into research candidates without overclaiming."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from reconforge.intelligence.graph import EvidenceGraph
from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType, Observation


@dataclass(frozen=True, slots=True)
class Candidate:
    subject: str
    hypothesis_type: HypothesisType
    observation_keys: tuple[str, ...]
    rationale: str


def correlate(observations: Iterable[Observation], graph: EvidenceGraph) -> list[Candidate]:
    """Create conservative research candidates from correlated observations.

    This first pass only uses deterministic relationships. A single observation
    cannot create a candidate; at least two distinct evidence sources must agree.
    """
    grouped: dict[str, list[str]] = defaultdict(list)
    for observation in observations:
        key = graph.add_observation(observation)
        grouped[observation.subject].append(key)

    candidates: list[Candidate] = []
    for subject, keys in grouped.items():
        if graph.corroborating_sources(keys) < 2:
            continue

        joined = " ".join(graph.observations[key].kind.value for key in keys)
        hypothesis_type = HypothesisType.UNKNOWN
        if "authentication" in joined or "endpoint" in joined:
            hypothesis_type = HypothesisType.AUTHENTICATION
        if "parameter" in joined and "endpoint" in joined:
            hypothesis_type = HypothesisType.INPUT_SURFACE

        candidates.append(
            Candidate(
                subject=subject,
                hypothesis_type=hypothesis_type,
                observation_keys=tuple(dict.fromkeys(keys)),
                rationale=f"Corroborated by {graph.corroborating_sources(keys)} independent sources.",
            )
        )
    return candidates


def to_hypothesis(candidate: Candidate, graph: EvidenceGraph) -> Hypothesis:
    contributions = [
        EvidenceContribution(key, f"Observed by {graph.observations[key].source}", 8.0)
        for key in candidate.observation_keys
    ]
    hypothesis = Hypothesis(candidate.subject, candidate.hypothesis_type, contributions=contributions)
    hypothesis.recompute()
    return hypothesis
