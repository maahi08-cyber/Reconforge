"""Cross-source correlation and conservative research-signal generation."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType, Observation, ObservationKind


@dataclass(frozen=True, slots=True)
class Correlation:
    subject: str
    observations: tuple[Observation, ...]
    independent_sources: int
    source_families: int


def correlate(observations: Iterable[Observation]) -> list[Correlation]:
    groups: dict[str, list[Observation]] = defaultdict(list)
    for obs in observations:
        groups[obs.subject].append(obs)

    result: list[Correlation] = []
    for subject, items in groups.items():
        # Tool names often overlap at the same underlying data source. We use a
        # conservative family key when supplied, otherwise the adapter source.
        families = {
            str(item.attributes.get("source_family", item.source))
            for item in items
        }
        result.append(Correlation(subject, tuple(items), len({item.source for item in items}), len(families)))
    return sorted(result, key=lambda item: (item.independent_sources, item.source_families), reverse=True)


def build_hypothesis(correlation: Correlation) -> Hypothesis | None:
    observations = correlation.observations
    kinds = {item.kind for item in observations}
    if ObservationKind.ENDPOINT not in kinds and ObservationKind.HTTP not in kinds:
        return None

    attrs = [item.attributes for item in observations]
    categories = set().union(*(set(a.get("categories", [])) for a in attrs))
    has_object = any(a.get("object_identifier") or a.get("identifiers") for a in attrs)
    authenticated = any(bool(a.get("authenticated")) for a in attrs)
    state_change = any(bool(a.get("state_changing")) for a in attrs)
    historical = any(bool(a.get("historical")) for a in attrs)

    if "invitation" in categories or "membership" in categories:
        htype = HypothesisType.AUTHORIZATION
    elif "file" in categories and has_object:
        htype = HypothesisType.AUTHORIZATION
    elif "billing" in categories:
        htype = HypothesisType.BUSINESS_LOGIC
    elif "graphql" in categories or "api" in categories:
        htype = HypothesisType.API
    else:
        htype = HypothesisType.UNKNOWN

    hypothesis = Hypothesis(subject=correlation.subject, hypothesis_type=htype)
    for index, obs in enumerate(observations):
        weight = 2.0 if index == 0 else 1.5
        reason = f"{obs.source} provided {obs.kind.value} evidence"
        hypothesis.contributions.append(EvidenceContribution(obs.evidence_hash, reason, weight))

    if authenticated:
        hypothesis.contributions.append(EvidenceContribution("synthetic:authenticated", "authenticated context observed", 4.0))
    if has_object:
        hypothesis.contributions.append(EvidenceContribution("synthetic:object", "object-like identifier observed", 5.0))
    if state_change:
        hypothesis.contributions.append(EvidenceContribution("synthetic:state-change", "state-changing operation observed", 3.0))
    if historical and not authenticated:
        hypothesis.negative_evidence.append(EvidenceContribution("synthetic:historical-only", "historical evidence lacks current authenticated confirmation", 4.0))

    hypothesis.recompute()
    hypothesis.novelty = 1.0 if historical is False else 0.6
    return hypothesis
