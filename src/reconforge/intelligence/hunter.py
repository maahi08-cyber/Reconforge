"""Generate high-signal research hypotheses from correlated observations."""
from __future__ import annotations

from collections import defaultdict

from reconforge.intelligence.classify import EndpointFeatures, classify_url
from reconforge.intelligence.score import score
from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType, Observation


def build_hypotheses(observations: list[Observation]) -> list[Hypothesis]:
    by_subject: dict[str, list[Observation]] = defaultdict(list)
    for item in observations:
        by_subject[item.subject].append(item)

    results: list[Hypothesis] = []
    for subject, items in by_subject.items():
        endpoint = next((item for item in items if item.kind.value == "endpoint"), None)
        if endpoint is None:
            continue
        features = endpoint.attributes.get("features", {})
        if not features:
            features_obj = classify_url(subject, endpoint.attributes.get("method", "GET"))
            features = {k: v for k, v in vars(features_obj).items() if v}
        sources = {item.source for item in items}
        families = {_source_family(item.source) for item in items}

        if not sources:
            continue
        candidates: list[tuple[HypothesisType, list[EvidenceContribution], float, float]] = []
        if features.get("has_object_reference") and (features.get("is_api") or features.get("is_account_or_team") or features.get("is_file_operation")):
            contributions = [EvidenceContribution(endpoint.evidence_hash, "object reference on security-relevant endpoint", 0.65)]
            if len(sources) >= 2:
                contributions.append(EvidenceContribution(next(item.evidence_hash for item in items if item.source != endpoint.source), "independent source corroboration", 0.55))
            if len(families) >= 2:
                contributions.append(EvidenceContribution(endpoint.evidence_hash, "evidence spans distinct source families", 0.30))
            results.append(_make(subject, HypothesisType.AUTHORIZATION, contributions, features, len(sources)))
        if features.get("has_sensitive_parameter"):
            contributions = [EvidenceContribution(endpoint.evidence_hash, "URL-like or callback parameter", 0.45)]
            if features.get("is_state_changing"):
                contributions.append(EvidenceContribution(endpoint.evidence_hash, "state-changing operation", 0.30))
            results.append(_make(subject, HypothesisType.INPUT_SURFACE, contributions, features, len(sources)))
        if features.get("is_invitation") or features.get("is_billing") or features.get("is_file_operation"):
            contributions = [EvidenceContribution(endpoint.evidence_hash, "workflow-sensitive operation", 0.50)]
            if features.get("is_state_changing"):
                contributions.append(EvidenceContribution(endpoint.evidence_hash, "state transition can mutate server state", 0.35))
            results.append(_make(subject, HypothesisType.BUSINESS_LOGIC, contributions, features, len(sources)))
    return sorted(results, key=lambda item: (item.confidence, item.novelty), reverse=True)


def _make(subject: str, kind: HypothesisType, contributions: list[EvidenceContribution], features: dict, source_count: int) -> Hypothesis:
    relevance = min(1.0, 0.35 + 0.12 * sum(bool(v) for v in features.values()))
    corroboration = min(1.0, 0.30 + 0.18 * max(0, source_count - 1))
    result = score(exposure=1.0, relevance=relevance, corroboration=corroboration, novelty=min(1.0, 0.45 + corroboration * 0.4))
    hypothesis = Hypothesis(subject, kind, contributions=contributions, confidence=result.confidence, novelty=result.novelty * 100)
    hypothesis.status = "candidate" if result.confidence >= 45 else "monitor"
    return hypothesis


def _source_family(source: str) -> str:
    name = source.lower()
    if name in {"subfinder", "amass", "crt", "securitytrails", "censys"}:
        return "asset-passive"
    if name in {"gau", "waybackurls", "urlscan"}:
        return "historical"
    if name in {"httpx", "katana", "nmap", "naabu"}:
        return "active"
    if name in {"nuclei"}:
        return "detection"
    return name
