"""Generate high-signal research hypotheses from correlated observations."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict

from reconforge.intelligence.classify import classify_url
from reconforge.intelligence.correlation import corroboration_contributions, negative_evidence, summarize
from reconforge.intelligence.ownership import infer_ownership
from reconforge.intelligence.score import score
from reconforge.intelligence.workflow import extract_workflows
from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType, Observation


def build_hypotheses(observations: list[Observation]) -> list[Hypothesis]:
    by_subject: dict[str, list[Observation]] = defaultdict(list)
    for item in observations:
        by_subject[item.subject].append(item)

    results: list[Hypothesis] = []
    workflow_endpoints: list[tuple[str, str]] = []
    endpoint_evidence: dict[str, str] = {}

    for subject, items in by_subject.items():
        endpoint = next((item for item in items if item.kind.value == "endpoint"), None)
        for delta in (item for item in items if item.kind.value == "historical"):
            status = str(delta.attributes.get("status", ""))
            if status == "new":
                features = {"temporal_new": True, "historical_delta": True}
                contribution = EvidenceContribution(
                    delta.evidence_hash,
                    "endpoint is newly observed relative to prior target evidence",
                    0.55,
                )
                results.append(_make(subject, HypothesisType.EXPOSURE, [contribution], features, 1, []))

        if endpoint is None:
            continue

        method = str(endpoint.attributes.get("method", "GET")).upper()
        workflow_endpoints.append((subject, method))
        endpoint_evidence.setdefault(subject, endpoint.evidence_hash)

        features = endpoint.attributes.get("features", {})
        if not features:
            features_obj = classify_url(subject, method)
            features = {key: value for key, value in asdict(features_obj).items() if value}

        summary = summarize(items)
        sources = {item.source for item in items}
        if not sources:
            continue
        corroboration = corroboration_contributions(items)
        negatives = negative_evidence(items)

        ownership = infer_ownership(
            subject,
            response_fields=set(endpoint.attributes.get("response_fields", ())),
        )
        strongest_ownership = max((signal.confidence for signal in ownership), default=0.0)
        ownership_context = bool(ownership and strongest_ownership >= 0.45)

        if features.get("has_object_reference") and (
            features.get("is_api")
            or features.get("is_account_or_team")
            or features.get("is_file_operation")
            or ownership_context
        ):
            contributions = [
                EvidenceContribution(endpoint.evidence_hash, "object reference on security-relevant endpoint", 0.65),
            ]
            if ownership:
                reason = "ownership-boundary context strengthens object-reference relevance"
                if endpoint.attributes.get("response_fields"):
                    reason += " with response ownership fields"
                contributions.append(EvidenceContribution(endpoint.evidence_hash, reason, 0.20))
            contributions.extend(corroboration[: max(0, summary.family_count - 1)])
            results.append(_make(subject, HypothesisType.AUTHORIZATION, contributions, features, summary.source_count, negatives))

        if features.get("has_sensitive_parameter"):
            contributions = [EvidenceContribution(endpoint.evidence_hash, "URL-like or callback parameter", 0.45)]
            if features.get("is_state_changing"):
                contributions.append(EvidenceContribution(endpoint.evidence_hash, "state-changing operation", 0.30))
            contributions.extend(corroboration[: max(0, summary.family_count - 1)])
            results.append(_make(subject, HypothesisType.INPUT_SURFACE, contributions, features, summary.source_count, negatives))

        if features.get("is_invitation") or features.get("is_billing") or features.get("is_file_operation"):
            contributions = [EvidenceContribution(endpoint.evidence_hash, "workflow-sensitive operation", 0.50)]
            if features.get("is_state_changing"):
                contributions.append(EvidenceContribution(endpoint.evidence_hash, "state transition can mutate server state", 0.35))
            contributions.extend(corroboration[: max(0, summary.family_count - 1)])
            results.append(_make(subject, HypothesisType.BUSINESS_LOGIC, contributions, features, summary.source_count, negatives))

    for workflow in extract_workflows(workflow_endpoints):
        if len(workflow.steps) < 2:
            continue
        transition_pairs = workflow.transition_hypotheses()
        for first_action, second_action in transition_pairs:
            first_hash = endpoint_evidence.get(workflow.steps[0].subject)
            last_hash = endpoint_evidence.get(workflow.steps[-1].subject)
            if not first_hash or not last_hash:
                continue
            subject = workflow.steps[0].subject
            contributions = [
                EvidenceContribution(
                    first_hash,
                    f"workflow contains {second_action} without observed {first_action} transition",
                    0.45,
                ),
                EvidenceContribution(last_hash, workflow.rationale, 0.35),
            ]
            features = {
                "workflow_family": True,
                "transition_gap": True,
                "workflow_steps": len(workflow.steps),
            }
            results.append(_make(subject, HypothesisType.BUSINESS_LOGIC, contributions, features, len(workflow.steps), []))

    return sorted(results, key=lambda item: (item.confidence, item.novelty), reverse=True)


def _make(
    subject: str,
    kind: HypothesisType,
    contributions: list[EvidenceContribution],
    features: dict,
    source_count: int,
    negatives: list[EvidenceContribution],
) -> Hypothesis:
    relevance = min(1.0, 0.35 + 0.12 * sum(bool(v) for v in features.values()))
    corroboration = min(1.0, 0.30 + 0.18 * max(0, source_count - 1))
    novelty_bonus = 0.55 if features.get("temporal_new") else 0.45
    negative_penalty = min(1.0, sum(item.weight for item in negatives))
    result = score(
        exposure=1.0,
        relevance=relevance,
        corroboration=corroboration,
        novelty=min(1.0, novelty_bonus + corroboration * 0.4),
        negative_penalty=negative_penalty,
    )
    hypothesis = Hypothesis(
        subject,
        kind,
        contributions=contributions,
        negative_evidence=negatives,
        confidence=result.confidence,
        novelty=result.novelty * 100,
    )
    hypothesis.status = "candidate" if result.confidence >= 45 else "monitor"
    return hypothesis
