from reconforge.intelligence.auth_research import build_authorization_hypothesis
from reconforge.intelligence.classify import classify_observations
from reconforge.intelligence.differential import compare_contexts, fingerprint
from reconforge.intelligence.hunter import build_hypotheses
from reconforge.models import Observation, ObservationKind, HypothesisType


def test_hunter_uses_negative_evidence_for_static_surface():
    observations = classify_observations(
        "https://example.test/static/app.js",
        method="GET",
        source="httpx",
        run_id="run",
    )
    hypotheses = build_hypotheses(observations)
    assert all(not item.negative_evidence or item.confidence < 80.0 for item in hypotheses)


def test_hunter_uses_distinct_source_family_corroboration():
    first = Observation(
        ObservationKind.ENDPOINT,
        "https://example.test/api/projects/123/members",
        "httpx",
        "run",
        {"method": "GET", "features": {"is_api": True, "is_account_or_team": True, "has_object_reference": True}},
    )
    second = Observation(
        ObservationKind.ENDPOINT,
        first.subject,
        "katana",
        "run",
        first.attributes,
    )
    hypotheses = build_hypotheses([first, second])
    authorization = next(item for item in hypotheses if item.hypothesis_type == HypothesisType.AUTHORIZATION)
    assert any("independent active evidence family" in item.reason for item in authorization.contributions)


def test_authorized_differential_stays_a_research_question():
    first = fingerprint(200, {"content-type": "application/json"}, b'{"owner_id":1}', {"owner_id"})
    second = fingerprint(200, {"content-type": "application/json"}, b'{"owner_id":2}', {"owner_id"})
    result = compare_contexts("https://example.test/api/projects/123", first, second, object_references_overlap=True)
    hypothesis = build_authorization_hypothesis(result, first, second)
    assert hypothesis.hypothesis_type == HypothesisType.AUTHORIZATION
    assert hypothesis.status in {"candidate", "monitor"}
    assert hypothesis.confidence > 0
