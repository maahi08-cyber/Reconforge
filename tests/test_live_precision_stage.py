from reconforge.intelligence.hunter import build_hypotheses
from reconforge.intelligence.hunter_queue import rank_hypotheses
from reconforge.models import Observation, ObservationKind


def test_low_value_surfaces_receive_negative_evidence():
    static = Observation(ObservationKind.ENDPOINT, "https://example.test/static/app.js", "httpx", "run")
    health = Observation(ObservationKind.ENDPOINT, "https://example.test/health", "httpx", "run")
    api = Observation(
        ObservationKind.ENDPOINT,
        "https://example.test/api/v1/users/123",
        "httpx",
        "run",
        {"method": "GET", "features": {"is_api": True, "is_account_or_team": True, "has_object_reference": True}},
    )
    hypotheses = build_hypotheses([static, health, api])
    assert hypotheses
    assert all(item.negative_evidence == [] for item in hypotheses)


def test_queue_ranking_remains_evidence_first_for_correlated_api():
    api_a = Observation(
        ObservationKind.ENDPOINT,
        "https://example.test/api/v1/users/123",
        "httpx",
        "run",
        {"method": "GET", "features": {"is_api": True, "is_account_or_team": True, "has_object_reference": True}},
    )
    api_b = Observation(
        ObservationKind.ENDPOINT,
        "https://example.test/api/v1/users/123",
        "katana",
        "run",
        {"method": "GET", "features": {"is_api": True, "is_account_or_team": True, "has_object_reference": True}},
    )
    hypotheses = build_hypotheses([api_a, api_b])
    ranked = rank_hypotheses(hypotheses, limit=5)
    assert ranked
    assert ranked[0].hypothesis.subject.endswith("/api/v1/users/123")
