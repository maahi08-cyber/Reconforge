from reconforge.intelligence.hunter import build_hypotheses
from reconforge.models import Observation, ObservationKind


def test_new_temporal_surface_becomes_exposure_hypothesis():
    endpoint = Observation(
        ObservationKind.ENDPOINT,
        "https://example.com/api/new",
        "httpx",
        "run",
        {"method": "GET", "features": {"is_api": True}},
    )
    delta = Observation(
        ObservationKind.HISTORICAL,
        endpoint.subject,
        "history-delta",
        "run",
        {"status": "new", "rationale": "new in current collection"},
    )
    hypotheses = build_hypotheses([endpoint, delta])
    exposure = next(item for item in hypotheses if item.subject == endpoint.subject and item.hypothesis_type.value == "exposure")
    assert exposure.confidence > 0
    assert any("newly observed" in contribution.reason for contribution in exposure.contributions)
