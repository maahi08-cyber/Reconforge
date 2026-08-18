from reconforge.adapters.contracts import DEFAULT_ADAPTERS
from reconforge.intelligence.hunter import build_hypotheses
from reconforge.models import Observation, ObservationKind
from reconforge.runtime.planner import PlanPolicy, plan


def test_default_passive_plan_is_safe_and_deterministic():
    result = plan(DEFAULT_ADAPTERS, PlanPolicy())
    assert [item.name for item in result] == ["subfinder", "amass", "gau", "waybackurls"]


def test_temporal_new_endpoint_generates_research_hypothesis():
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
    assert any(item.hypothesis_type.value == "exposure" for item in hypotheses)
