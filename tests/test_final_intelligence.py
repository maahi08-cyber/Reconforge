from reconforge.intelligence.authz_orchestrator import compare_fixture_files
from reconforge.intelligence.correlation import summarize
from reconforge.intelligence.hunter import build_hypotheses
from reconforge.models import Observation, ObservationKind


def test_correlation_counts_independent_families():
    items = [
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "httpx", "r1"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "katana", "r1"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "httpx", "r1"),
    ]
    summary = summarize(items)
    assert summary.source_count == 2
    assert summary.family_count == 1
    assert summary.duplicate_sources == 1


def test_static_asset_gets_negative_evidence():
    items = [
        Observation(ObservationKind.ENDPOINT, "https://example.test/static/app.abc123.js", "httpx", "r1"),
    ]
    hypotheses = build_hypotheses(items)
    for hypothesis in hypotheses:
        assert hypothesis.negative_evidence


def test_authorized_fixture_comparison_is_research_hypothesis(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text('{"status":200,"headers":{"content-type":"application/json"},"body":"{\\"id\\":1}","schema_keys":["id"]}')
    second.write_text('{"status":200,"headers":{"content-type":"application/json"},"body":"{\\"id\\":2}","schema_keys":["id"]}')
    result = compare_fixture_files(first, second, "https://example.test/api/projects/1", object_reference_overlap=True)
    assert result.hypothesis.hypothesis_type.value == "authorization"
    assert result.hypothesis.status == "candidate"
    assert result.signal_strength > 0
