from reconforge.intelligence.correlation import corroboration_contributions, negative_evidence, summarize
from reconforge.models import Observation, ObservationKind


def test_correlation_counts_independent_source_families():
    items = [
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "httpx", "run"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "katana", "run"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "javascript", "run"),
    ]
    summary = summarize(items)
    assert summary.source_count == 3
    assert summary.family_count == 3
    assert len(corroboration_contributions(items)) == 3


def test_correlation_deduplicates_same_family():
    items = [
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "httpx", "run"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "httpx", "run"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/api/users/1", "katana", "run"),
    ]
    summary = summarize(items)
    assert summary.family_count == 2
    assert len(corroboration_contributions(items)) == 2


def test_negative_evidence_marks_static_and_operational_surfaces():
    items = [
        Observation(ObservationKind.ENDPOINT, "https://example.test/static/app.12345678.js", "javascript", "run"),
        Observation(ObservationKind.ENDPOINT, "https://example.test/health", "httpx", "run"),
    ]
    findings = negative_evidence(items)
    assert len(findings) == 2
