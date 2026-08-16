from reconforge.intelligence.normalize import normalize_url
from reconforge.intelligence.score import score
from reconforge.models import Observation, ObservationKind


def test_url_normalization_is_deterministic():
    assert normalize_url("HTTPS://Example.COM:443/a/?b=2&a=1#fragment") == "https://example.com/a?a=1&b=2"


def test_observation_gets_stable_evidence_hash():
    first = Observation(ObservationKind.ENDPOINT, "https://example.com/api", "unit", "run-1")
    second = Observation(ObservationKind.ENDPOINT, "https://example.com/api", "unit", "run-1")
    assert first.evidence_hash == second.evidence_hash


def test_score_penalizes_negative_evidence():
    clean = score(exposure=1, relevance=1, corroboration=1, novelty=1)
    noisy = score(exposure=1, relevance=1, corroboration=1, novelty=1, negative_penalty=1)
    assert clean.confidence > noisy.confidence
