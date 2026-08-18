from reconforge.intelligence.auth_research import build_authorization_hypothesis
from reconforge.intelligence.differential import compare_contexts, fingerprint
from reconforge.models import HypothesisType


def test_authorized_differential_produces_research_hypothesis():
    first = fingerprint(200, {"content-type": "application/json"}, b'{"id":1}', {"id"})
    second = fingerprint(200, {"content-type": "application/json"}, b'{"id":2}', {"id"})
    result = compare_contexts(
        "https://example.test/api/projects/123",
        first,
        second,
        object_references_overlap=True,
    )
    hypothesis = build_authorization_hypothesis(result, first, second)
    assert hypothesis.hypothesis_type == HypothesisType.AUTHORIZATION
    assert hypothesis.confidence >= result.signal_strength * 100
    assert hypothesis.status in {"candidate", "monitor"}
    assert hypothesis.contributions
