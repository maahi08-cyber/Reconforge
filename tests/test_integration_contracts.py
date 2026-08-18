from reconforge.graph import AssetGraph
from reconforge.graph_query import find_security_surface, neighborhood
from reconforge.intelligence.hunter_queue import rank_hypotheses
from reconforge.models import EvidenceContribution, Hypothesis, HypothesisType, Observation, ObservationKind
from reconforge.release import evaluate


def test_hunter_queue_priority_prefers_more_evidence():
    weak = Hypothesis("https://example.test/api/a", HypothesisType.API, confidence=80.0)
    strong = Hypothesis("https://example.test/api/b", HypothesisType.API, confidence=80.0)
    strong.contributions.extend([
        EvidenceContribution("e1", "source one", 0.4),
        EvidenceContribution("e2", "source two", 0.4),
        EvidenceContribution("e3", "source three", 0.4),
    ])
    ranked = rank_hypotheses([weak, strong], limit=2)
    assert ranked[0].hypothesis.subject == strong.subject
    assert ranked[0].priority > ranked[1].priority


def test_graph_query_uses_asset_graph():
    graph = AssetGraph()
    host = Observation(ObservationKind.ASSET, "example.test", "fixture", "run")
    endpoint = Observation(
        ObservationKind.ENDPOINT,
        "https://example.test/api/users",
        "fixture",
        "run",
        {"parent": host.evidence_hash},
    )
    graph.ingest(host)
    graph.ingest(endpoint)
    surface = find_security_surface(graph, kind="endpoint")
    assert [node.label for node in surface.nodes] == [endpoint.subject]
    node_key = f"endpoint:{endpoint.subject}"
    result = neighborhood(graph, node_key, depth=1)
    assert any(node.label == host.subject for node in result.nodes)


def test_release_gate_requires_empirical_inputs(tmp_path):
    report = evaluate()
    assert not report.ready
    assert any(gate.name == "benchmark-corpus" and not gate.passed for gate in report.gates)
    assert any(gate.name == "regression-corpus" and not gate.passed for gate in report.gates)
