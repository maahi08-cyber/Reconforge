"""Graph-backed asset intelligence for ReconForge."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from collections import defaultdict

from reconforge.models import Observation


class NodeKind(StrEnum):
    TARGET = "target"
    HOST = "host"
    URL = "url"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    JAVASCRIPT = "javascript"
    OBJECT = "object"
    WORKFLOW = "workflow"


@dataclass(frozen=True, slots=True)
class Node:
    key: str
    kind: NodeKind
    label: str


@dataclass(frozen=True, slots=True)
class Edge:
    source: str
    relation: str
    target: str


class AssetGraph:
    """In-memory graph that merges observations by stable node identity."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: set[Edge] = set()
        self.observations_by_node: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node: Node) -> None:
        self.nodes[node.key] = node

    def add_edge(self, source: str, relation: str, target: str) -> None:
        self.edges.add(Edge(source, relation, target))

    def ingest(self, observation: Observation) -> str:
        key = f"{observation.kind.value}:{observation.subject}"
        kind = _kind_for_observation(observation)
        self.add_node(Node(key, kind, observation.subject))
        self.observations_by_node[key].append(observation.evidence_hash)
        parent = observation.attributes.get("parent")
        if parent:
            parent_key = str(parent)
            if parent_key in self.nodes:
                self.add_edge(parent_key, observation.kind.value, key)
        related = observation.attributes.get("related") or []
        for value in related:
            related_key = str(value)
            if related_key in self.nodes:
                self.add_edge(key, "related", related_key)
        return key

    def neighbors(self, key: str) -> list[Node]:
        keys = {edge.target for edge in self.edges if edge.source == key}
        keys.update(edge.source for edge in self.edges if edge.target == key)
        return [self.nodes[item] for item in keys if item in self.nodes]


def _kind_for_observation(observation: Observation) -> NodeKind:
    mapping = {
        "asset": NodeKind.HOST,
        "dns": NodeKind.HOST,
        "http": NodeKind.URL,
        "endpoint": NodeKind.ENDPOINT,
        "parameter": NodeKind.PARAMETER,
        "javascript": NodeKind.JAVASCRIPT,
        "technology": NodeKind.TECHNOLOGY,
        "historical": NodeKind.URL,
        "authentication": NodeKind.OBJECT,
    }
    return mapping.get(observation.kind.value, NodeKind.OBJECT)
