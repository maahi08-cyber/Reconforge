"""Small, dependency-free evidence graph for ReconForge."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from reconforge.models import Observation


@dataclass(frozen=True, slots=True)
class Node:
    key: str
    kind: str
    label: str


@dataclass(frozen=True, slots=True)
class Edge:
    source: str
    relation: str
    target: str
    evidence_id: str


@dataclass(slots=True)
class EvidenceGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], Edge] = field(default_factory=dict)
    observations: dict[str, Observation] = field(default_factory=dict)

    def add_observation(self, observation: Observation) -> str:
        """Store an observation once and return its stable identity."""
        key = observation.evidence_hash
        self.observations.setdefault(key, observation)
        return key

    def add_node(self, kind: str, label: str) -> str:
        canonical = f"{kind}|{label}".strip().lower()
        key = sha256(canonical.encode()).hexdigest()[:32]
        self.nodes.setdefault(key, Node(key, kind, label))
        return key

    def link(self, source: str, relation: str, target: str, evidence_id: str) -> None:
        self.edges.setdefault((source, relation, target), Edge(source, relation, target, evidence_id))

    def corroborating_sources(self, observation_keys: list[str]) -> int:
        """Count distinct evidence sources, preventing duplicate-source inflation."""
        return len({self.observations[key].source for key in observation_keys if key in self.observations})
