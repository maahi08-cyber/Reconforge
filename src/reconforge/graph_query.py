"""Read-only queries over the ReconForge evidence graph.

Queries return evidence-oriented relationships rather than vulnerability claims.
"""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.graph import AssetGraph, Node


@dataclass(frozen=True, slots=True)
class GraphResult:
    nodes: tuple[Node, ...]
    rationale: str


def find_security_surface(graph: AssetGraph, *, kind: str | None = None, contains: str | None = None) -> GraphResult:
    nodes = list(graph.nodes.values())
    if kind:
        nodes = [node for node in nodes if node.kind.value == kind or str(node.kind) == kind]
    if contains:
        needle = contains.lower()
        nodes = [node for node in nodes if needle in node.label.lower()]
    nodes.sort(key=lambda node: (node.kind.value, node.label))
    return GraphResult(tuple(nodes), f"Returned {len(nodes)} graph nodes matching the requested evidence filters.")


def neighborhood(graph: AssetGraph, key: str, *, depth: int = 1) -> GraphResult:
    if key not in graph.nodes:
        return GraphResult((), "node identity not present in graph")
    frontier = {key}
    seen = {key}
    for _ in range(max(0, depth)):
        next_frontier: set[str] = set()
        for node_key in frontier:
            for edge in graph.edges:
                if edge.source == node_key and edge.target not in seen:
                    next_frontier.add(edge.target)
                elif edge.target == node_key and edge.source not in seen:
                    next_frontier.add(edge.source)
        seen.update(next_frontier)
        frontier = next_frontier
    nodes = tuple(graph.nodes[item] for item in sorted(seen) if item in graph.nodes)
    return GraphResult(nodes, f"Evidence neighborhood expanded to depth {max(0, depth)}.")
