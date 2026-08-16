"""Portable evidence-graph export for researcher review and downstream tooling."""
from __future__ import annotations

import json
from pathlib import Path

from reconforge.graph import AssetGraph


def export_graph(graph: AssetGraph, path: str | Path) -> int:
    payload = {
        "nodes": [
            {"key": node.key, "kind": node.kind.value, "label": node.label,
             "evidence": graph.observations_by_node.get(node.key, [])}
            for node in graph.nodes.values()
        ],
        "edges": [
            {"source": edge.source, "relation": edge.relation, "target": edge.target}
            for edge in sorted(graph.edges, key=lambda item: (item.source, item.relation, item.target))
        ],
    }
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return len(payload["nodes"])
