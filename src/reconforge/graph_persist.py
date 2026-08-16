"""Persistent SQLite-backed graph index for long-lived ReconForge projects."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass


SCHEMA = """
CREATE TABLE IF NOT EXISTS graph_nodes (
    node_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS graph_edges (
    source_key TEXT NOT NULL,
    relation TEXT NOT NULL,
    target_key TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    PRIMARY KEY (source_key, relation, target_key)
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_key, relation);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_key, relation);
"""


@dataclass(frozen=True, slots=True)
class GraphNode:
    key: str
    kind: str
    label: str


class PersistentGraph:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def add_node(self, node: GraphNode, attributes_json: str = "{}") -> None:
        self.connection.execute(
            "INSERT INTO graph_nodes(node_key, kind, label, attributes_json) VALUES (?, ?, ?, ?) ON CONFLICT(node_key) DO UPDATE SET label=excluded.label, attributes_json=excluded.attributes_json",
            (node.key, node.kind, node.label, attributes_json),
        )
        self.connection.commit()

    def add_edge(self, source: str, relation: str, target: str, confidence: float = 1.0) -> None:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        self.connection.execute(
            "INSERT OR REPLACE INTO graph_edges(source_key, relation, target_key, confidence) VALUES (?, ?, ?, ?)",
            (source, relation, target, confidence),
        )
        self.connection.commit()

    def neighbors(self, node_key: str, relation: str | None = None) -> list[tuple[str, str, float]]:
        if relation:
            rows = self.connection.execute("SELECT relation, target_key, confidence FROM graph_edges WHERE source_key = ? AND relation = ?", (node_key, relation))
        else:
            rows = self.connection.execute("SELECT relation, target_key, confidence FROM graph_edges WHERE source_key = ?", (node_key,))
        return [(row[0], row[1], float(row[2])) for row in rows]
