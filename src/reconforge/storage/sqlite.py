"""SQLite persistence boundary for ReconForge state."""

from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    attributes_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_observations_subject ON observations(subject);
CREATE INDEX IF NOT EXISTS idx_observations_source ON observations(source);
CREATE INDEX IF NOT EXISTS idx_observations_evidence_hash ON observations(evidence_hash);
"""


class SQLiteStore:
    """Small dependency-free persistence layer suitable for local research."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path)
        self._connection.executescript(SCHEMA)
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()
