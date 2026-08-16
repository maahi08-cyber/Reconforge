"""SQLite persistence boundary for observations and research state."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from reconforge.models import Observation


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_hash TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    source TEXT NOT NULL,
    run_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    attributes_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_subject ON observations(subject);
CREATE INDEX IF NOT EXISTS idx_observations_kind ON observations(kind);
CREATE INDEX IF NOT EXISTS idx_observations_source ON observations(source);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    target TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def add_observation(self, observation: Observation) -> bool:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO observations
               (evidence_hash, kind, subject, source, run_id, observed_at, attributes_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                observation.evidence_hash,
                observation.kind.value,
                observation.subject,
                observation.source,
                observation.run_id,
                observation.observed_at.isoformat(),
                json.dumps(observation.attributes, sort_keys=True, default=str),
            ),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def add_observations(self, observations: Iterable[Observation]) -> int:
        inserted = sum(self.add_observation(item) for item in observations)
        return inserted

    def observations_for_subject(self, subject: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM observations WHERE subject = ? ORDER BY observed_at",
            (subject,),
        ))
