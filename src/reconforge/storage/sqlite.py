"""SQLite persistence for ReconForge state."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from reconforge.models import Hypothesis, Observation
from reconforge.storage.audit import append_event, init_audit_schema

SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target, started_at DESC);
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    evidence_hash TEXT NOT NULL UNIQUE,
    attributes_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_subject ON observations(subject);
CREATE INDEX IF NOT EXISTS idx_observations_source ON observations(source);
CREATE INDEX IF NOT EXISTS idx_observations_kind ON observations(kind);
CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    hypothesis_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    novelty REAL NOT NULL,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(subject, hypothesis_type)
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_queue ON hypotheses(status, confidence DESC, novelty DESC);
CREATE TABLE IF NOT EXISTS calibration_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    signal TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at TEXT NOT NULL,
    run_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_calibration_signal ON calibration_events(signal, created_at);
"""


class SQLiteStore:
    """Durable local persistence with auditability and calibration history."""

    def __init__(self, path: str | Path = "reconforge.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(SCHEMA)
        init_audit_schema(self._connection)
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def start_run(self, run_id: str, target: str) -> None:
        self._connection.execute(
            "INSERT INTO runs(run_id, target, started_at, status) VALUES (?, ?, ?, ?)",
            (run_id, target, datetime.now(timezone.utc).isoformat(), "running"),
        )
        self._connection.commit()
        append_event(self._connection, run_id, "run.started", payload={"target": target})

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        self._connection.execute(
            "UPDATE runs SET finished_at = ?, status = ? WHERE run_id = ?",
            (datetime.now(timezone.utc).isoformat(), status, run_id),
        )
        self._connection.commit()
        append_event(self._connection, run_id, "run.finished", payload={"status": status})

    def record_event(self, run_id: str, event_type: str, **payload: object) -> None:
        append_event(self._connection, run_id, event_type, payload=payload)

    def add_observation(self, item: Observation) -> bool:
        cursor = self._connection.execute(
            """INSERT OR IGNORE INTO observations
            (observation_id, run_id, kind, subject, source, observed_at, evidence_hash, attributes_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                item.evidence_hash[:32], item.run_id, item.kind.value, item.subject,
                item.source, item.observed_at.isoformat(), item.evidence_hash,
                json.dumps(item.attributes, sort_keys=True, default=str),
            ),
        )
        self._connection.commit()
        return cursor.rowcount == 1

    def add_observations(self, items: Iterable[Observation]) -> int:
        return sum(int(self.add_observation(item)) for item in items)

    def observations_for_subject(self, subject: str) -> list[sqlite3.Row]:
        return list(self._connection.execute(
            "SELECT * FROM observations WHERE subject = ? ORDER BY observed_at DESC", (subject,)
        ))

    def record_calibration(self, signal: str, outcome: str, *, run_id: str | None = None) -> None:
        self._connection.execute(
            "INSERT INTO calibration_events(signal, outcome, created_at, run_id) VALUES (?, ?, ?, ?)",
            (signal, outcome, datetime.now(timezone.utc).isoformat(), run_id),
        )
        self._connection.commit()
        if run_id:
            append_event(self._connection, run_id, "calibration.recorded", payload={"signal": signal, "outcome": outcome})

    def calibration_snapshot(self) -> dict[str, dict[str, int]]:
        rows = self._connection.execute(
            "SELECT signal, outcome, COUNT(*) AS count FROM calibration_events GROUP BY signal, outcome"
        )
        result: dict[str, dict[str, int]] = {}
        for row in rows:
            result.setdefault(row["signal"], {})[row["outcome"]] = int(row["count"])
        return result

    def upsert_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._connection.execute(
            """INSERT INTO hypotheses(subject, hypothesis_type, confidence, novelty, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject, hypothesis_type) DO UPDATE SET
              confidence = excluded.confidence,
              novelty = excluded.novelty,
              status = excluded.status,
              updated_at = excluded.updated_at""",
            (hypothesis.subject, hypothesis.hypothesis_type.value, hypothesis.confidence,
             hypothesis.novelty, hypothesis.status, datetime.now(timezone.utc).isoformat()),
        )
        self._connection.commit()

    def hunter_queue(self, limit: int = 20) -> list[sqlite3.Row]:
        return list(self._connection.execute(
            """SELECT * FROM hypotheses WHERE status = 'candidate'
            ORDER BY confidence DESC, novelty DESC LIMIT ?""",
            (max(1, min(limit, 1000)),),
        ))
