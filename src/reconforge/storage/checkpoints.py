"""Durable checkpoints for resumable reconnaissance runs."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    detail TEXT,
    PRIMARY KEY (run_id, stage)
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_status ON checkpoints(status, updated_at);
"""


def init_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()


def mark(connection: sqlite3.Connection, run_id: str, stage: str, status: str, *, detail: str | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    connection.execute(
        """INSERT INTO checkpoints(run_id, stage, status, attempts, updated_at, detail)
        VALUES (?, ?, ?, 1, ?, ?)
        ON CONFLICT(run_id, stage) DO UPDATE SET
          status=excluded.status,
          attempts=checkpoints.attempts + 1,
          updated_at=excluded.updated_at,
          detail=excluded.detail""",
        (run_id, stage, status, now, detail),
    )
    connection.commit()


def is_complete(connection: sqlite3.Connection, run_id: str, stage: str) -> bool:
    row = connection.execute(
        "SELECT status FROM checkpoints WHERE run_id = ? AND stage = ?", (run_id, stage)
    ).fetchone()
    return bool(row and row[0] == "completed")
