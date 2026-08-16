"""Append-only audit events for enterprise ReconForge runs.

The audit trail records orchestration decisions and outcomes without storing
secrets or full request bodies. It is intended for reproducibility and review.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def init_audit_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_run ON audit_events(run_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type, created_at);
        """
    )


def append_event(
    connection: sqlite3.Connection,
    run_id: str,
    event_type: str,
    *,
    actor: str = "reconforge",
    payload: dict[str, Any] | None = None,
) -> None:
    safe_payload = dict(payload or {})
    for key in list(safe_payload):
        if key.lower() in {"secret", "token", "password", "authorization", "api_key", "apikey"}:
            safe_payload[key] = "<redacted>"
    connection.execute(
        "INSERT INTO audit_events(run_id, event_type, actor, created_at, payload_json) VALUES (?, ?, ?, ?, ?)",
        (run_id, event_type, actor, datetime.now(timezone.utc).isoformat(), json.dumps(safe_payload, sort_keys=True, default=str)),
    )
    connection.commit()
