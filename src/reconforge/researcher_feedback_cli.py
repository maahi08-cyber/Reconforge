"""Researcher feedback persistence helpers for the CLI."""
from __future__ import annotations

from reconforge.storage.sqlite import SQLiteStore


ALLOWED_OUTCOMES = ("useful", "validated", "noisy", "duplicate", "invalid")


def record_feedback(db_path: str, signal: str, outcome: str, run_id: str | None = None) -> None:
    if not signal.strip():
        raise ValueError("signal cannot be empty")
    if outcome not in ALLOWED_OUTCOMES:
        raise ValueError(f"outcome must be one of: {', '.join(ALLOWED_OUTCOMES)}")
    store = SQLiteStore(db_path)
    try:
        store.record_calibration(signal.strip(), outcome, run_id=run_id)
    finally:
        store.close()
