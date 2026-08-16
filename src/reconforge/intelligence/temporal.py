"""Temporal asset intelligence for repeated ReconForge runs."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from collections.abc import Iterable


@dataclass(frozen=True, slots=True)
class TemporalChange:
    subject: str
    status: str
    first_seen: datetime | None
    last_seen: datetime | None
    rationale: str


def compare_observations(previous: Iterable[tuple[str, datetime]], current: Iterable[tuple[str, datetime]]) -> list[TemporalChange]:
    before = dict(previous)
    after = dict(current)
    changes: list[TemporalChange] = []
    for subject in sorted(set(before) | set(after)):
        if subject not in before:
            changes.append(TemporalChange(subject, "new", None, after[subject], "first observed in current run"))
        elif subject not in after:
            changes.append(TemporalChange(subject, "disappeared", before[subject], None, "previously observed but absent from current run"))
        elif before[subject] != after[subject]:
            changes.append(TemporalChange(subject, "persistent", before[subject], after[subject], "observed across multiple runs"))
    return changes


def is_recent(timestamp: datetime, reference: datetime, max_age_days: int = 7) -> bool:
    age = reference - timestamp
    return age.total_seconds() >= 0 and age.days <= max_age_days
