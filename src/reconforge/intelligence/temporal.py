"""Temporal asset intelligence for repeated ReconForge runs."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from collections.abc import Iterable
from enum import StrEnum
from hashlib import sha256


class ChangeKind(StrEnum):
    NEW = "new"
    PERSISTENT = "persistent"
    DISAPPEARED = "disappeared"
    REACTIVATED = "reactivated"


@dataclass(frozen=True, slots=True)
class TemporalChange:
    subject: str
    status: str
    first_seen: datetime | None
    last_seen: datetime | None
    rationale: str
    evidence_delta: float = 0.0


def compare_observations(previous: Iterable[tuple[str, datetime]], current: Iterable[tuple[str, datetime]]) -> list[TemporalChange]:
    before = dict(previous)
    after = dict(current)
    changes: list[TemporalChange] = []
    for subject in sorted(set(before) | set(after)):
        if subject not in before:
            changes.append(TemporalChange(subject, ChangeKind.NEW.value, None, after[subject], "first observed in current run", 1.0))
        elif subject not in after:
            changes.append(TemporalChange(subject, ChangeKind.DISAPPEARED.value, before[subject], None, "previously observed but absent from current run", -0.5))
        elif before[subject] != after[subject]:
            changes.append(TemporalChange(subject, ChangeKind.PERSISTENT.value, before[subject], after[subject], "observed across multiple runs", 0.1))
    return changes


def identity(value: str) -> str:
    return sha256(value.strip().lower().encode("utf-8")).hexdigest()[:24]


def is_recent(timestamp: datetime, reference: datetime, max_age_days: int = 7) -> bool:
    age = reference - timestamp
    return age.total_seconds() >= 0 and age.days <= max_age_days
