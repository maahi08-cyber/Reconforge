"""Small distributed-worker seam for future enterprise execution.

The core keeps jobs declarative and idempotent. Transport is deliberately
separate so Redis, a queue service, or a local worker pool can be plugged in
without changing evidence semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SensorJob:
    run_id: str
    target: str
    sensor: str
    capabilities: frozenset[str] = frozenset()
    attempt: int = 0


@dataclass(frozen=True, slots=True)
class JobResult:
    run_id: str
    sensor: str
    success: bool
    observation_count: int
    error: str | None = None


class JobQueue(Protocol):
    def submit(self, job: SensorJob) -> str: ...
    def claim(self, worker_id: str) -> SensorJob | None: ...
    def complete(self, job: SensorJob, result: JobResult) -> None: ...


class InMemoryJobQueue:
    """Deterministic reference queue used for local development and tests."""

    def __init__(self) -> None:
        self._pending: list[SensorJob] = []
        self._completed: list[tuple[SensorJob, JobResult]] = []

    def submit(self, job: SensorJob) -> str:
        self._pending.append(job)
        return f"{job.run_id}:{job.sensor}:{job.attempt}"

    def claim(self, worker_id: str) -> SensorJob | None:
        del worker_id  # transport implementations may use it for leases.
        return self._pending.pop(0) if self._pending else None

    def complete(self, job: SensorJob, result: JobResult) -> None:
        self._completed.append((job, result))

    @property
    def completed(self) -> tuple[tuple[SensorJob, JobResult], ...]:
        return tuple(self._completed)
