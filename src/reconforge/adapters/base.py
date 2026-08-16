"""Adapter contracts for ReconForge collection sensors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, Sequence

from reconforge.models import Observation, Target


@dataclass(frozen=True, slots=True)
class RunContext:
    run_id: str
    target: Target
    rate_limit: float | None = None
    concurrency: int = 4
    tags: tuple[str, ...] = field(default_factory=tuple)


class Adapter(Protocol):
    name: str
    version: str

    def discover(self, context: RunContext) -> Sequence[Observation]: ...


@dataclass(frozen=True, slots=True)
class AdapterMetadata:
    name: str
    version: str
    capabilities: tuple[str, ...]
    cost: str
    active: bool
