"""Capability-driven orchestration primitives."""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.adapters.contracts import DEFAULT_ADAPTERS, AdapterSpec
from reconforge.models import Target


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    allow_active: bool = False
    max_concurrency: int = 4
    rate_limit_per_second: float = 5.0
    timeout_seconds: float = 60.0
    excluded_capabilities: frozenset[str] = frozenset()

    def permits(self, spec: AdapterSpec) -> bool:
        if spec.requires_scope is True and not spec.safe_default and not self.allow_active:
            return False
        if spec.passive:
            return True
        return self.allow_active


def select_adapters(target: Target, requested_capabilities: frozenset[str], policy: ExecutionPolicy) -> list[AdapterSpec]:
    if not target.in_scope:
        return []
    selected: list[AdapterSpec] = []
    for spec in DEFAULT_ADAPTERS:
        if not policy.permits(spec):
            continue
        if requested_capabilities and not (spec.capabilities & requested_capabilities):
            continue
        if spec.capabilities & policy.excluded_capabilities:
            continue
        selected.append(spec)
    return selected
