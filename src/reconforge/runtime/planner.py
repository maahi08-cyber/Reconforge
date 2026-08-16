"""Policy-aware sensor planning for ReconForge.

The planner selects sensors by capability, cost, and risk. It does not execute
anything; it produces a reproducible plan for the orchestrator and audit log.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from reconforge.adapters.contracts import AdapterSpec


@dataclass(frozen=True, slots=True)
class PlanPolicy:
    allow_active: bool = False
    max_cost: str = "medium"
    max_risk: str = "low"
    required_capabilities: frozenset[str] = frozenset()


_COST = {"low": 1, "medium": 2, "high": 3}
_RISK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True, slots=True)
class PlannedSensor:
    name: str
    capabilities: frozenset[str]
    reason: str


def plan(specs: Iterable[AdapterSpec], policy: PlanPolicy) -> tuple[PlannedSensor, ...]:
    selected: list[PlannedSensor] = []
    for spec in specs:
        if not policy.allow_active and not spec.passive:
            continue
        if _COST.get(spec.cost, 99) > _COST.get(policy.max_cost, 0):
            continue
        if _RISK.get(spec.risk, 99) > _RISK.get(policy.max_risk, 0):
            continue
        if policy.required_capabilities and not (spec.capabilities & policy.required_capabilities):
            continue
        selected.append(PlannedSensor(spec.name, spec.capabilities, _reason(spec)))
    return tuple(selected)


def _reason(spec: AdapterSpec) -> str:
    if spec.passive:
        return "passive sensor selected within default policy"
    return f"active sensor selected explicitly within cost={spec.cost}, risk={spec.risk} policy"
