"""Evidence-aware sensor planning.

The planner prefers sensors that can add genuinely new evidence. Tool execution
remains policy-gated; the planner only recommends candidates and does not bypass
scope or active-testing controls.
"""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.adapters.contracts import AdapterSpec
from reconforge.intelligence.calibration import CalibrationModel


@dataclass(frozen=True, slots=True)
class SensorPlan:
    name: str
    capability: str
    priority: float
    rationale: str


def plan_sensors(specs: list[AdapterSpec], observed_capabilities: set[str], *, calibration: CalibrationModel | None = None) -> list[SensorPlan]:
    plans: list[SensorPlan] = []
    calibration = calibration or CalibrationModel()
    for spec in specs:
        novel = [cap for cap in spec.capabilities if cap not in observed_capabilities]
        if not novel:
            continue
        risk_penalty = 0.20 if spec.risk == "medium" else 0.0
        cost_penalty = 0.12 if spec.cost == "high" else 0.06 if spec.cost == "medium" else 0.0
        source_weight = calibration.weight(spec.name)
        priority = max(0.0, min(1.0, (0.55 + 0.15 * len(novel) - risk_penalty - cost_penalty) * source_weight))
        plans.append(SensorPlan(spec.name, novel[0], priority, f"adds {len(novel)} unseen capabilities; policy cost={spec.cost}, risk={spec.risk}"))
    return sorted(plans, key=lambda item: item.priority, reverse=True)
