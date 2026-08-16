"""Conservative business-logic workflow hypotheses."""
from __future__ import annotations

from dataclasses import dataclass
from reconforge.intelligence.workflow import Workflow


@dataclass(frozen=True, slots=True)
class LogicSignal:
    workflow: str
    signal: str
    strength: float
    rationale: str


def analyze_workflow(workflow: Workflow) -> list[LogicSignal]:
    actions = [step.action for step in workflow.steps]
    seen = set(actions)
    signals: list[LogicSignal] = []

    if "invite" in seen and "accept" in seen:
        signals.append(LogicSignal(workflow.key, "invite_accept_boundary", 0.72,
                                   "invitation and acceptance are represented in the same workflow"))
    if "share" in seen and "delete" in seen:
        signals.append(LogicSignal(workflow.key, "share_delete_boundary", 0.68,
                                   "resource sharing and deletion both affect durable state"))
    if "create" in seen and "delete" in seen:
        signals.append(LogicSignal(workflow.key, "create_delete_lifecycle", 0.62,
                                   "workflow contains both creation and deletion transitions"))
    if len(seen) >= 3:
        signals.append(LogicSignal(workflow.key, "multi_state_workflow", 0.58,
                                   "multiple state-changing operations form a testable lifecycle"))

    return sorted(signals, key=lambda item: item.strength, reverse=True)
