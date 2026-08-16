"""Workflow and state-transition intelligence.

ReconForge models related operations so researchers can inspect ordering,
identity/role boundaries, and state transitions manually. No transition is
classified as a confirmed vulnerability.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re


_ACTIONS = {
    "create": {"create", "new", "add"},
    "read": {"get", "list", "view", "fetch"},
    "update": {"update", "edit", "modify", "set", "change"},
    "delete": {"delete", "remove", "destroy", "revoke"},
    "invite": {"invite", "invitation"},
    "accept": {"accept", "approve", "confirm"},
    "share": {"share", "publish", "export"},
}


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    subject: str
    action: str
    order_hint: int


@dataclass(frozen=True, slots=True)
class Workflow:
    key: str
    steps: tuple[WorkflowStep, ...]
    rationale: str

    def transition_hypotheses(self) -> tuple[tuple[str, str], ...]:
        actions = {step.action for step in self.steps}
        pairs: list[tuple[str, str]] = []
        if "accept" in actions and "invite" not in actions:
            pairs.append(("accept", "invite"))
        if "share" in actions and "create" not in actions:
            pairs.append(("share", "create"))
        if "delete" in actions and "create" not in actions:
            pairs.append(("delete", "create"))
        return tuple(pairs)


def extract_workflows(endpoints: list[tuple[str, str]]) -> list[Workflow]:
    groups: dict[str, list[WorkflowStep]] = defaultdict(list)
    for subject, method in endpoints:
        tokens = set(re.findall(r"[a-z0-9]+", subject.lower()))
        family = _family(tokens)
        if not family:
            continue
        action = _action(tokens, method)
        groups[family].append(WorkflowStep(subject, action, _order(action)))

    workflows: list[Workflow] = []
    for family, steps in groups.items():
        unique = {(step.subject, step.action): step for step in steps}
        ordered = tuple(sorted(unique.values(), key=lambda item: (item.order_hint, item.subject)))
        if len(ordered) >= 2:
            workflows.append(Workflow(family, ordered, f"{len(ordered)} related operations share the {family} workflow family"))
    return workflows


def _family(tokens: set[str]) -> str | None:
    families = (
        ("invitation", {"invite", "invitation", "invitations", "membership", "member"}),
        ("file", {"file", "files", "upload", "download", "attachment", "export"}),
        ("billing", {"billing", "payment", "invoice", "subscription", "checkout"}),
        ("account", {"account", "user", "profile", "session"}),
        ("team", {"team", "organization", "org", "member"}),
    )
    for name, needles in families:
        if tokens & needles:
            return name
    return None


def _action(tokens: set[str], method: str) -> str:
    method = method.upper()
    if method == "DELETE":
        return "delete"
    if method == "POST":
        for action, needles in _ACTIONS.items():
            if tokens & needles:
                return action
        return "create"
    if method in {"PUT", "PATCH"}:
        return "update"
    for action, needles in _ACTIONS.items():
        if tokens & needles:
            return action
    return "read"


def _order(action: str) -> int:
    return {"read": 0, "create": 10, "invite": 20, "accept": 30, "update": 40, "share": 50, "delete": 60}.get(action, 25)
