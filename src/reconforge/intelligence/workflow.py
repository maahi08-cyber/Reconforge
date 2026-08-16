"""Workflow and state-transition intelligence.

ReconForge does not attempt to exploit workflows. It models related operations
so a researcher can inspect ordering, role, and state boundaries manually.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict
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


def extract_workflows(endpoints: list[tuple[str, str]]) -> list[Workflow]:
    """Group endpoint paths into conservative workflow families."""
    groups: dict[str, list[WorkflowStep]] = defaultdict(list)
    for subject, method in endpoints:
        lowered = subject.lower()
        tokens = set(re.findall(r"[a-z0-9]+", lowered))
        action = _action(tokens, method)
        family = _family(tokens)
        if not family:
            continue
        groups[family].append(WorkflowStep(subject, action, _order(action)))

    workflows: list[Workflow] = []
    for family, steps in groups.items():
        ordered = tuple(sorted({(step.subject, step.action): step for step in steps}.values(), key=lambda item: (item.order_hint, item.subject)))
        if len(ordered) < 2:
            continue
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
    if method.upper() in {"DELETE"}:
        return "delete"
    if method.upper() in {"POST"}:
        for action, needles in _ACTIONS.items():
            if tokens & needles:
                return action
        return "create"
    if method.upper() in {"PUT", "PATCH"}:
        return "update"
    for action, needles in _ACTIONS.items():
        if tokens & needles:
            return action
    return "read"


def _order(action: str) -> int:
    return {"read": 0, "create": 10, "invite": 20, "accept": 30, "update": 40, "share": 50, "delete": 60}.get(action, 25)
