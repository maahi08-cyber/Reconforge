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
    "invite": {"invite", "invitation", "invitations"},
    "accept": {"accept", "approve", "confirm", "join"},
    "share": {"share", "export"},
    "publish": {"publish", "published", "release", "release-to-production"},
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
        if "publish" in actions and not ({"create", "update"} & actions):
            pairs.append(("publish", "create_or_update"))
        if "share" in actions and "delete" not in actions:
            pairs.append(("share", "revoke_or_remove") )
        if "invite" in actions and "accept" not in actions:
            pairs.append(("invite", "accept") )
        if "update" in actions and "create" not in actions:
            pairs.append(("update", "create") )
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
        ("invitation", {"invite", "invitation", "invitations", "membership", "member", "members"}),
        ("file", {"file", "files", "upload", "uploads", "download", "downloads", "attachment", "attachments", "export"}),
        ("billing", {"billing", "payment", "payments", "invoice", "invoices", "subscription", "subscriptions", "checkout"}),
        ("account", {"account", "accounts", "user", "users", "profile", "session", "sessions"}),
        ("team", {"team", "teams", "organization", "organizations", "org", "member", "members"}),
        ("content", {"content", "contents", "draft", "drafts", "publish", "published", "release", "releases", "post", "posts"}),
    )
    for name, needles in families:
        if tokens & needles:
            return name
    return None


def _action(tokens: set[str], method: str) -> str:
    method = method.upper()
    for action, needles in _ACTIONS.items():
        if tokens & needles:
            return action
    if method == "DELETE":
        return "delete"
    if method == "POST":
        return "create"
    if method in {"PUT", "PATCH"}:
        return "update"
    return "read"


def _order(action: str) -> int:
    return {
        "read": 0,
        "create": 10,
        "invite": 20,
        "accept": 30,
        "update": 40,
        "share": 50,
        "publish": 55,
        "delete": 60,
    }.get(action, 25)
