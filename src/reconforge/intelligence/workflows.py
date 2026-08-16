"""Infer application workflows from endpoint observations."""
from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict

from reconforge.intelligence.classify import classify_url


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    endpoint: str
    method: str
    action: str


@dataclass(frozen=True, slots=True)
class Workflow:
    key: str
    steps: tuple[WorkflowStep, ...]
    confidence: float


def infer_workflows(endpoints: list[tuple[str, str]]) -> list[Workflow]:
    groups: dict[str, list[WorkflowStep]] = defaultdict(list)
    action_terms = {
        "create": "create", "new": "create", "update": "modify", "edit": "modify",
        "delete": "delete", "remove": "delete", "invite": "invite", "accept": "accept",
        "approve": "approve", "export": "export", "upload": "upload", "download": "download",
        "share": "share", "transfer": "transfer", "role": "role_change", "billing": "billing",
        "checkout": "checkout", "cancel": "cancel",
    }
    for url, method in endpoints:
        path = url.lower()
        action = next((action for term, action in action_terms.items() if term in path), "access")
        features = classify_url(url, method)
        if features.is_account_or_team or features.is_file_operation or features.is_billing or features.is_invitation:
            family = "account-team" if features.is_account_or_team else "file" if features.is_file_operation else "billing" if features.is_billing else "invitation"
            groups[family].append(WorkflowStep(url, method.upper(), action))

    workflows: list[Workflow] = []
    for family, steps in groups.items():
        unique = tuple(sorted({(s.endpoint, s.method, s.action): s for s in steps}.values(), key=lambda x: x.endpoint))
        if len(unique) >= 2:
            confidence = min(0.95, 0.45 + 0.08 * len(unique))
            workflows.append(Workflow(family, unique, confidence))
    return sorted(workflows, key=lambda item: item.confidence, reverse=True)
