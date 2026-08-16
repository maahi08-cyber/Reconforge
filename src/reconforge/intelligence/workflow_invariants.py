"""Conservative workflow invariant checks for research prioritization.

These checks describe suspicious state/sequence relationships. They do not
claim exploitation or authorization failure.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WorkflowInvariant:
    name: str
    confidence: float
    rationale: tuple[str, ...]


def infer_invariants(states: list[str], operations: list[str]) -> list[WorkflowInvariant]:
    normalized_states = [state.lower() for state in states]
    normalized_ops = [operation.lower() for operation in operations]
    results: list[WorkflowInvariant] = []

    if "invite" in normalized_ops and any(item in normalized_ops for item in ("accept", "join")):
        results.append(WorkflowInvariant(
            "invitation_lifecycle",
            0.82,
            ("invite and acceptance operations are both present", "lifecycle transition is worth boundary review"),
        ))

    if "create" in normalized_ops and "delete" in normalized_ops:
        results.append(WorkflowInvariant(
            "resource_lifecycle",
            0.78,
            ("create and delete operations form a lifecycle", "review ownership and state transitions between them"),
        ))

    if any(item in normalized_ops for item in ("share", "publish")) and any(item in normalized_ops for item in ("revoke", "unshare")):
        results.append(WorkflowInvariant(
            "sharing_lifecycle",
            0.80,
            ("sharing and revocation operations coexist", "review transition ordering and authorization boundaries"),
        ))

    if "pending" in normalized_states and any(item in normalized_states for item in ("active", "accepted")):
        results.append(WorkflowInvariant(
            "state_transition_boundary",
            0.74,
            ("pending and active/accepted states are represented", "review who can trigger or bypass the transition"),
        ))

    if "draft" in normalized_states and any(item in normalized_states for item in ("published", "live")):
        results.append(WorkflowInvariant(
            "publication_boundary",
            0.76,
            ("draft and published states coexist", "review state-changing authorization and ownership"),
        ))

    return results
