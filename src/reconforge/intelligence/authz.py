"""Authorization-context modeling for explicitly authorized research."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    ANONYMOUS = "anonymous"
    USER = "user"
    MEMBER = "member"
    ADMIN = "admin"
    OWNER = "owner"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class IdentityContext:
    name: str
    role: Role
    tenant: str | None = None
    account: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationSignal:
    endpoint: str
    stronger_role: Role
    weaker_role: Role
    shared_object_reference: bool
    response_difference: bool
    signal_strength: float
    rationale: tuple[str, ...]


def compare_contexts(endpoint: str, stronger: IdentityContext, weaker: IdentityContext, *, shared_object_reference: bool, response_difference: bool) -> AuthorizationSignal:
    reasons: list[str] = []
    score = 0.20
    if stronger.role != weaker.role:
        reasons.append("roles differ between explicitly authorized contexts")
        score += 0.20
    if stronger.tenant and weaker.tenant and stronger.tenant != weaker.tenant:
        reasons.append("tenant boundary differs")
        score += 0.20
    if shared_object_reference:
        reasons.append("same object reference observed across contexts")
        score += 0.25
    if response_difference:
        reasons.append("response behavior differs across contexts")
        score += 0.15
    return AuthorizationSignal(endpoint, stronger.role, weaker.role, shared_object_reference, response_difference, min(score, 1.0), tuple(reasons))
