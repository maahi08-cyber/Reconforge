"""Scope and target primitives."""

from dataclasses import dataclass
from enum import StrEnum


class TargetKind(StrEnum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"


@dataclass(frozen=True, slots=True)
class Target:
    value: str
    kind: TargetKind
    in_scope: bool = True

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("target value cannot be empty")
