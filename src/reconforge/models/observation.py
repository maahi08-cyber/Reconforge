"""Evidence primitives used throughout ReconForge.

Observations are facts collected from an authorized target. They are deliberately
separate from hypotheses so a scanner signal can never masquerade as a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Any


class ObservationKind(StrEnum):
    ASSET = "asset"
    DNS = "dns"
    HTTP = "http"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    JAVASCRIPT = "javascript"
    TECHNOLOGY = "technology"
    HISTORICAL = "historical"
    AUTHENTICATION = "authentication"


@dataclass(frozen=True, slots=True)
class Observation:
    """Immutable, provenance-aware fact from reconnaissance."""

    kind: ObservationKind
    subject: str
    source: str
    run_id: str
    attributes: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_hash: str = ""

    def __post_init__(self) -> None:
        if not self.subject:
            raise ValueError("observation subject cannot be empty")
        if not self.source:
            raise ValueError("observation source cannot be empty")
        if not self.run_id:
            raise ValueError("observation run_id cannot be empty")
        if not self.evidence_hash:
            canonical = f"{self.kind}|{self.subject}|{self.source}|{sorted(self.attributes.items())}"
            object.__setattr__(self, "evidence_hash", sha256(canonical.encode()).hexdigest())
