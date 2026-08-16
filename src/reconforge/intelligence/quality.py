"""Evidence quality and source-independence calculations."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

from reconforge.models import Observation


@dataclass(frozen=True, slots=True)
class EvidenceQuality:
    source_count: int
    family_count: int
    freshness: float
    provenance: float
    duplicate_penalty: float

    @property
    def score(self) -> float:
        raw = (
            0.35 * min(1.0, self.source_count / 3.0)
            + 0.30 * min(1.0, self.family_count / 3.0)
            + 0.20 * self.freshness
            + 0.15 * self.provenance
            - 0.35 * self.duplicate_penalty
        )
        return max(0.0, min(1.0, raw))


def assess(items: Iterable[Observation], *, now_timestamp: float | None = None) -> EvidenceQuality:
    observations = list(items)
    sources = {item.source for item in observations}
    families = {_family(item.source) for item in observations}
    duplicate_penalty = 0.0 if len(observations) <= len({item.evidence_hash for item in observations}) else 1.0
    provenance = 1.0 if all(item.run_id and item.source and item.observed_at for item in observations) else 0.3
    if not observations:
        return EvidenceQuality(0, 0, 0.0, 0.0, 0.0)
    newest = max(item.observed_at.timestamp() for item in observations)
    if now_timestamp is None:
        now_timestamp = newest
    age = max(0.0, now_timestamp - newest)
    freshness = max(0.0, min(1.0, 1.0 - age / (7 * 24 * 3600)))
    return EvidenceQuality(len(sources), len(families), freshness, provenance, duplicate_penalty)


def _family(source: str) -> str:
    name = source.lower()
    if name in {"subfinder", "amass", "crt", "censys", "securitytrails"}:
        return "asset-passive"
    if name in {"gau", "waybackurls", "urlscan"}:
        return "historical"
    if name in {"httpx", "katana", "dnsx", "naabu", "nmap"}:
        return "active"
    if name in {"jsintel", "jsluice", "linkfinder"}:
        return "client-code"
    return name
