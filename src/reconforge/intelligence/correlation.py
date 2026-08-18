"""Canonical evidence correlation and negative-evidence helpers.

This layer combines observations without declaring vulnerabilities.  It keeps
positive and negative evidence explicit so ranking can stay conservative and
explainable.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from reconforge.models import EvidenceContribution, Observation


@dataclass(frozen=True, slots=True)
class CorrelationSummary:
    source_count: int
    family_count: int
    source_families: frozenset[str]
    duplicate_sources: int


def summarize(items: list[Observation]) -> CorrelationSummary:
    sources = {item.source for item in items if item.source}
    families = {_source_family(source) for source in sources}
    return CorrelationSummary(
        source_count=len(sources),
        family_count=len(families),
        source_families=frozenset(families),
        duplicate_sources=max(0, len(items) - len(sources)),
    )


def corroboration_contributions(items: list[Observation]) -> list[EvidenceContribution]:
    """Return at most one corroboration contribution per independent source family."""
    selected: list[EvidenceContribution] = []
    seen_families: set[str] = set()
    for item in items:
        family = _source_family(item.source)
        if family in seen_families:
            continue
        seen_families.add(family)
        selected.append(
            EvidenceContribution(
                item.evidence_hash,
                f"independent {family} evidence family corroborates the subject",
                0.30,
            )
        )
    return selected


def negative_evidence(items: list[Observation]) -> list[EvidenceContribution]:
    """Generate conservative suppression signals from clearly low-value surfaces."""
    results: list[EvidenceContribution] = []
    for item in items:
        parts = urlsplit(item.subject)
        path = parts.path.lower()
        if path.endswith(('.js', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2')):
            results.append(EvidenceContribution(item.evidence_hash, "static asset surface provides weak direct security-research signal", 0.25))
        elif path.rstrip('/').endswith(('/health', '/healthz', '/ready', '/readiness', '/live', '/version')):
            results.append(EvidenceContribution(item.evidence_hash, "operational endpoint is generally low-value without additional evidence", 0.20))
    return results


def _source_family(source: str) -> str:
    name = source.lower()
    if name in {"subfinder", "amass", "crt", "securitytrails", "censys"}:
        return "asset-passive"
    if name in {"gau", "waybackurls", "urlscan", "history"}:
        return "historical"
    if name in {"httpx", "katana", "nmap", "naabu", "dnsx"}:
        return "active"
    if name in {"nuclei"}:
        return "detection"
    if name in {"javascript", "js-analyzer", "jsintel"}:
        return "client"
    return name
