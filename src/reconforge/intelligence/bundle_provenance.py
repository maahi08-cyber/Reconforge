"""Client-bundle and source-map provenance intelligence."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urljoin


@dataclass(frozen=True, slots=True)
class BundleProvenance:
    bundle_url: str
    content_hash: str
    source_map_url: str | None
    mapped_source_count: int
    confidence: float
    rationale: str


def analyze_bundle(bundle_url: str, content: bytes, *, base_url: str | None = None, source_map_url: str | None = None, mapped_sources: list[str] | None = None) -> BundleProvenance:
    sources = list(mapped_sources or [])
    resolved_map = urljoin(base_url or bundle_url, source_map_url) if source_map_url else None
    confidence = 0.78
    reasons = ["bundle content has a stable content hash"]
    if resolved_map:
        confidence += 0.12
        reasons.append("source map reference resolves to a concrete URL")
    if sources:
        confidence += 0.08
        reasons.append("source map exposes original source references")
    return BundleProvenance(bundle_url, sha256(content).hexdigest(), resolved_map, len(sources), min(1.0, confidence), "; ".join(reasons))
