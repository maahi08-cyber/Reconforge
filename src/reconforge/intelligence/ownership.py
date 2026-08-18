"""Object/reference and ownership-boundary intelligence.

The module identifies possible ownership boundaries. It never assumes an
identifier proves ownership or that a mismatch proves an authorization flaw.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True, slots=True)
class ObjectReference:
    raw: str
    name: str
    kind: str
    location: str
    confidence: float


@dataclass(frozen=True, slots=True)
class OwnershipSignal:
    endpoint: str
    object_name: str
    identifier_kind: str
    likely_owner_fields: tuple[str, ...]
    confidence: float
    rationale: tuple[str, ...]


_ID_PATTERNS = (
    ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)),
    ("numeric_id", re.compile(r"(?<![A-Za-z0-9])\d{2,18}(?![A-Za-z0-9])")),
    ("hex_id", re.compile(r"(?<![A-Za-z0-9])[0-9a-f]{16,64}(?![A-Za-z0-9])", re.I)),
)

_OWNER_FIELDS = {
    "user_id", "owner_id", "account_id", "org_id", "organization_id",
    "tenant_id", "team_id", "member_id", "created_by", "created_by_id",
}
_RESOURCE_FAMILIES = {
    "users", "accounts", "projects", "teams", "files", "documents",
    "organizations", "orders", "invoices", "members", "workspaces",
}
_STATIC_EXTENSIONS = {"js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2", "ico"}


def extract_object_references(url: str) -> list[ObjectReference]:
    parts = urlsplit(url)
    results: list[ObjectReference] = []
    path_segments = [segment for segment in parts.path.split("/") if segment]
    for name, pattern in _ID_PATTERNS:
        for match in pattern.finditer(parts.path):
            raw = match.group(0)
            before = parts.path[: match.start()].rstrip("/").split("/")
            resource = before[-1] if before else "object"
            confidence = 0.92 if name == "uuid" else 0.72 if name == "numeric_id" else 0.68
            # A filename hash/build number is not an ownership signal.
            if path_segments and "." in path_segments[-1] and path_segments[-1].rsplit(".", 1)[-1].lower() in _STATIC_EXTENSIONS:
                continue
            results.append(ObjectReference(raw, resource, name, "path", confidence))
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered.endswith(("id", "_id", "uuid")) and value:
            results.append(ObjectReference(value, lowered, "parameter_id", "query", 0.82))
    return results


def ownership_signals(url: str, *, response_fields: set[str] | None = None) -> dict[str, object]:
    refs = extract_object_references(url)
    path = urlsplit(url).path.lower()
    fields = {field.lower() for field in (response_fields or set())}
    owner_fields = tuple(sorted(fields & _OWNER_FIELDS))
    resource_names = {segment for segment in path.split("/") if segment}
    resource_context = bool(resource_names & _RESOURCE_FAMILIES)
    reference_confidence = max((ref.confidence for ref in refs), default=0.0)
    named_identity = bool(resource_names & {"users", "accounts", "projects", "teams", "members", "organizations", "org", "workspaces"})
    confidence = min(
        0.98,
        0.20
        + reference_confidence * 0.30
        + (0.20 if resource_context else 0.0)
        + (0.25 if owner_fields else 0.0)
        + (0.10 if named_identity else 0.0),
    ) if refs else 0.0
    # A bare identifier without a meaningful resource/ownership context stays weak.
    if refs and not resource_context and not owner_fields:
        confidence = min(confidence, 0.30)
    return {
        "has_reference": bool(refs),
        "reference_confidence": reference_confidence,
        "ownership_context": resource_context,
        "owner_fields": owner_fields,
        "named_identity_reference": named_identity,
        "confidence": confidence,
    }


def infer_ownership(endpoint: str, *, response_fields: set[str] | None = None) -> list[OwnershipSignal]:
    signals = ownership_signals(endpoint, response_fields=response_fields)
    if not signals["has_reference"]:
        return []
    refs = extract_object_references(endpoint)
    result: list[OwnershipSignal] = []
    for ref in refs:
        rationale = [f"{ref.kind} object reference appears in {ref.location}"]
        if signals["ownership_context"]:
            rationale.append("resource path suggests an ownership boundary")
        if signals["owner_fields"]:
            rationale.append("response metadata supplied ownership-related fields")
        if not signals["ownership_context"] and not signals["owner_fields"]:
            rationale.append("identifier lacks corroborating ownership context; confidence intentionally capped")
        result.append(OwnershipSignal(endpoint, ref.name, ref.kind, tuple(signals["owner_fields"]), float(signals["confidence"]), tuple(rationale)))
    return result
