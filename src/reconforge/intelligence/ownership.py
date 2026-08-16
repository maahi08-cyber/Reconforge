"""Object/reference and ownership-boundary intelligence."""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ObjectReference:
    raw: str
    name: str
    kind: str
    location: str
    confidence: float


_ID_PATTERNS = (
    ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)),
    ("numeric_id", re.compile(r"(?<![A-Za-z0-9])\d{2,18}(?![A-Za-z0-9])")),
    ("hex_id", re.compile(r"(?<![A-Za-z0-9])[0-9a-f]{16,64}(?![A-Za-z0-9])", re.I)),
)


def extract_object_references(url: str) -> list[ObjectReference]:
    parts = urlsplit(url)
    results: list[ObjectReference] = []
    for name, pattern in _ID_PATTERNS:
        for match in pattern.finditer(parts.path):
            raw = match.group(0)
            before = parts.path[: match.start()].rstrip("/").split("/")
            resource = before[-1] if before else "object"
            confidence = 0.92 if name == "uuid" else 0.72 if name == "numeric_id" else 0.68
            results.append(ObjectReference(raw, resource, name, "path", confidence))
    for key, value in __import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(parts.query, keep_blank_values=True):
        if key.lower().endswith(("id", "_id", "uuid")) and value:
            results.append(ObjectReference(value, key.lower(), "parameter_id", "query", 0.82))
    return results


def ownership_signals(url: str) -> dict[str, float | bool]:
    refs = extract_object_references(url)
    names = " ".join(ref.name for ref in refs).lower()
    path = urlsplit(url).path.lower()
    sensitive_context = any(token in path for token in ("account", "user", "team", "org", "project", "file", "document", "member"))
    return {
        "has_reference": bool(refs),
        "reference_confidence": max((ref.confidence for ref in refs), default=0.0),
        "ownership_context": sensitive_context,
        "named_identity_reference": any(token in names for token in ("user", "account", "member", "project", "team", "org")),
    }
