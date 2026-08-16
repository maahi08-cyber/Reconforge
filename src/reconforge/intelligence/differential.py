"""Differential evidence for explicitly authorized request contexts."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping


@dataclass(frozen=True, slots=True)
class ResponseFingerprint:
    status: int
    headers: tuple[tuple[str, str], ...]
    body_hash: str
    body_length: int
    schema_keys: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    endpoint: str
    status_changed: bool
    body_changed: bool
    schema_changed: bool
    object_reference_overlap: bool
    signal_strength: float
    rationale: tuple[str, ...]


def fingerprint(status: int, headers: Mapping[str, str], body: bytes, schema_keys: set[str] | None = None) -> ResponseFingerprint:
    stable_headers = tuple(sorted((k.lower(), v.strip()) for k, v in headers.items() if k.lower() in {"content-type", "location", "content-length"}))
    return ResponseFingerprint(status, stable_headers, sha256(body).hexdigest(), len(body), tuple(sorted(schema_keys or set())))


def compare_contexts(endpoint: str, first: ResponseFingerprint, second: ResponseFingerprint, *, object_references_overlap: bool = False) -> DifferentialResult:
    rationale: list[str] = []
    status_changed = first.status != second.status
    body_changed = first.body_hash != second.body_hash or first.body_length != second.body_length
    schema_changed = first.schema_keys != second.schema_keys
    if status_changed:
        rationale.append("HTTP status differs between authorized contexts")
    if body_changed:
        rationale.append("response fingerprint differs between contexts")
    if schema_changed:
        rationale.append("response schema differs between contexts")
    if object_references_overlap:
        rationale.append("object reference overlap supplied by researcher")
    raw = 0.20 + 0.20 * status_changed + 0.25 * body_changed + 0.20 * schema_changed + 0.30 * object_references_overlap
    return DifferentialResult(endpoint, status_changed, body_changed, schema_changed, object_references_overlap, min(1.0, raw), tuple(rationale))
