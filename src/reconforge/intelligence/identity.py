"""Stable asset and endpoint identity plus authorization-context signals."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,64}$", re.I)
_INT = re.compile(r"^\d{1,20}$")


class IdentityKind(StrEnum):
    USER = "user"
    ROLE = "role"
    TEAM = "team"
    ORGANIZATION = "organization"
    PROJECT = "project"
    OBJECT = "object"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Identity:
    canonical: str
    identity_key: str
    kind: str
    confidence: float


@dataclass(frozen=True, slots=True)
class IdentitySignal:
    value: str
    kind: IdentityKind
    confidence: float
    rationale: str


_PREFIXES = {
    "user": IdentityKind.USER,
    "account": IdentityKind.USER,
    "team": IdentityKind.TEAM,
    "org": IdentityKind.ORGANIZATION,
    "organization": IdentityKind.ORGANIZATION,
    "project": IdentityKind.PROJECT,
    "file": IdentityKind.OBJECT,
    "document": IdentityKind.OBJECT,
    "member": IdentityKind.USER,
    "invite": IdentityKind.OBJECT,
}


def canonical_host(value: str) -> str:
    host = urlsplit(value).hostname if "://" in value else value
    return (host or "").strip().lower().rstrip(".")


def canonical_url(value: str, *, ignore_query_values: bool = False) -> str:
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path or "/"
    path = path.rstrip("/") or "/"
    params = parse_qsl(parts.query, keep_blank_values=True)
    if ignore_query_values:
        query = "&".join(sorted({key.lower() for key, _ in params}))
    else:
        query = "&".join(f"{k}={v}" for k, v in sorted(params))
    return urlunsplit((scheme, host, path, query, ""))


def classify_identifier(value: str) -> str | None:
    value = value.strip()
    if _UUID.match(value):
        return "uuid"
    if _INT.match(value):
        return "integer"
    if _HEX.match(value):
        return "hex_or_hash"
    if value.startswith("0x") and _HEX.match(value[2:]):
        return "hex_or_hash"
    return None


def endpoint_identity(value: str) -> Identity:
    canonical = canonical_url(value, ignore_query_values=True)
    key = sha256(canonical.encode("utf-8")).hexdigest()[:24]
    queryless = urlsplit(canonical).query == ""
    return Identity(canonical, key, "endpoint_template" if queryless else "endpoint", 0.96 if queryless else 0.90)


def host_identity(value: str) -> Identity:
    canonical = canonical_host(value)
    key = sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return Identity(canonical, key, "host", 0.99)


def infer_identity(value: str) -> IdentitySignal | None:
    token = value.strip("/ \t\r\n")
    lower = token.lower()
    for prefix, kind in _PREFIXES.items():
        if lower.startswith(prefix + "_") or lower.startswith(prefix + "-") or lower == prefix:
            return IdentitySignal(token, kind, 0.90, f"identifier uses explicit {prefix} namespace")
    identifier_kind = classify_identifier(token)
    if identifier_kind:
        return IdentitySignal(token, IdentityKind.OBJECT, 0.64, f"stable {identifier_kind} resembles an application object reference")
    return None


def authorization_pressure(*, authenticated: bool, object_reference: bool, ownership_context: bool, role_boundary: bool) -> float:
    score = 0.25 * authenticated + 0.30 * object_reference + 0.25 * ownership_context + 0.20 * role_boundary
    return min(1.0, score)
