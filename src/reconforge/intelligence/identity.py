"""Stable asset and endpoint identity resolution.

The goal is to prevent aliases and cosmetic URL differences from becoming
separate research targets. Identity is deterministic and intentionally
conservative: uncertain relationships are retained as candidates rather than
being merged destructively.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,64}$", re.I)
_INT = re.compile(r"^\d{1,20}$")


@dataclass(frozen=True, slots=True)
class Identity:
    canonical: str
    identity_key: str
    kind: str
    confidence: float


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
