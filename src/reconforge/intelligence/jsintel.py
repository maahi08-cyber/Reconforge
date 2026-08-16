"""Lightweight JavaScript and client-route intelligence.

Extracts structured client-side references that enrich the endpoint graph. It
never executes target JavaScript and does not turn strings into vulnerability
claims.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urljoin


@dataclass(frozen=True, slots=True)
class JSRoute:
    value: str
    kind: str
    confidence: float
    rationale: str
    line: int


_PATTERNS = (
    ("absolute_url", re.compile(r"https?://[^\"'`\s<>]+", re.I), 0.94),
    ("api_route", re.compile(r"[\"'`]((?:/api/|/graphql|/v\d+/)[^\"'`\s<>]{1,300})[\"'`]", re.I), 0.92),
    ("fetch", re.compile(r"fetch\(\s*[\"'`]([^\"'`]+)[\"'`]", re.I), 0.90),
    ("axios", re.compile(r"axios\.(?:get|post|put|patch|delete)\(\s*[\"'`]([^\"'`]+)[\"'`]", re.I), 0.90),
)


def extract_routes(script: str, base_url: str | None = None) -> list[JSRoute]:
    seen: set[tuple[str, str]] = set()
    results: list[JSRoute] = []
    for line_no, line in enumerate(script.splitlines(), 1):
        for kind, pattern, confidence in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1) if pattern.groups else match.group(0)
                value = urljoin(base_url, value) if base_url and value.startswith("/") else value
                key = (value, kind)
                if key in seen:
                    continue
                seen.add(key)
                if "graphql" in value.lower():
                    normalized_kind = "graphql"
                elif "/api" in value.lower() or "/v" in value.lower():
                    normalized_kind = "api"
                else:
                    normalized_kind = kind
                results.append(JSRoute(value, normalized_kind, confidence, "structured client request reference", line_no))
    return results
