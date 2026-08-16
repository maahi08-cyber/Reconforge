"""Lightweight JavaScript and client-route intelligence.

This module deliberately extracts structured candidate routes and references;
it does not treat arbitrary strings as vulnerabilities or secrets.
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


_ROUTE_PATTERNS = (
    re.compile(r"['\"]((?:https?://[^'\"]+|/api(?:/[^'\"]*)?|/graphql(?:[^'\"]*)?))['\"]", re.I),
    re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"axios\.(?:get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]", re.I),
)


def extract_routes(script: str, base_url: str | None = None) -> list[JSRoute]:
    seen: set[str] = set()
    results: list[JSRoute] = []
    for pattern in _ROUTE_PATTERNS:
        for match in pattern.findall(script):
            route = match.strip()
            if base_url and route.startswith("/"):
                route = urljoin(base_url, route)
            if route in seen:
                continue
            seen.add(route)
            kind = "graphql" if "graphql" in route.lower() else "api" if "/api" in route.lower() else "url"
            confidence = 0.95 if kind in {"api", "graphql"} else 0.75
            results.append(JSRoute(route, kind, confidence, "structured client request reference"))
    return results
