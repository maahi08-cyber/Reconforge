"""JavaScript intelligence for routes and sensitive-data leakage."""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urljoin

from reconforge.intelligence.secretintel import SecretCandidate, scan_javascript


@dataclass(frozen=True, slots=True)
class JSRoute:
    value: str
    kind: str
    confidence: float
    rationale: str
    line: int
    method: str | None = None


@dataclass(frozen=True, slots=True)
class JSAnalysis:
    routes: tuple[JSRoute, ...]
    secrets: tuple[SecretCandidate, ...]


_PATTERNS = (
    ("absolute_url", re.compile(r"https?://[^\"'`\s<>]+", re.I), 0.94, None),
    ("api_route", re.compile(r"[\"'`]((?:/api/|/graphql|/v\d+/)[^\"'`\s<>]{1,300})[\"'`]", re.I), 0.92, None),
    ("fetch", re.compile(r"fetch\(\s*[\"'`]([^\"'`]+)[\"'`]", re.I), 0.90, "GET"),
    ("axios", re.compile(r"axios\.(get|post|put|patch|delete)\(\s*[\"'`]([^\"'`]+)[\"'`]", re.I), 0.90, None),
)


def extract_routes(script: str, base_url: str | None = None) -> list[JSRoute]:
    seen: set[tuple[str, str | None]] = set()
    results: list[JSRoute] = []
    for line_no, line in enumerate(script.splitlines(), 1):
        for kind, pattern, confidence, default_method in _PATTERNS:
            for match in pattern.finditer(line):
                if kind == "axios":
                    method = match.group(1).upper()
                    raw_value = match.group(2)
                else:
                    method = default_method
                    raw_value = match.group(1) if pattern.groups else match.group(0)
                value = urljoin(base_url, raw_value) if base_url and raw_value.startswith("/") else raw_value
                normalized_kind = "graphql" if "graphql" in value.lower() else "api" if _is_api_route(value) else kind
                key = (value, method)
                if key in seen:
                    continue
                seen.add(key)
                results.append(JSRoute(value, normalized_kind, confidence, "structured client request reference", line_no, method))
    return results


def _is_api_route(value: str) -> bool:
    path = value.lower()
    return "/api/" in path or path.startswith("/api") or re.search(r"/v\d+(?:/|$)", path) is not None


def analyze_script(script: str, base_url: str | None = None) -> JSAnalysis:
    """Run route and sensitive-data intelligence as one client-side pass."""
    return JSAnalysis(tuple(extract_routes(script, base_url)), tuple(scan_javascript(script)))
