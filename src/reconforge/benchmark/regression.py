"""Executable lightweight regression checks for precision-critical signals."""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.intelligence.jsintel import analyze_script
from reconforge.intelligence.ownership import ownership_signals


@dataclass(frozen=True, slots=True)
class RegressionCase:
    name: str
    passed: bool
    detail: str


def run_regression() -> tuple[RegressionCase, ...]:
    cases: list[RegressionCase] = []

    random_uuid = "https://example.test/api/items/123e4567-e89b-12d3-a456-426614174000"
    ownership = ownership_signals(random_uuid)
    cases.append(RegressionCase(
        "uuid-without-owner-context",
        bool(ownership["has_reference"]) and not bool(ownership["owner_fields"]),
        "UUID is recognized without inventing ownership fields",
    ))

    public_example = "const example = 'eyJhbGciOiJIUzI1NiJ9.demo.example';"
    js = analyze_script(public_example)
    public_jwt_ignored = not any(secret.kind == "jwt" and secret.confidence > 0.8 for secret in js.secrets)
    cases.append(RegressionCase(
        "public-jwt-example",
        public_jwt_ignored,
        "example JWT-like text should not become a high-confidence secret",
    ))

    duplicate_urls = "const a='/api/users/1'; const b='/api/users/1';"
    duplicate_analysis = analyze_script(duplicate_urls)
    route_values = [route.value for route in duplicate_analysis.routes]
    cases.append(RegressionCase(
        "duplicate-route-suppression",
        len(route_values) == len(set(route_values)),
        "the same route is emitted once per analysis",
    ))

    return tuple(cases)
