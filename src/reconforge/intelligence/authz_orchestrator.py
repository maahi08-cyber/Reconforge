"""Orchestrate authorized differential research from supplied response fixtures."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from reconforge.intelligence.auth_research import build_authorization_hypothesis
from reconforge.intelligence.differential import compare_contexts, fingerprint
from reconforge.models import Hypothesis


@dataclass(frozen=True, slots=True)
class AuthorizedDifferential:
    hypothesis: Hypothesis
    signal_strength: float
    rationale: tuple[str, ...]


def compare_fixture_files(
    first: str | Path,
    second: str | Path,
    endpoint: str,
    *,
    object_reference_overlap: bool = False,
) -> AuthorizedDifferential:
    first_data = _read_fixture(first)
    second_data = _read_fixture(second)
    first_fp = fingerprint(
        int(first_data["status"]),
        first_data.get("headers", {}),
        str(first_data.get("body", "")).encode("utf-8"),
        set(first_data.get("schema_keys", [])),
    )
    second_fp = fingerprint(
        int(second_data["status"]),
        second_data.get("headers", {}),
        str(second_data.get("body", "")).encode("utf-8"),
        set(second_data.get("schema_keys", [])),
    )
    result = compare_contexts(
        endpoint,
        first_fp,
        second_fp,
        object_references_overlap=object_reference_overlap,
    )
    hypothesis = build_authorization_hypothesis(result, first_fp, second_fp)
    return AuthorizedDifferential(hypothesis, result.signal_strength, result.rationale)


def _read_fixture(path: str | Path) -> dict[str, object]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"fixture must contain a JSON object: {path}")
    if "status" not in payload:
        raise ValueError(f"fixture is missing status: {path}")
    return payload
