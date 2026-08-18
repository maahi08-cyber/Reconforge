"""Execute declarative ReconForge regression cases."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconforge.intelligence.history import compare_urls
from reconforge.intelligence.jsintel import extract_routes
from reconforge.intelligence.ownership import infer_ownership
from reconforge.intelligence.secretintel import scan_javascript
from reconforge.intelligence.workflow import extract_workflows
from reconforge.scope import ScopePolicy


def _load_cases(path: Path) -> list[dict[str, Any]]:
    text = path.read_text().strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        cases = [json.loads(line) for line in text.splitlines() if line.strip()]
        return [case for case in cases if isinstance(case, dict)]
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [case for case in payload if isinstance(case, dict)]
    raise ValueError(f"unsupported regression document in {path.name}")


def run_directory(directory: str | Path) -> tuple[bool, list[str]]:
    root = Path(directory)
    failures: list[str] = []
    for path in sorted(root.glob("*.json")):
        try:
            cases = _load_cases(path)
            if not cases:
                failures.append(f"{path.name}: no regression cases found")
                continue
            for case in cases:
                try:
                    _run_case(case)
                except Exception as exc:
                    failures.append(f"{path.name}:{case.get('id', '<unknown>')}: {exc}")
        except Exception as exc:
            failures.append(f"{path.name}: {exc}")
    return not failures, failures


def _run_case(case: dict[str, Any]) -> None:
    kind = case["kind"]
    expected = case.get("expected", {})

    if kind == "secret":
        findings = scan_javascript(case["script"])
        found = {item.kind for item in findings}
        assert set(expected.get("contains", [])) <= found
        assert not (set(expected.get("not_contains", [])) & found)
        return

    if kind == "history":
        current = set(case["current"])
        historical = set(case["historical"])
        statuses = [item.status for item in compare_urls(current, historical)]
        assert statuses == expected["statuses"]
        return

    if kind == "ownership":
        signals = infer_ownership(case["url"])
        maximum = max((item.confidence for item in signals), default=0.0)
        assert maximum <= float(expected["max_confidence"])
        return

    if kind == "workflow":
        workflows = extract_workflows([tuple(item) for item in case["endpoints"]])
        families = {item.key for item in workflows}
        assert set(expected.get("families", [])) <= families
        return

    if kind == "scope":
        policy = ScopePolicy(tuple(case.get("allowed", [])), tuple(case.get("denied", [])))
        for value in expected.get("allow", []):
            assert policy.allows(value)
        for value in expected.get("deny", []):
            assert not policy.allows(value)
        return

    raise ValueError(f"unsupported regression case kind: {kind}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run ReconForge regression cases")
    parser.add_argument("directory")
    args = parser.parse_args()
    ok, failures = run_directory(args.directory)
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"regressions: {'PASS' if ok else 'FAIL'}")
    raise SystemExit(0 if ok else 2)
