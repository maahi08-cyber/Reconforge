"""Portable JSONL import/export for ReconForge observations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from reconforge.models import Observation, ObservationKind


def export_observations(items: Iterable[Observation], path: str | Path) -> int:
    count = 0
    with Path(path).open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps({
                "kind": item.kind.value,
                "subject": item.subject,
                "source": item.source,
                "run_id": item.run_id,
                "attributes": item.attributes,
                "observed_at": item.observed_at.isoformat(),
                "evidence_hash": item.evidence_hash,
            }, sort_keys=True, default=str) + "\n")
            count += 1
    return count


def import_observations(path: str | Path) -> list[Observation]:
    results: list[Observation] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        results.append(Observation(
            ObservationKind(data["kind"]), data["subject"], data["source"],
            data["run_id"], data.get("attributes", {}), evidence_hash=data.get("evidence_hash", ""),
        ))
    return results
