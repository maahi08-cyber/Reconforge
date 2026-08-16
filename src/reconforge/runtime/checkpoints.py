"""Resumable run checkpoints for long reconnaissance jobs."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Checkpoint:
    run_id: str
    target: str
    completed_sensors: tuple[str, ...]
    updated_at: str

    @classmethod
    def new(cls, run_id: str, target: str, completed_sensors: tuple[str, ...] = ()) -> "Checkpoint":
        return cls(run_id, target, completed_sensors, datetime.now(timezone.utc).isoformat())

    def complete(self, sensor: str) -> "Checkpoint":
        sensors = tuple(dict.fromkeys((*self.completed_sensors, sensor)))
        return Checkpoint(self.run_id, self.target, sensors, datetime.now(timezone.utc).isoformat())

    def has_completed(self, sensor: str) -> bool:
        return sensor in self.completed_sensors


def save(checkpoint: Checkpoint, path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps({
        "run_id": checkpoint.run_id,
        "target": checkpoint.target,
        "completed_sensors": checkpoint.completed_sensors,
        "updated_at": checkpoint.updated_at,
    }, sort_keys=True), encoding="utf-8")
    temporary.replace(destination)


def load(path: str | Path) -> Checkpoint:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Checkpoint(
        str(data["run_id"]),
        str(data["target"]),
        tuple(str(item) for item in data.get("completed_sensors", [])),
        str(data["updated_at"]),
    )
