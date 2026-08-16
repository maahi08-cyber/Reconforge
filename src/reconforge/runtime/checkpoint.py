"""Resumable run checkpoints for long-lived ReconForge jobs."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Checkpoint:
    run_id: str
    completed: tuple[str, ...]
    failed: tuple[str, ...] = ()


class CheckpointStore:
    def __init__(self, root: str | Path = ".reconforge/checkpoints") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, run_id: str) -> Path:
        safe = "".join(ch for ch in run_id if ch.isalnum() or ch in "._-")
        if not safe:
            raise ValueError("invalid run_id")
        return self.root / f"{safe}.json"

    def load(self, run_id: str) -> Checkpoint:
        path = self.path_for(run_id)
        if not path.exists():
            return Checkpoint(run_id, ())
        data = json.loads(path.read_text(encoding="utf-8"))
        return Checkpoint(run_id, tuple(data.get("completed", ())), tuple(data.get("failed", ())))

    def mark(self, run_id: str, sensor: str, *, failed: bool = False) -> Checkpoint:
        current = self.load(run_id)
        completed = set(current.completed)
        failed_items = set(current.failed)
        if failed:
            failed_items.add(sensor)
        else:
            completed.add(sensor)
            failed_items.discard(sensor)
        updated = Checkpoint(run_id, tuple(sorted(completed)), tuple(sorted(failed_items)))
        self.path_for(run_id).write_text(
            json.dumps({"run_id": run_id, "completed": updated.completed, "failed": updated.failed}, indent=2),
            encoding="utf-8",
        )
        return updated
