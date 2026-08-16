"""Run manifests for reproducibility, auditability, and enterprise review."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(slots=True)
class RunManifest:
    run_id: str
    target: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy: dict[str, object] = field(default_factory=dict)
    tools: list[dict[str, object]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    selected_capabilities: list[str] = field(default_factory=list)

    def record_tool(self, name: str, *, version: str | None, enabled: bool, passive: bool) -> None:
        self.tools.append({
            "name": name,
            "version": version,
            "enabled": enabled,
            "passive": passive,
        })

    def write(self, directory: str | Path) -> Path:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        output = path / f"{self.run_id}.json"
        output.write_text(json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8")
        return output
