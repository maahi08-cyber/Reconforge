"""Real subprocess-backed ReconForge adapters.

The wrappers are intentionally thin: tool-specific output is parsed into the
same Observation model and never bypasses scope/correlation layers.
"""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.models import Observation, ObservationKind, Target
from reconforge.runtime.tooling import run_command


@dataclass(frozen=True, slots=True)
class ProcessAdapter:
    name: str
    binary: str
    source_kind: ObservationKind
    passive: bool = True

    def collect(self, target: Target, run_id: str, timeout: float = 120.0) -> tuple[list[Observation], str | None]:
        if not target.in_scope:
            return [], "target is outside configured scope"
        result = run_command(self.build_argv(target), timeout=timeout)
        if result.returncode != 0:
            return [], result.stderr.strip() or f"{self.name} exited with {result.returncode}"
        observations = [
            Observation(
                self.source_kind,
                line.strip(),
                self.name,
                run_id,
                {"tool": self.name, "passive": self.passive},
            )
            for line in result.stdout.splitlines()
            if line.strip()
        ]
        return observations, None

    def build_argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-d", target.value]


class SubfinderAdapter(ProcessAdapter):
    def __init__(self) -> None:
        super().__init__("subfinder", "subfinder", ObservationKind.ASSET, True)


class GauAdapter(ProcessAdapter):
    def __init__(self) -> None:
        super().__init__("gau", "gau", ObservationKind.HISTORICAL, True)

    def build_argv(self, target: Target) -> list[str]:
        return [self.binary, target.value]


class WaybackAdapter(ProcessAdapter):
    def __init__(self) -> None:
        super().__init__("waybackurls", "waybackurls", ObservationKind.HISTORICAL, True)

    def build_argv(self, target: Target) -> list[str]:
        return [self.binary]
