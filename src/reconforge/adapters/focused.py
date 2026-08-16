"""Focused active adapters for explicitly authorized application surfaces.

These adapters are intentionally opt-in and target a single supplied URL surface
rather than performing broad, implicit expansion.
"""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.models import Observation, ObservationKind, Target
from reconforge.runtime.tooling import run_command


@dataclass(frozen=True, slots=True)
class FocusedAdapter:
    name: str
    binary: str

    def collect(self, target: Target, run_id: str, *, timeout: float = 120.0, wordlist: str | None = None) -> tuple[list[Observation], str | None]:
        if not target.in_scope:
            return [], "target is outside configured scope"
        argv = self.build_argv(target, wordlist=wordlist)
        result = run_command(argv, timeout=timeout)
        if result.returncode != 0:
            return [], result.stderr.strip() or f"{self.name} exited with {result.returncode}"
        return [Observation(ObservationKind.ENDPOINT, line.strip(), self.name, run_id, {"focused": True})
                for line in result.stdout.splitlines() if line.strip()], None

    def build_argv(self, target: Target, *, wordlist: str | None) -> list[str]:
        raise NotImplementedError


class FfufAdapter(FocusedAdapter):
    def __init__(self) -> None:
        super().__init__("ffuf", "ffuf")

    def build_argv(self, target: Target, *, wordlist: str | None) -> list[str]:
        if not wordlist:
            raise ValueError("FFUF requires an explicit wordlist")
        return [self.binary, "-u", target.value.rstrip("/") + "/FUZZ", "-w", wordlist, "-of", "json", "-noninteractive"]


class ArjunAdapter(FocusedAdapter):
    def __init__(self) -> None:
        super().__init__("arjun", "arjun")

    def build_argv(self, target: Target, *, wordlist: str | None) -> list[str]:
        return [self.binary, "-u", target.value, "--stable"]
