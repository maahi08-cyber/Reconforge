"""Scope-aware active adapters for HTTP, crawling, ports, and service context."""
from __future__ import annotations

import json
from dataclasses import dataclass

from reconforge.models import Observation, ObservationKind, Target
from reconforge.runtime.tooling import run_command


@dataclass(frozen=True, slots=True)
class ActiveAdapter:
    name: str
    binary: str
    kind: ObservationKind

    def collect(self, target: Target, run_id: str, timeout: float = 180.0) -> tuple[list[Observation], str | None]:
        if not target.in_scope:
            return [], "target is outside configured scope"
        result = run_command(self.argv(target), timeout=timeout)
        if result.returncode != 0:
            return [], result.stderr.strip() or f"{self.name} exited with {result.returncode}"
        return self.parse(result.stdout, run_id), None

    def argv(self, target: Target) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, run_id: str) -> list[Observation]:
        return [Observation(self.kind, line.strip(), self.name, run_id) for line in stdout.splitlines() if line.strip()]


class HttpxAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("httpx", "httpx", ObservationKind.HTTP)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-json", "-u", target.value, "-title", "-status-code", "-tech-detect", "-web-server"]

    def parse(self, stdout: str, run_id: str) -> list[Observation]:
        items: list[Observation] = []
        for line in stdout.splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            subject = data.get("url") or data.get("input")
            if not subject:
                continue
            attrs = {key: data[key] for key in ("status_code", "title", "webserver", "tech") if key in data}
            items.append(Observation(self.kind, subject, self.name, run_id, attrs))
        return items


class NaabuAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("naabu", "naabu", ObservationKind.DNS)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-host", target.value]


class NmapAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("nmap", "nmap", ObservationKind.TECHNOLOGY)

    def argv(self, target: Target) -> list[str]:
        # Conservative version/service identification; scope must be supplied by the caller.
        return [self.binary, "-Pn", "-sV", "--version-light", target.value]
