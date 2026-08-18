"""Scope-aware active adapters for HTTP, crawling, ports, services, and detection."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from reconforge.models import Observation, ObservationKind, Target
from reconforge.runtime.tooling import run_command


_SENSITIVE_KEYS = {"authorization", "token", "access_token", "refresh_token", "api_key", "apikey", "secret", "password", "cookie", "set-cookie"}
_MAX_TEXT = 500


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): ("<redacted>" if str(key).lower() in _SENSITIVE_KEYS else _sanitize(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value[:50]]
    if isinstance(value, str):
        return value[:_MAX_TEXT]
    return value


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
            attrs = {key: _sanitize(data[key]) for key in ("status_code", "title", "webserver", "tech") if key in data}
            items.append(Observation(self.kind, subject, self.name, run_id, attrs))
        return items


class KatanaAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("katana", "katana", ObservationKind.ENDPOINT)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-u", target.value, "-j", "-kf", "all"]

    def parse(self, stdout: str, run_id: str) -> list[Observation]:
        items: list[Observation] = []
        for line in stdout.splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                if line.strip().startswith(("http://", "https://")):
                    items.append(Observation(self.kind, line.strip(), self.name, run_id, {"format": "line"}))
                continue
            request = data.get("request") or {}
            subject = request.get("endpoint") or data.get("endpoint") or data.get("url")
            if subject:
                attrs = {
                    "method": request.get("method"),
                    "status_code": data.get("response", {}).get("status_code"),
                    "source_type": data.get("type"),
                }
                attrs = {key: _sanitize(value) for key, value in attrs.items() if value not in (None, "")}
                items.append(Observation(self.kind, subject, self.name, run_id, attrs))
        return items


class DnsxAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("dnsx", "dnsx", ObservationKind.DNS)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-a", "-resp", "-d", target.value]


class NaabuAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("naabu", "naabu", ObservationKind.PORT)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-host", target.value]


class NmapAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("nmap", "nmap", ObservationKind.TECHNOLOGY)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-Pn", "-sV", "--version-light", target.value]


class NucleiAdapter(ActiveAdapter):
    def __init__(self) -> None:
        super().__init__("nuclei", "nuclei", ObservationKind.TECHNOLOGY)

    def argv(self, target: Target) -> list[str]:
        return [self.binary, "-silent", "-jsonl", "-u", target.value]

    def parse(self, stdout: str, run_id: str) -> list[Observation]:
        items: list[Observation] = []
        for line in stdout.splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            subject = data.get("matched-at") or data.get("host") or data.get("template-id")
            if subject:
                attrs = {
                    "template_id": data.get("template-id"),
                    "severity": data.get("info", {}).get("severity"),
                    "type": data.get("type"),
                    "matcher_name": data.get("matcher-name"),
                }
                attrs = {key: _sanitize(value) for key, value in attrs.items() if value not in (None, "")}
                items.append(Observation(self.kind, subject, self.name, run_id, attrs))
        return items
