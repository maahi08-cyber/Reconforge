"""Tool discovery and safe execution primitives."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from reconforge.adapters.contracts import DEFAULT_ADAPTERS, AdapterSpec


@dataclass(frozen=True, slots=True)
class ToolStatus:
    name: str
    binary: str
    available: bool
    path: str | None
    version: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def discover_tools(specs: Sequence[AdapterSpec] = DEFAULT_ADAPTERS) -> list[ToolStatus]:
    results: list[ToolStatus] = []
    for spec in specs:
        path = shutil.which(spec.binary)
        if not path:
            results.append(ToolStatus(spec.name, spec.binary, False, None))
            continue
        version = None
        try:
            probe = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5, check=False)
            line = (probe.stdout or probe.stderr).strip().splitlines()
            version = line[0] if line else None
        except (OSError, subprocess.SubprocessError) as exc:
            results.append(ToolStatus(spec.name, spec.binary, True, path, error=str(exc)))
            continue
        results.append(ToolStatus(spec.name, spec.binary, True, path, version=version))
    return results


def run_command(argv: Sequence[str], *, timeout: float = 120.0, cwd: str | None = None) -> CommandResult:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise ValueError("argv must contain non-empty strings")
    env = os.environ.copy()
    env.pop("PYTHONINSPECT", None)
    try:
        completed = subprocess.run(
            list(argv), cwd=cwd, env=env, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return CommandResult(tuple(argv), completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(tuple(argv), -1, exc.stdout or "", exc.stderr or "", True)
