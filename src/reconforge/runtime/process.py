"""Safe external-process boundary for ReconForge adapters."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from shutil import which
from typing import Sequence


@dataclass(frozen=True, slots=True)
class ProcessResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class ProcessRunner:
    """Run an allowlisted executable without shell interpolation."""

    def __init__(self, timeout_seconds: float = 60.0) -> None:
        self.timeout_seconds = timeout_seconds

    def run(self, argv: Sequence[str], *, env: dict[str, str] | None = None) -> ProcessResult:
        if not argv or not argv[0]:
            raise ValueError("command cannot be empty")
        executable = which(argv[0])
        if executable is None:
            raise FileNotFoundError(argv[0])

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        command = tuple(str(value) for value in argv)
        try:
            completed = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                env=merged_env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ProcessResult(command, -1, exc.stdout or "", exc.stderr or "", True)

        return ProcessResult(command, completed.returncode, completed.stdout, completed.stderr, False)
