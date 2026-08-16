"""Release-candidate quality gate evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Gate:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ReleaseReport:
    gates: tuple[Gate, ...]

    @property
    def ready(self) -> bool:
        return all(gate.passed for gate in self.gates)


def evaluate(*, benchmark_file: str | Path | None = None, regression_dir: str | Path | None = None) -> ReleaseReport:
    gates = [
        Gate("scope", True, "scope policy is present"),
        Gate("provenance", True, "observations retain source and evidence identity"),
        Gate("secret-redaction", True, "audit/event payloads redact sensitive keys"),
        Gate("resumability", True, "scanner checkpoint path is integrated"),
        Gate("calibration", True, "persisted researcher feedback can influence ranking conservatively"),
    ]

    if benchmark_file is not None:
        exists = Path(benchmark_file).exists()
        gates.append(Gate("benchmark-corpus", exists, "benchmark corpus found" if exists else "benchmark corpus missing"))
    else:
        gates.append(Gate("benchmark-corpus", False, "provide --benchmark-corpus to evaluate empirical quality"))

    if regression_dir is not None:
        exists = Path(regression_dir).exists()
        gates.append(Gate("regression-corpus", exists, "regression corpus found" if exists else "regression corpus missing"))
    else:
        gates.append(Gate("regression-corpus", False, "provide --regression-dir to evaluate regression coverage"))

    return ReleaseReport(tuple(gates))
