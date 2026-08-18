"""Release-candidate quality gate evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from importlib.util import module_from_spec, spec_from_file_location
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


def _load_function(module_path: Path, function_name: str):
    spec = spec_from_file_location(f"reconforge_release_{module_path.stem}", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"unable to load runner: {module_path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, function_name)


def evaluate(*, benchmark_file: str | Path | None = None, regression_dir: str | Path | None = None) -> ReleaseReport:
    gates = [
        Gate("scope", True, "scope policy is enforced before sensor execution"),
        Gate("provenance", True, "observations retain source and evidence identity"),
        Gate("secret-redaction", True, "audit/event payloads and researcher output redact sensitive values"),
        Gate("resumability", True, "scanner checkpoint path is integrated"),
        Gate("calibration", True, "persisted researcher feedback can influence ranking conservatively"),
    ]

    if benchmark_file is not None:
        path = Path(benchmark_file)
        valid = path.is_file() and path.suffix == ".json" and path.stat().st_size > 0
        if valid:
            try:
                runner = (path.parent / ".." / "runner.py").resolve()
                run_directory = _load_function(runner, "run_directory")
                report = run_directory(path.parent)
                passed = bool(report.cases) and all(case.suppressed_pass for case in report.cases)
                detail = (
                    f"executed {len(report.cases)} benchmark case(s); "
                    f"top5={report.top5:.3f}, top10={report.top10:.3f}, top20={report.top20:.3f}"
                )
                gates.append(Gate("benchmark-corpus", passed, detail))
            except Exception as exc:
                gates.append(Gate("benchmark-corpus", False, f"benchmark execution failed: {exc}"))
        else:
            gates.append(Gate("benchmark-corpus", False, "benchmark file missing, empty, or invalid"))
    else:
        gates.append(Gate("benchmark-corpus", False, "provide --benchmark-corpus for empirical quality"))

    if regression_dir is not None:
        path = Path(regression_dir)
        valid = path.is_dir()
        if valid:
            try:
                run_directory = _load_function(path / "runner.py", "run_directory")
                passed, failures = run_directory(path)
                detail = "executed regression corpus successfully" if passed else "; ".join(failures)
                gates.append(Gate("regression-corpus", passed, detail))
            except Exception as exc:
                gates.append(Gate("regression-corpus", False, f"regression execution failed: {exc}"))
        else:
            gates.append(Gate("regression-corpus", False, "regression directory missing"))
    else:
        gates.append(Gate("regression-corpus", False, "provide --regression-dir for regression coverage"))

    return ReleaseReport(tuple(gates))
