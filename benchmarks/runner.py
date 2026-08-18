"""Executable precision benchmark for ReconForge intelligence."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconforge.intelligence.hunter import build_hypotheses
from reconforge.intelligence.hunter_queue import rank_hypotheses
from reconforge.models import Observation, ObservationKind


@dataclass(frozen=True, slots=True)
class BenchmarkCaseResult:
    case_id: str
    observed: int
    hypotheses: int
    useful_hits: int
    suppressed_hits: int
    duplicate_hits: int
    not_applicable_hits: int
    top5_precision: float
    top10_precision: float
    top20_precision: float
    suppressed_pass: bool

    @property
    def considered(self) -> int:
        return max(1, self.useful_hits + self.suppressed_hits + self.duplicate_hits + self.not_applicable_hits)


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    cases: tuple[BenchmarkCaseResult, ...]

    @property
    def top5(self) -> float:
        return _mean(item.top5_precision for item in self.cases)

    @property
    def top10(self) -> float:
        return _mean(item.top10_precision for item in self.cases)

    @property
    def top20(self) -> float:
        return _mean(item.top20_precision for item in self.cases)

    @property
    def useful_rate(self) -> float:
        return _rate(sum(item.useful_hits for item in self.cases), sum(item.considered for item in self.cases))

    @property
    def duplicate_rate(self) -> float:
        return _rate(sum(item.duplicate_hits for item in self.cases), sum(item.considered for item in self.cases))

    @property
    def not_applicable_rate(self) -> float:
        return _rate(sum(item.not_applicable_hits for item in self.cases), sum(item.considered for item in self.cases))

    @property
    def suppression_rate(self) -> float:
        return _rate(sum(item.suppressed_hits for item in self.cases), sum(item.considered for item in self.cases))

    @property
    def all_regressions_pass(self) -> bool:
        return bool(self.cases) and all(item.suppressed_pass for item in self.cases)


def run_directory(directory: str | Path) -> BenchmarkReport:
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"benchmark directory does not exist: {root}")
    results: list[BenchmarkCaseResult] = []
    for path in sorted(root.glob("*.json")):
        payload = json.loads(path.read_text())
        results.append(_run_case(payload))
    if not results:
        raise ValueError(f"no benchmark cases found in {root}")
    return BenchmarkReport(tuple(results))


def _run_case(payload: dict[str, Any]) -> BenchmarkCaseResult:
    observations = [_observation(item, payload["id"]) for item in payload["observations"]]
    expected = set(payload.get("expected_queue", []))
    suppressed = set(payload.get("expected_suppressed", []))
    duplicates = set(payload.get("expected_duplicates", []))
    not_applicable = set(payload.get("expected_not_applicable", []))
    hypotheses = build_hypotheses(observations)
    ranked = rank_hypotheses(hypotheses, limit=max(20, len(hypotheses)))
    subjects = [item.hypothesis.subject for item in ranked]

    def precision(limit: int) -> float:
        window = subjects[:limit]
        if not window:
            return 0.0
        return sum(subject in expected for subject in window) / len(window)

    useful_hits = sum(subject in expected for subject in subjects)
    suppressed_hits = sum(subject in suppressed for subject in subjects)
    duplicate_hits = sum(subject in duplicates for subject in subjects)
    not_applicable_hits = sum(subject in not_applicable for subject in subjects)
    suppressed_pass = suppressed_hits == 0
    return BenchmarkCaseResult(
        case_id=str(payload["id"]),
        observed=len(observations),
        hypotheses=len(hypotheses),
        useful_hits=useful_hits,
        suppressed_hits=suppressed_hits,
        duplicate_hits=duplicate_hits,
        not_applicable_hits=not_applicable_hits,
        top5_precision=precision(5),
        top10_precision=precision(10),
        top20_precision=precision(20),
        suppressed_pass=suppressed_pass,
    )


def _observation(raw: dict[str, Any], run_id: str) -> Observation:
    kind = ObservationKind(raw.get("kind", "endpoint"))
    return Observation(
        kind=kind,
        subject=str(raw["subject"]),
        source=str(raw.get("source", "benchmark")),
        run_id=run_id,
        attributes=dict(raw.get("attributes", {})),
    )


def _mean(values: Any) -> float:
    values = tuple(values)
    return sum(values) / len(values) if values else 0.0


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run ReconForge benchmark cases")
    parser.add_argument("directory")
    args = parser.parse_args()
    try:
        report = run_directory(args.directory)
    except Exception as exc:
        print(f"benchmark execution failed: {exc}")
        return 2

    for case in report.cases:
        print(
            f"{case.case_id}: observations={case.observed} hypotheses={case.hypotheses} "
            f"top5={case.top5_precision:.3f} top10={case.top10_precision:.3f} "
            f"top20={case.top20_precision:.3f} suppressed={case.suppressed_pass}"
        )
    print(
        f"aggregate: top5={report.top5:.3f} top10={report.top10:.3f} top20={report.top20:.3f} "
        f"useful={report.useful_rate:.3f} suppressed={report.suppression_rate:.3f} "
        f"duplicate={report.duplicate_rate:.3f} n/a={report.not_applicable_rate:.3f}"
    )
    return 0 if report.all_regressions_pass else 2


if __name__ == "__main__":
    raise SystemExit(main())
