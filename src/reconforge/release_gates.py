"""Enterprise release-quality gates for ReconForge."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QualitySnapshot:
    scope_enforced: bool
    provenance_present: bool
    secrets_redacted: bool
    deduplication_present: bool
    resumability_present: bool
    benchmark_available: bool
    regression_corpus_available: bool
    measured_precision: bool

    @property
    def blocking_failures(self) -> tuple[str, ...]:
        failures: list[str] = []
        for name, value in (
            ("scope_enforced", self.scope_enforced),
            ("provenance_present", self.provenance_present),
            ("secrets_redacted", self.secrets_redacted),
            ("deduplication_present", self.deduplication_present),
            ("resumability_present", self.resumability_present),
            ("benchmark_available", self.benchmark_available),
            ("regression_corpus_available", self.regression_corpus_available),
            ("measured_precision", self.measured_precision),
        ):
            if not value:
                failures.append(name)
        return tuple(failures)

    @property
    def release_candidate(self) -> bool:
        return not self.blocking_failures
