"""Persistent, conservative calibration primitives for Hunter Queue ranking."""
from __future__ import annotations

from dataclasses import dataclass, field
from math import log1p


@dataclass(slots=True)
class SignalStats:
    useful: int = 0
    noisy: int = 0
    duplicate: int = 0
    not_applicable: int = 0

    @property
    def total(self) -> int:
        return self.useful + self.noisy + self.duplicate + self.not_applicable

    @property
    def precision_estimate(self) -> float:
        # Conservative Beta(1,1) prior; only useful outcomes count as positives.
        return (self.useful + 1.0) / (self.total + 2.0)

    @property
    def confidence_weight(self) -> float:
        trust = min(0.75, log1p(self.total) / 4.0)
        return 1.0 + (self.precision_estimate - 0.5) * trust


@dataclass(slots=True)
class CalibrationModel:
    signals: dict[str, SignalStats] = field(default_factory=dict)

    def record(self, signal: str, outcome: str) -> None:
        if outcome not in {"useful", "noisy", "duplicate", "n/a"}:
            raise ValueError("outcome must be useful, noisy, duplicate, or n/a")
        stats = self.signals.setdefault(signal, SignalStats())
        if outcome == "useful":
            stats.useful += 1
        elif outcome == "noisy":
            stats.noisy += 1
        elif outcome == "duplicate":
            stats.duplicate += 1
        else:
            stats.not_applicable += 1

    def weight(self, signal: str) -> float:
        return self.signals.get(signal, SignalStats()).confidence_weight

    def snapshot(self) -> dict[str, dict[str, int | float]]:
        return {
            name: {
                "useful": stats.useful,
                "noisy": stats.noisy,
                "duplicate": stats.duplicate,
                "not_applicable": stats.not_applicable,
                "precision_estimate": stats.precision_estimate,
                "confidence_weight": stats.confidence_weight,
            }
            for name, stats in self.signals.items()
        }
