"""Researcher feedback loop for calibrating ranking weights.

Feedback remains interpretable and conservative. It changes trust in signal
families gradually instead of allowing a handful of labels to rewrite ranking.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import log1p


@dataclass(slots=True)
class SignalStats:
    useful: int = 0
    validated: int = 0
    noisy: int = 0
    duplicate: int = 0
    invalid: int = 0

    @property
    def utility(self) -> float:
        total = self.useful + self.validated + self.noisy + self.duplicate + self.invalid
        if total == 0:
            return 0.5
        positive = self.useful + self.validated * 1.25
        negative = self.noisy + self.duplicate * 0.8 + self.invalid * 1.15
        return max(0.0, min(1.0, (positive + 0.5) / (positive + negative + 1.0)))


@dataclass(slots=True)
class FeedbackModel:
    signals: dict[str, SignalStats] = field(default_factory=dict)

    def record(self, signal: str, outcome: str) -> None:
        stats = self.signals.setdefault(signal, SignalStats())
        if outcome == "useful":
            stats.useful += 1
        elif outcome == "validated":
            stats.validated += 1
        elif outcome == "noisy":
            stats.noisy += 1
        elif outcome == "duplicate":
            stats.duplicate += 1
        elif outcome == "invalid":
            stats.invalid += 1
        else:
            raise ValueError("unknown feedback outcome")

    def weight(self, signal: str) -> float:
        """Return a cold-start-safe multiplier bounded to 0.75..1.25."""
        stats = self.signals.get(signal, SignalStats())
        total = stats.useful + stats.validated + stats.noisy + stats.duplicate + stats.invalid
        trust = min(0.75, log1p(total) / 4.0)
        utility = stats.utility
        multiplier = 1.0 + (utility - 0.5) * trust
        return max(0.75, min(1.25, multiplier))

    def snapshot(self) -> dict[str, dict[str, int]]:
        return {signal: vars(stats).copy() for signal, stats in self.signals.items()}
