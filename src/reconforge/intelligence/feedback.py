"""Researcher feedback loop for calibrating ranking weights.

Feedback is intentionally simple and interpretable: a researcher labels a
candidate useful/noisy/duplicate, and ReconForge maintains per-signal priors.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import log1p


@dataclass(slots=True)
class SignalStats:
    useful: int = 0
    noisy: int = 0
    duplicate: int = 0

    @property
    def utility(self) -> float:
        total = self.useful + self.noisy + self.duplicate
        if total == 0:
            return 0.5
        return (self.useful + 0.5) / (total + 1.0)


@dataclass(slots=True)
class FeedbackModel:
    signals: dict[str, SignalStats] = field(default_factory=dict)

    def record(self, signal: str, outcome: str) -> None:
        stats = self.signals.setdefault(signal, SignalStats())
        if outcome == "useful":
            stats.useful += 1
        elif outcome == "noisy":
            stats.noisy += 1
        elif outcome == "duplicate":
            stats.duplicate += 1
        else:
            raise ValueError("outcome must be useful, noisy, or duplicate")

    def weight(self, signal: str) -> float:
        """Return a bounded multiplier with conservative cold-start behavior."""
        utility = self.signals.get(signal, SignalStats()).utility
        observations = sum(vars(self.signals.get(signal, SignalStats())).values())
        trust = min(0.75, log1p(observations) / 4.0)
        return 1.0 + (utility - 0.5) * trust
