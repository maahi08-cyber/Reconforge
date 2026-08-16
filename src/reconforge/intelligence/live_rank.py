"""Apply conservative calibration weights to Hunter Queue candidates.

Calibration changes ranking gently; it never turns weak evidence into a
finding and never uses researcher outcomes as a binary vulnerability oracle.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from reconforge.intelligence.calibration import CalibrationModel
from reconforge.models import Hypothesis


def calibrated_hypotheses(items: Iterable[Hypothesis], model: CalibrationModel, *, signal_names: dict[str, str] | None = None) -> list[Hypothesis]:
    result: list[Hypothesis] = []
    signal_names = signal_names or {}
    for item in items:
        signal = signal_names.get(item.subject, item.hypothesis_type.value)
        factor = model.weight(signal)
        confidence = max(0.0, min(100.0, item.confidence * factor))
        clone = replace(item, confidence=confidence)
        result.append(clone)
    return sorted(result, key=lambda value: (value.confidence, value.novelty), reverse=True)
