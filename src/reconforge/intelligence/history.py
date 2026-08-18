"""Historical reconnaissance delta analysis."""
from __future__ import annotations

from dataclasses import dataclass

from reconforge.intelligence.normalize import normalize_url


@dataclass(frozen=True, slots=True)
class HistoricalDelta:
    url: str
    status: str
    rationale: str


def compare_urls(current: set[str], historical: set[str]) -> list[HistoricalDelta]:
    current_map = _normalized_map(current)
    historical_map = _normalized_map(historical)
    deltas: list[HistoricalDelta] = []

    for key in sorted(set(historical_map) - set(current_map)):
        representative = historical_map[key]
        deltas.append(HistoricalDelta(representative, "historical_only", "seen historically but not in the current URL set"))

    for key in sorted(set(current_map) - set(historical_map)):
        representative = current_map[key]
        deltas.append(HistoricalDelta(representative, "new", "present in current collection but absent from historical set"))

    for key in sorted(set(current_map) & set(historical_map)):
        representative = current_map[key]
        deltas.append(HistoricalDelta(representative, "persistent", "present both historically and currently after canonical normalization"))

    return deltas


def _normalized_map(values: set[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        try:
            normalized = normalize_url(value)
        except ValueError:
            normalized = value.strip()
        result.setdefault(normalized, value)
    return result
