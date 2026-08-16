"""Historical reconnaissance delta analysis."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class HistoricalDelta:
    url: str
    status: str
    rationale: str


def compare_urls(current: set[str], historical: set[str]) -> list[HistoricalDelta]:
    deltas: list[HistoricalDelta] = []
    for url in sorted(historical - current):
        deltas.append(HistoricalDelta(url, "historical_only", "seen historically but not in the current URL set"))
    for url in sorted(current - historical):
        deltas.append(HistoricalDelta(url, "new", "present in current collection but absent from historical set"))
    for url in sorted(current & historical):
        current_parts = urlsplit(url)
        if current_parts.path:
            deltas.append(HistoricalDelta(url, "persistent", "present both historically and currently"))
    return deltas
