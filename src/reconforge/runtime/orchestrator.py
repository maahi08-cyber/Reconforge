"""ReconForge MVP orchestration pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from reconforge.adapters.process import GauAdapter, SubfinderAdapter, WaybackAdapter
from reconforge.graph import AssetGraph
from reconforge.intelligence.classify import classify_observations
from reconforge.intelligence.hunter import build_hypotheses
from reconforge.models import Observation, ObservationKind, Target, TargetKind
from reconforge.runtime.tooling import ToolStatus, discover_tools
from reconforge.scope import ScopePolicy
from reconforge.storage.sqlite import SQLiteStore


@dataclass(frozen=True, slots=True)
class ScanResult:
    run_id: str
    observations: int
    new_observations: int
    hypotheses: int
    tool_status: tuple[ToolStatus, ...]


class ReconForge:
    """Coordinates the evidence-first MVP without making vulnerability claims."""

    def __init__(self, db_path: str = "reconforge.db") -> None:
        self.store = SQLiteStore(db_path)
        self.graph = AssetGraph()

    def close(self) -> None:
        self.store.close()

    def scan(self, target_value: str, *, active: bool = False) -> ScanResult:
        target = Target(target_value, _kind(target_value), True)
        run_id = uuid4().hex
        self.store.start_run(run_id, target_value)
        statuses = tuple(discover_tools())
        available = {item.name for item in statuses if item.available}
        observations: list[Observation] = []
        errors: list[str] = []

        # Passive-first collection gives the researcher a useful inventory before probes.
        for adapter in (SubfinderAdapter(), GauAdapter(), WaybackAdapter()):
            if adapter.name not in available:
                continue
            items, error = adapter.collect(target, run_id)
            observations.extend(items)
            if error:
                errors.append(f"{adapter.name}: {error}")

        # Convert discovered URL observations into security-relevant semantic observations.
        derived: list[Observation] = []
        for item in observations:
            if item.kind in {ObservationKind.ASSET, ObservationKind.HISTORICAL} and item.subject.startswith(("http://", "https://")):
                derived.extend(classify_observations(item.subject, source="classifier", run_id=run_id))
        observations.extend(derived)

        # Active mode is deliberately explicit. MVP collection remains conservative.
        if active:
            errors.append("active collection requested: use explicit active adapters in the configured execution profile")

        for item in observations:
            self.graph.ingest(item)
        new_count = self.store.add_observations(observations)

        hypotheses = build_hypotheses(observations)
        for hypothesis in hypotheses:
            self.store.upsert_hypothesis(hypothesis)

        self.store.finish_run(run_id, "completed" if not errors else "completed_with_warnings")
        return ScanResult(run_id, len(observations), new_count, len(hypotheses), statuses)


def _kind(value: str) -> TargetKind:
    if value.startswith(("http://", "https://")):
        return TargetKind.URL
    return TargetKind.DOMAIN
