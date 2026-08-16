"""ReconForge MVP orchestration pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from reconforge.adapters.active import DnsxAdapter, HttpxAdapter, KatanaAdapter, NaabuAdapter, NmapAdapter, NucleiAdapter
from reconforge.adapters.process import GauAdapter, SubfinderAdapter, WaybackAdapter
from reconforge.graph import AssetGraph
from reconforge.intelligence.classify import classify_observations
from reconforge.intelligence.hunter import build_hypotheses
from reconforge.models import Observation, ObservationKind, Target, TargetKind
from reconforge.runtime.tooling import ToolStatus, discover_tools
from reconforge.storage.sqlite import SQLiteStore


@dataclass(frozen=True, slots=True)
class ScanResult:
    run_id: str
    observations: int
    new_observations: int
    hypotheses: int
    tool_status: tuple[ToolStatus, ...]
    warnings: tuple[str, ...] = ()


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
        warnings: list[str] = []

        passive = (SubfinderAdapter(), GauAdapter(), WaybackAdapter())
        for adapter in passive:
            if adapter.name not in available:
                continue
            items, error = adapter.collect(target, run_id)
            observations.extend(items)
            if error:
                warnings.append(f"{adapter.name}: {error}")

        if active:
            active_adapters = (HttpxAdapter(), KatanaAdapter(), DnsxAdapter(), NaabuAdapter(), NmapAdapter())
            for adapter in active_adapters:
                if adapter.name not in available:
                    continue
                items, error = adapter.collect(target, run_id)
                observations.extend(items)
                if error:
                    warnings.append(f"{adapter.name}: {error}")
        else:
            warnings.append("active adapters were not run; enable --active only for authorized active testing")

        derived: list[Observation] = []
        for item in observations:
            if item.kind in {ObservationKind.ASSET, ObservationKind.HISTORICAL, ObservationKind.HTTP, ObservationKind.ENDPOINT} and item.subject.startswith(("http://", "https://")):
                method = str(item.attributes.get("method", "GET"))
                derived.extend(classify_observations(item.subject, method=method, source="classifier", run_id=run_id))
        observations.extend(derived)

        for item in observations:
            self.graph.ingest(item)
        new_count = self.store.add_observations(observations)

        hypotheses = build_hypotheses(observations)
        for hypothesis in hypotheses:
            self.store.upsert_hypothesis(hypothesis)

        self.store.finish_run(run_id, "completed_with_warnings" if warnings else "completed")
        return ScanResult(run_id, len(observations), new_count, len(hypotheses), statuses, tuple(warnings))


def _kind(value: str) -> TargetKind:
    if value.startswith(("http://", "https://")):
        return TargetKind.URL
    return TargetKind.DOMAIN
