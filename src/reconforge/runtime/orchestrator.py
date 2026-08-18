"""ReconForge MVP orchestration pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from reconforge.adapters.active import DnsxAdapter, HttpxAdapter, KatanaAdapter, NaabuAdapter, NmapAdapter, NucleiAdapter
from reconforge.adapters.process import GauAdapter, SubfinderAdapter, WaybackAdapter
from reconforge.graph import AssetGraph
from reconforge.intelligence.calibration import CalibrationModel
from reconforge.intelligence.classify import classify_observations
from reconforge.intelligence.hunter import build_hypotheses
from reconforge.intelligence.hunter_queue import rank_hypotheses
from reconforge.models import Observation, ObservationKind, Target, TargetKind
from reconforge.runtime.checkpoints import Checkpoint, load as load_checkpoint, save as save_checkpoint
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
    warnings: tuple[str, ...] = ()


class ReconForge:
    """Coordinates the evidence-first pipeline with explicit scope enforcement."""

    def __init__(self, db_path: str = "reconforge.db", checkpoint_dir: str = ".reconforge/checkpoints") -> None:
        self.store = SQLiteStore(db_path)
        self.graph = AssetGraph()
        self.checkpoint_dir = Path(checkpoint_dir)

    def close(self) -> None:
        self.store.close()

    def scan(
        self,
        target_value: str,
        *,
        active: bool = False,
        resume_run_id: str | None = None,
        allowed_scope: tuple[str, ...] = (),
        denied_scope: tuple[str, ...] = (),
    ) -> ScanResult:
        if not allowed_scope:
            raise ValueError("explicit scope is required; provide at least one --scope entry")

        policy = ScopePolicy(tuple(allowed_scope), tuple(denied_scope))
        if not policy.allows(target_value):
            raise ValueError("target is outside the configured scope")

        target = Target(target_value, _kind(target_value), True)
        run_id = resume_run_id or uuid4().hex
        checkpoint_path = self.checkpoint_dir / f"{run_id}.json"
        completed: set[str] = set()
        warnings: list[str] = []

        if resume_run_id and checkpoint_path.exists():
            checkpoint = load_checkpoint(checkpoint_path)
            if checkpoint.target != target_value:
                raise ValueError("resume target does not match checkpoint target")
            completed = set(checkpoint.completed_sensors)
            self.store.record_event(run_id, "run.resumed", completed_sensors=sorted(completed))
        else:
            self.store.start_run(run_id, target_value)

        statuses = tuple(discover_tools())
        available = {item.name for item in statuses if item.available}
        observations: list[Observation] = []

        adapters = [SubfinderAdapter(), GauAdapter(), WaybackAdapter()]
        if active:
            adapters.extend([HttpxAdapter(), KatanaAdapter(), DnsxAdapter(), NaabuAdapter(), NmapAdapter(), NucleiAdapter()])
        else:
            warnings.append("active adapters were not run; enable --active only for authorized active testing")

        for adapter in adapters:
            if adapter.name in completed or adapter.name not in available:
                continue
            items, error = adapter.collect(target, run_id)
            observations.extend(items)
            if error:
                warnings.append(f"{adapter.name}: {error}")
            completed.add(adapter.name)
            save_checkpoint(Checkpoint.new(run_id, target_value, tuple(sorted(completed))), checkpoint_path)
            self.store.record_event(run_id, "sensor.completed", sensor=adapter.name, error=bool(error))

        derived: list[Observation] = []
        for item in observations:
            if item.kind in {ObservationKind.ASSET, ObservationKind.HISTORICAL, ObservationKind.HTTP, ObservationKind.ENDPOINT} and item.subject.startswith(("http://", "https://")):
                method = str(item.attributes.get("method", "GET"))
                derived.extend(classify_observations(item.subject, method=method, source="classifier", run_id=run_id))
        observations.extend(derived)

        for item in observations:
            self.graph.ingest(item)
        new_count = self.store.add_observations(observations)

        calibration = CalibrationModel()
        for signal, outcomes in self.store.calibration_snapshot().items():
            for outcome, count in outcomes.items():
                for _ in range(count):
                    try:
                        calibration.record(signal, outcome)
                    except ValueError:
                        continue

        hypotheses = build_hypotheses(observations)
        for hypothesis in hypotheses:
            multiplier = calibration.weight(hypothesis.hypothesis_type.value)
            hypothesis.confidence = min(100.0, hypothesis.confidence * multiplier)

        queue_items = rank_hypotheses(hypotheses, limit=max(20, len(hypotheses)))
        ranked = [(item.hypothesis, item.priority, item.rationale) for item in queue_items]
        self.store.upsert_hypotheses(ranked)

        if queue_items:
            self.store.record_event(
                run_id,
                "hunter_queue.ranked",
                candidates=len(queue_items),
                top_subject=queue_items[0].hypothesis.subject,
                top_priority=round(queue_items[0].priority, 3),
            )

        expected = {adapter.name for adapter in adapters if adapter.name in available}
        finished = expected.issubset(completed)
        status = "completed_with_warnings" if warnings else "completed"
        if finished:
            self.store.finish_run(run_id, status)
        else:
            self.store.record_event(run_id, "run.checkpointed", completed_sensors=sorted(completed))
        return ScanResult(run_id, len(observations), new_count, len(hypotheses), statuses, tuple(warnings))


def _kind(value: str) -> TargetKind:
    if value.startswith(("http://", "https://")):
        return TargetKind.URL
    return TargetKind.DOMAIN
