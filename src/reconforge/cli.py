"""ReconForge command-line interface."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .graph import AssetGraph
from .graph_query import find_security_surface, neighborhood
from .intelligence.auth_research import build_authorization_hypothesis
from .intelligence.differential import compare_contexts, fingerprint
from .intelligence.feedback import FeedbackModel
from .intelligence.history import compare_urls
from .intelligence.jsintel import analyze_script
from .release import evaluate
from .runtime.orchestrator import ReconForge
from .runtime.tooling import discover_tools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="Precision-first reconnaissance framework for authorized research.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run or resume the reconnaissance pipeline")
    scan.add_argument("target")
    scan.add_argument("--db", default="reconforge.db")
    scan.add_argument("--active", action="store_true", help="enable explicitly active execution profile")
    scan.add_argument("--scope", action="append", required=True, help="explicit in-scope host or wildcard; repeat for multiple entries")
    scan.add_argument("--deny-scope", action="append", default=[], help="explicitly excluded host or wildcard; repeatable")
    scan.add_argument("--resume", metavar="RUN_ID", help="resume a checkpointed run")

    queue = sub.add_parser("queue", help="show the Hunter Queue")
    queue.add_argument("--db", default="reconforge.db")
    queue.add_argument("--limit", type=int, default=20)

    feedback = sub.add_parser("feedback", help="record researcher feedback for a signal family")
    feedback.add_argument("--db", default="reconforge.db")
    feedback.add_argument("signal")
    feedback.add_argument("outcome", choices=("useful", "validated", "noisy", "duplicate", "invalid"))
    feedback.add_argument("--run-id")

    calib = sub.add_parser("calibration", help="show persisted signal calibration")
    calib.add_argument("--db", default="reconforge.db")

    release = sub.add_parser("release-check", help="evaluate release-readiness gates")
    release.add_argument("--benchmark-corpus", help="path to a benchmark corpus file")
    release.add_argument("--regression-dir", help="directory containing executable regression cases")

    graph = sub.add_parser("graph-query", help="query the in-memory evidence graph from a JSONL observation file")
    graph.add_argument("observations", type=Path)
    graph.add_argument("--kind")
    graph.add_argument("--contains")
    graph.add_argument("--node")
    graph.add_argument("--depth", type=int, default=1)

    js = sub.add_parser("js-analyze", help="analyze a JavaScript file for routes and sensitive-data leakage")
    js.add_argument("file", type=Path)
    js.add_argument("--base-url")

    history = sub.add_parser("history-diff", help="compare current and historical URL lists")
    history.add_argument("current", type=Path)
    history.add_argument("historical", type=Path)

    diff = sub.add_parser("auth-diff", help="compare two authorized response fixtures")
    diff.add_argument("first", type=Path, help="JSON response fingerprint fixture")
    diff.add_argument("second", type=Path, help="JSON response fingerprint fixture")
    diff.add_argument("--endpoint", required=True)
    diff.add_argument("--object-overlap", action="store_true", help="researcher-supplied object reference overlap")

    sub.add_parser("doctor", help="show discovered tool availability")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "doctor":
        for status in discover_tools():
            state = "available" if status.available else "missing"
            suffix = f" — {status.version}" if status.version else ""
            print(f"{status.name:14} {state}{suffix}")
        return 0

    if args.command == "release-check":
        report = evaluate(benchmark_file=args.benchmark_corpus, regression_dir=args.regression_dir)
        for gate in report.gates:
            state = "PASS" if gate.passed else "FAIL"
            print(f"{state:4} {gate.name:20} {gate.detail}")
        print(f"\nrelease_ready: {report.ready}")
        return 0 if report.ready else 2

    if args.command == "graph-query":
        try:
            graph = AssetGraph()
            for line in args.observations.read_text().splitlines():
                if line.strip():
                    graph.ingest(_observation_from_json(line))
            result = neighborhood(graph, args.node, depth=args.depth) if args.node else find_security_surface(graph, kind=args.kind, contains=args.contains)
            print(result.rationale)
            for node in result.nodes:
                print(f"{node.kind.value:12} {node.key} {node.label}")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", flush=True)
            return 2
        return 0

    if args.command == "scan":
        engine = ReconForge(args.db)
        try:
            result = engine.scan(args.target, active=args.active, resume_run_id=args.resume, allowed_scope=tuple(args.scope), denied_scope=tuple(args.deny_scope))
            print(f"run:              {result.run_id}")
            print(f"observations:     {result.observations}")
            print(f"new observations: {result.new_observations}")
            print(f"hypotheses:       {result.hypotheses}")
            for warning in result.warnings:
                print(f"warning:          {warning}")
            print("\nTop Hunter Queue:")
            for row in engine.store.hunter_queue(20):
                print(f"  {row['queue_priority']:5.1f}  {row['hypothesis_type']:16}  {row['subject']}")
        except ValueError as exc:
            print(f"error: {exc}", flush=True)
            return 2
        finally:
            engine.close()
        return 0

    if args.command == "queue":
        engine = ReconForge(args.db)
        try:
            for row in engine.store.hunter_queue(args.limit):
                print(f"{row['queue_priority']:5.1f}  {row['hypothesis_type']:16}  {row['subject']}")
        finally:
            engine.close()
        return 0

    if args.command == "feedback":
        engine = ReconForge(args.db)
        try:
            engine.store.record_calibration(args.signal, args.outcome, run_id=args.run_id)
            model = FeedbackModel()
            model.record(args.signal, args.outcome)
            print(json.dumps({"signal": args.signal, "outcome": args.outcome, "weight": model.weight(args.signal)}, indent=2))
        finally:
            engine.close()
        return 0

    if args.command == "calibration":
        engine = ReconForge(args.db)
        try:
            print(json.dumps(engine.store.calibration_snapshot(), indent=2, sort_keys=True))
        finally:
            engine.close()
        return 0

    if args.command == "js-analyze":
        try:
            analysis = analyze_script(args.file.read_text(errors="replace"), args.base_url)
        except OSError as exc:
            print(f"error: {exc}", flush=True)
            return 2
        print("Routes:")
        for route in analysis.routes:
            method = route.method or "-"
            print(f"  {route.confidence:0.2f}  {route.kind:12}  {method:4}  line {route.line:4}  {route.value}")
        print("\nSensitive-data candidates:")
        if not analysis.secrets:
            print("  none")
        for secret in analysis.secrets:
            print(f"  {secret.confidence:0.2f}  {secret.kind:28}  line {secret.line:4}  {secret.redacted}  # {secret.rationale}")
        return 0

    if args.command == "history-diff":
        try:
            current = {line.strip() for line in args.current.read_text().splitlines() if line.strip()}
            historical = {line.strip() for line in args.historical.read_text().splitlines() if line.strip()}
        except OSError as exc:
            print(f"error: {exc}", flush=True)
            return 2
        for delta in compare_urls(current, historical):
            print(f"{delta.status:16} {delta.url}  # {delta.rationale}")
        return 0

    if args.command == "auth-diff":
        try:
            first_data = json.loads(args.first.read_text())
            second_data = json.loads(args.second.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", flush=True)
            return 2
        first = fingerprint(first_data["status"], first_data.get("headers", {}), first_data.get("body", "").encode(), set(first_data.get("schema_keys", [])))
        second = fingerprint(second_data["status"], second_data.get("headers", {}), second_data.get("body", "").encode(), set(second_data.get("schema_keys", [])))
        result = compare_contexts(args.endpoint, first, second, object_references_overlap=args.object_overlap)
        hypothesis = build_authorization_hypothesis(result, first, second)
        print(json.dumps({
            "endpoint": result.endpoint,
            "signal_strength": result.signal_strength,
            "rationale": result.rationale,
            "research_hypothesis": {
                "type": hypothesis.hypothesis_type.value,
                "confidence": hypothesis.confidence,
                "status": hypothesis.status,
                "subject": hypothesis.subject,
            },
        }, indent=2))
        return 0

    return 0


def _observation_from_json(line: str):
    from .models import Observation, ObservationKind
    payload = json.loads(line)
    return Observation(ObservationKind(payload["kind"]), payload["subject"], payload.get("source", "import"), payload.get("run_id", "graph-import"), payload.get("attributes", {}))
