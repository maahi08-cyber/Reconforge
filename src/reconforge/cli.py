"""ReconForge command-line interface."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .intelligence.differential import compare_contexts, fingerprint
from .intelligence.history import compare_urls
from .intelligence.jsintel import analyze_script
from .intelligence.feedback import FeedbackModel
from .runtime.orchestrator import ReconForge
from .runtime.tooling import discover_tools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="Precision-first reconnaissance framework for authorized research.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the reconnaissance pipeline")
    scan.add_argument("target")
    scan.add_argument("--db", default="reconforge.db")
    scan.add_argument("--active", action="store_true", help="enable explicitly active execution profile")

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

    if args.command == "scan":
        engine = ReconForge(args.db)
        try:
            result = engine.scan(args.target, active=args.active)
            print(f"run:              {result.run_id}")
            print(f"observations:     {result.observations}")
            print(f"new observations: {result.new_observations}")
            print(f"hypotheses:       {result.hypotheses}")
            for warning in result.warnings:
                print(f"warning:          {warning}")
            print("\nTop Hunter Queue:")
            for row in engine.store.hunter_queue(20):
                print(f"  {row['confidence']:5.1f}  {row['hypothesis_type']:16}  {row['subject']}")
        finally:
            engine.close()
        return 0

    if args.command == "queue":
        engine = ReconForge(args.db)
        try:
            for row in engine.store.hunter_queue(args.limit):
                print(f"{row['confidence']:5.1f}  {row['hypothesis_type']:16}  {row['subject']}")
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
        analysis = analyze_script(args.file.read_text(errors="replace"), args.base_url)
        print("Routes:")
        for route in analysis.routes:
            print(f"  {route.confidence:0.2f}  {route.kind:12}  line {route.line:4}  {route.value}")
        print("\nSensitive-data candidates:")
        if not analysis.secrets:
            print("  none")
        for secret in analysis.secrets:
            print(f"  {secret.confidence:0.2f}  {secret.kind:28}  line {secret.line:4}  {secret.redacted}  # {secret.rationale}")
        return 0

    if args.command == "history-diff":
        current = {line.strip() for line in args.current.read_text().splitlines() if line.strip()}
        historical = {line.strip() for line in args.historical.read_text().splitlines() if line.strip()}
        for delta in compare_urls(current, historical):
            print(f"{delta.status:16} {delta.url}  # {delta.rationale}")
        return 0

    if args.command == "auth-diff":
        first_data = json.loads(args.first.read_text())
        second_data = json.loads(args.second.read_text())
        first = fingerprint(first_data["status"], first_data.get("headers", {}), first_data.get("body", "").encode(), set(first_data.get("schema_keys", [])))
        second = fingerprint(second_data["status"], second_data.get("headers", {}), second_data.get("body", "").encode(), set(second_data.get("schema_keys", [])))
        result = compare_contexts(args.endpoint, first, second, object_references_overlap=args.object_overlap)
        print(json.dumps({"endpoint": result.endpoint, "signal_strength": result.signal_strength, "rationale": result.rationale}, indent=2))
        return 0

    return 0
