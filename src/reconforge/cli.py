"""ReconForge command-line interface."""
from __future__ import annotations

import argparse

from . import __version__
from .runtime.orchestrator import ReconForge
from .runtime.tooling import discover_tools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reconforge", description="Precision-first reconnaissance framework for authorized research.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the MVP passive reconnaissance pipeline")
    scan.add_argument("target", help="authorized domain or URL")
    scan.add_argument("--db", default="reconforge.db", help="SQLite database path")
    scan.add_argument("--active", action="store_true", help="enable explicitly active execution profile")

    queue = sub.add_parser("queue", help="show the Hunter Queue")
    queue.add_argument("--db", default="reconforge.db")
    queue.add_argument("--limit", type=int, default=20)

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
            print(f"run:             {result.run_id}")
            print(f"observations:    {result.observations}")
            print(f"new observations:{result.new_observations}")
            print(f"hypotheses:      {result.hypotheses}")
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
    return 0
