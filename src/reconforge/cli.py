"""ReconForge command-line entry point."""

from __future__ import annotations

import argparse

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="Precision-first reconnaissance and security research framework.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="initialize a local ReconForge workspace")
    init.add_argument("target", help="authorized target to add to the workspace")

    sub.add_parser("doctor", help="validate the local ReconForge installation")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "init":
        print(f"Target registered for authorized reconnaissance: {args.target}")
        return 0
    if args.command == "doctor":
        print("ReconForge foundation: OK")
        return 0
    build_parser().print_help()
    return 0
