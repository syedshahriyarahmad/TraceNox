from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .history import (
    compare_snapshot_files,
    format_comparison,
    save_comparison,
    save_score_snapshot,
)


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="tracenox-history",
        description="TraceNox historical security-score comparison",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    save_parser = subparsers.add_parser(
        "save",
        help="save a security-score JSON report as a snapshot",
    )

    save_parser.add_argument(
        "report",
        help="TraceNox security-score JSON report",
    )

    save_parser.add_argument(
        "output",
        help="historical snapshot output path",
    )

    compare_parser = subparsers.add_parser(
        "compare",
        help="compare two historical security snapshots",
    )

    compare_parser.add_argument(
        "previous",
        help="previous snapshot JSON",
    )

    compare_parser.add_argument(
        "current",
        help="current snapshot JSON",
    )

    compare_parser.add_argument(
        "--output",
        help="optional comparison JSON output",
    )

    return parser


def main(argv: list[str] | None = None) -> int:

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "save":

        try:
            data = json.loads(
                Path(args.report).read_text(
                    encoding="utf-8"
                )
            )

            save_score_snapshot(
                data,
                args.output,
            )

        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        print(
            f"Historical snapshot saved: {args.output}"
        )

        return 0

    if args.command == "compare":

        try:
            comparison = compare_snapshot_files(
                args.previous,
                args.current,
            )

        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        print(format_comparison(comparison))

        if args.output:
            save_comparison(
                comparison,
                args.output,
            )

            print(
                f"\nComparison JSON saved: {args.output}"
            )

        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
