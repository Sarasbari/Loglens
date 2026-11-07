"""Command-line interface (CLI) entry point for LogLens.

This module is the orchestrator: it parses command-line arguments using
argparse, wires the parser, filter, aggregator, and formatter together,
and prints the resulting output to standard output.
"""

import argparse
from collections.abc import Sequence
import sys

from loglens.aggregator import Aggregator
from loglens.filter import FilterEngine
from loglens.formatter import format_result
from loglens.models import FilterCriteria
from loglens.parser import LogParser


def build_parser() -> argparse.ArgumentParser:
    """Construct and configure the argparse ArgumentParser for LogLens."""
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="LogLens: Turn raw server logs into structured, validated answers.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -------------------------------------------------------------
    # 'analyze' subcommand
    # -------------------------------------------------------------
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a log file (Nginx or Syslog) and compute metrics.",
    )

    analyze_parser.add_argument(
        "file",
        help="Path to the log file to analyze.",
    )

    analyze_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format: 'table' (human-readable) or 'json' (machine-readable). Default: table.",
    )

    analyze_parser.add_argument(
        "--status",
        type=int,
        default=None,
        help="Filter by exact HTTP status code (e.g. 500).",
    )

    analyze_parser.add_argument(
        "--min-status",
        type=int,
        default=None,
        help="Filter by minimum HTTP status code (e.g. 500 for server errors).",
    )

    analyze_parser.add_argument(
        "--max-status",
        type=int,
        default=None,
        help="Filter by maximum HTTP status code (e.g. 599).",
    )

    analyze_parser.add_argument(
        "--ip",
        type=str,
        default=None,
        help="Filter by client IP address.",
    )

    analyze_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Filter by request path substring or regex pattern (Nginx).",
    )

    analyze_parser.add_argument(
        "--service",
        type=str,
        default=None,
        help="Filter by system service name (Syslog, e.g. sshd).",
    )

    analyze_parser.add_argument(
        "--pattern",
        type=str,
        default=None,
        help="Filter by message substring or regex pattern.",
    )

    analyze_parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top items to show in rankings (default: 5).",
    )

    return parser


def run_analysis(args: argparse.Namespace) -> int:
    """Execute the analyze workflow using the parsed arguments.

    Returns:
        0 on success, non-zero on error.
    """
    try:
        # 1. Parse log file
        parser = LogParser()
        entries = parser.parse_file(args.file)

        # 2. Determine and apply filter criteria if requested
        min_status = args.status if args.status is not None else args.min_status
        max_status = args.status if args.status is not None else args.max_status

        criteria = FilterCriteria(
            min_status=min_status,
            max_status=max_status,
            ip=args.ip,
            path_pattern=args.path,
            service=args.service,
            message_pattern=args.pattern,
        )

        has_filters = any(
            v is not None
            for v in (min_status, max_status, args.ip, args.path, args.service, args.pattern)
        )

        if has_filters:
            engine = FilterEngine()
            entries = engine.filter(entries, criteria)

        # 3. Aggregate metrics
        aggregator = Aggregator(top_n=args.top)
        result = aggregator.aggregate(entries)

        # 4. Format and print output
        output = format_result(result, format_type=args.format)
        print(output)
        return 0

    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected error: {err}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint.

    Args:
        argv: Command line arguments. If None, uses sys.argv[1:].

    Returns:
        Exit code integer (0 for success).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return run_analysis(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())

