"""Command-line interface (CLI) entry point for LogLens.

This module is the orchestrator: it parses command-line arguments using
argparse, wires the parser, filter, aggregator, prompt builder, LLM client,
validator, and formatter together, and prints the resulting output to standard output.
"""

import argparse
from collections.abc import Sequence
from dataclasses import asdict
import json
import sys

from loglens.aggregator import Aggregator
from loglens.filter import FilterEngine
from loglens.formatter import format_result
from loglens.llm_client import GeminiClient
from loglens.models import FilterCriteria, NginxAccessEntry, SyslogEntry
from loglens.parser import LogParser
from loglens.prompt_builder import PromptBuilder
from loglens.validator import IncidentValidator


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

    analyze_parser.add_argument(
        "--summarize",
        action="store_true",
        help="Request an LLM-assisted incident summary from Google Gemini.",
    )

    analyze_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed diagnostic and execution logging to stderr.",
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
        if args.verbose:
            detected = parser.detect_format_from_file(args.file)
            print(f"[VERBOSE] Target file: '{args.file}' (Detected format: {detected})", file=sys.stderr)

        entries = parser.parse_file(args.file)

        if args.verbose:
            print(f"[VERBOSE] Successfully parsed {len(entries)} valid log entries.", file=sys.stderr)

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
            before_count = len(entries)
            entries = engine.filter(entries, criteria)
            if args.verbose:
                print(f"[VERBOSE] Filter applied: {before_count} -> {len(entries)} entries remaining.", file=sys.stderr)

        # 3. Aggregate metrics
        aggregator = Aggregator(top_n=args.top)
        result = aggregator.aggregate(entries)

        # 4. Optional: LLM Incident Summarization with Strict Output Validation
        if args.summarize:
            error_keywords = ("fail", "error", "oom", "timeout", "refused", "lock")
            evidence_entries = [
                e
                for e in entries
                if (isinstance(e, NginxAccessEntry) and e.status_code >= 400)
                or (isinstance(e, SyslogEntry) and any(w in e.message.lower() for w in error_keywords))
            ] or list(entries)

            if args.verbose:
                print(f"[VERBOSE] Assembling prompt with {len(evidence_entries)} evidence candidate entries...", file=sys.stderr)

            prompt_builder = PromptBuilder(max_evidence=10)
            prompt = prompt_builder.build_prompt(result, evidence_entries=evidence_entries)

            if args.verbose:
                print(f"[VERBOSE] Querying Google Gemini 2.0 Flash API...", file=sys.stderr)

            client = GeminiClient()
            summary_json = client.generate_summary(prompt)

            # Pass raw LLM response through the trust boundary (IncidentValidator)
            validator = IncidentValidator()
            val_result = validator.validate(
                raw_llm_json=summary_json,
                result=result,
                source_entries=entries,
            )

            if args.verbose:
                status_word = "PASSED" if val_result.is_valid else f"FAILED ({len(val_result.errors)} errors)"
                print(f"[VERBOSE] Three-Layer Validation result: {status_word}", file=sys.stderr)

            if args.format == "json":
                data = asdict(result)
                if val_result.is_valid and val_result.report is not None:
                    data["incident_report"] = asdict(val_result.report)
                else:
                    data["validation_error"] = {
                        "status": "rejected",
                        "reasons": val_result.errors,
                        "raw_llm_output": summary_json,
                    }
                print(json.dumps(data, indent=2))
            else:
                table_output = format_result(result, format_type="table")
                print(table_output)
                print("\n" + "=" * 54)

                if val_result.is_valid and val_result.report is not None:
                    incident = val_result.report
                    print("         Verified LLM Incident Analysis (Gemini) ")
                    print("=" * 54)
                    print(f"Title:            {incident.title}")
                    print(f"Severity:         {incident.severity.upper()}")
                    print(f"Affected Service: {incident.affected_service}")
                    print(f"Error Count:      {incident.error_count} (Verified ✅)")
                    print(f"\nSummary:\n  {incident.summary}")
                    if incident.evidence_lines:
                        print("\nEvidence Cited (Verified against source logs ✅):")
                        for ev in incident.evidence_lines:
                            print(f"  • {ev}")
                else:
                    print("    [WARNING] LLM Incident Report Failed Validation   ")
                    print("=" * 54)
                    print("The LLM-generated incident summary was rejected because it failed")
                    print("our strict verification checks:\n")
                    for err in val_result.errors:
                        print(f"  ❌ {err}")
                    print("\nShowing verified deterministic results only.")

            return 0

        # Standard deterministic output (no LLM)
        output = format_result(result, format_type=args.format)
        print(output)
        return 0

    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except ValueError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    except RuntimeError as err:
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
