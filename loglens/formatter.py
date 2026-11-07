"""Output formatting engine for LogLens.

This module provides functions to format an AggregationResult into
either a human-readable text report (with tables and summaries) or
a machine-readable JSON string.
"""

from dataclasses import asdict
import json

from loglens.models import AggregationResult


def format_table(result: AggregationResult) -> str:
    """Format an AggregationResult into a clean, human-readable terminal report.

    Args:
        result: The AggregationResult containing calculated metrics.

    Returns:
        A formatted string ready to be printed to the terminal.
    """
    lines: list[str] = [
        "=" * 54,
        "             LogLens Analysis Report             ",
        "=" * 54,
        f"Total Entries Analyzed: {result.total_entries}",
        "",
    ]

    if result.total_entries == 0:
        lines.append("No entries found matching criteria.")
        return "\n".join(lines)

    # -------------------------------------------------------------
    # Nginx-Specific Metrics
    # -------------------------------------------------------------
    if result.status_counts:
        lines.append("--- HTTP Status Code Breakdown ---")
        for status, count in result.status_counts.items():
            pct = (count / result.total_entries) * 100
            lines.append(f"  {status}: {count:4d}  ({pct:5.1f}%)")
        lines.append("")

        lines.append("--- Error Summary ---")
        lines.append(f"  4xx Client Errors: {result.client_error_count}")
        lines.append(f"  5xx Server Errors: {result.server_error_count}")
        lines.append(f"  Total Data Sent:   {result.total_bytes:,} bytes")
        lines.append("")

    if result.top_ips:
        lines.append(f"--- Top {len(result.top_ips)} Client IPs ---")
        for ip, count in result.top_ips:
            lines.append(f"  {ip:<18} : {count:4d} requests")
        lines.append("")

    if result.top_paths:
        lines.append(f"--- Top {len(result.top_paths)} Requested Paths ---")
        for path, count in result.top_paths:
            lines.append(f"  {path:<28} : {count:4d} requests")
        lines.append("")

    # -------------------------------------------------------------
    # Syslog-Specific Metrics
    # -------------------------------------------------------------
    if result.host_counts:
        lines.append("--- Log Volume by Host ---")
        for host, count in result.host_counts.items():
            pct = (count / result.total_entries) * 100
            lines.append(f"  {host:<18} : {count:4d}  ({pct:5.1f}%)")
        lines.append("")

    if result.service_counts:
        lines.append("--- Events by Service ---")
        for service, count in result.service_counts.items():
            pct = (count / result.total_entries) * 100
            lines.append(f"  {service:<18} : {count:4d}  ({pct:5.1f}%)")
        lines.append("")

    # -------------------------------------------------------------
    # Shared Timeline Metric
    # -------------------------------------------------------------
    if result.entries_per_hour:
        lines.append("--- Activity by Hour ---")
        for hour, count in result.entries_per_hour.items():
            bar = "#" * max(1, int((count / result.total_entries) * 20))
            lines.append(f"  {hour} : {count:4d} requests [{bar}]")
        lines.append("")

    return "\n".join(lines).rstrip()


def format_json(result: AggregationResult) -> str:
    """Format an AggregationResult into an indented JSON string.

    Args:
        result: The AggregationResult containing calculated metrics.

    Returns:
        A serialized JSON string.
    """
    return json.dumps(asdict(result), indent=2)


def format_result(result: AggregationResult, format_type: str = "table") -> str:
    """Dispatch formatting to either table or json based on format_type.

    Args:
        result: The AggregationResult to format.
        format_type: 'table' or 'json'. Defaults to 'table'.

    Returns:
        The formatted string.

    Raises:
        ValueError: If format_type is not 'table' or 'json'.
    """
    fmt = format_type.lower()
    if fmt == "table":
        return format_table(result)
    elif fmt == "json":
        return format_json(result)
    else:
        raise ValueError(f"Unsupported format type: {format_type}. Expected 'table' or 'json'.")

