"""Aggregation engine for LogLens.

This module provides the Aggregator class, which computes statistical summaries,
frequency distributions, and top-N rankings from parsed LogEntry objects.
"""

from collections import Counter
from collections.abc import Sequence

from loglens.models import AggregationResult, LogEntry, NginxAccessEntry, SyslogEntry


class Aggregator:
    """Computes quantitative metrics and rankings from parsed log entries."""

    def __init__(self, top_n: int = 5) -> None:
        """Initialize the Aggregator.

        Args:
            top_n: Number of top elements to retain in rankings (e.g. top 5 IPs).

        Raises:
            ValueError: If top_n is not a positive integer.
        """
        if top_n <= 0:
            raise ValueError(f"top_n must be a positive integer, got {top_n}")
        self.top_n = top_n

    def aggregate(self, entries: Sequence[LogEntry]) -> AggregationResult:
        """Compute statistics across a sequence of parsed log entries.

        Args:
            entries: Sequence of parsed NginxAccessEntry or SyslogEntry objects.

        Returns:
            An AggregationResult dataclass containing computed counts,
            rankings, and distributions.
        """
        if not entries:
            return AggregationResult()

        status_counter: Counter[int] = Counter()
        ip_counter: Counter[str] = Counter()
        path_counter: Counter[str] = Counter()
        host_counter: Counter[str] = Counter()
        service_counter: Counter[str] = Counter()
        hour_counter: Counter[str] = Counter()

        client_errors = 0
        server_errors = 0
        total_bytes = 0

        for entry in entries:
            # Shared time bucketing: '08:00', '09:00', etc.
            hour_key = entry.timestamp.strftime("%H:00")
            hour_counter[hour_key] += 1

            if isinstance(entry, NginxAccessEntry):
                status_counter[entry.status_code] += 1
                if 400 <= entry.status_code <= 499:
                    client_errors += 1
                elif 500 <= entry.status_code <= 599:
                    server_errors += 1

                total_bytes += entry.body_bytes
                ip_counter[entry.ip] += 1
                path_counter[entry.path] += 1

            elif isinstance(entry, SyslogEntry):
                host_counter[entry.hostname] += 1
                service_counter[entry.service] += 1

        # Sort hours chronologically
        sorted_hours = dict(sorted(hour_counter.items()))

        return AggregationResult(
            total_entries=len(entries),
            status_counts=dict(status_counter.most_common()),
            client_error_count=client_errors,
            server_error_count=server_errors,
            total_bytes=total_bytes,
            top_ips=ip_counter.most_common(self.top_n),
            top_paths=path_counter.most_common(self.top_n),
            host_counts=dict(host_counter.most_common()),
            service_counts=dict(service_counter.most_common()),
            entries_per_hour=sorted_hours,
        )

