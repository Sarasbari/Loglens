"""Data models for LogLens.

This module defines the data structures that every other module
in the project imports. It is the single source of truth for
what a parsed log entry, query criteria, aggregation metrics,
and validated incident reports look like.

Design decision: We use two separate dataclasses (NginxAccessEntry
and SyslogEntry) instead of one class with Optional fields. This
means every field on each class is guaranteed to exist — no None
checks needed. The trade-off is that downstream code must handle
both types, typically with isinstance() checks or Union types.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NginxAccessEntry:
    """A single parsed line from an Nginx access log.

    Format (Combined Log Format):
        93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /path HTTP/1.1" 304 0

    Every field is required and non-None because the parser only
    creates this object when all fields are successfully extracted.

    Attributes:
        ip:          The client IP address that made the request.
        timestamp:   When the request was received by the server.
        method:      The HTTP method (GET, POST, PUT, DELETE, etc.).
        path:        The URL path that was requested.
        protocol:    The HTTP protocol version (e.g., "HTTP/1.1").
        status_code: The HTTP response status code (e.g., 200, 404, 500).
        body_bytes:  The size of the response body in bytes.
        raw_line:    The original unparsed log line. Kept for evidence
                     tracing — the LLM validator will check that cited
                     evidence lines actually exist in the source data.
    """

    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status_code: int
    body_bytes: int
    raw_line: str


@dataclass
class SyslogEntry:
    """A single parsed line from a Linux syslog file.

    Format (traditional BSD syslog):
        Nov  3 10:15:42 webserver01 sshd[12345]: Failed password for root

    Attributes:
        timestamp:  When the event was logged. Note: traditional syslog
                    does not include the year, so the parser must infer
                    it (typically the current year).
        hostname:   The machine that generated the log entry.
        service:    The service/program name (e.g., "sshd", "cron").
        pid:        The process ID, if present in the log line.
                    Some syslog entries omit the PID (e.g., "kernel:"
                    instead of "kernel[123]:"), so this is int | None.
        message:    The log message content after the service name.
        raw_line:   The original unparsed log line, kept for evidence
                    tracing.
    """

    timestamp: datetime
    hostname: str
    service: str
    pid: int | None
    message: str
    raw_line: str


# Type alias: a LogEntry is either an NginxAccessEntry or a SyslogEntry.
LogEntry = NginxAccessEntry | SyslogEntry


@dataclass
class FilterCriteria:
    """Criteria used to filter parsed log entries.

    All attributes default to None. If an attribute is set, entries must
    match that condition. When multiple attributes are set, an entry must
    match ALL of them (Boolean AND logic).
    """

    min_status: int | None = None
    max_status: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    ip: str | None = None
    path_pattern: str | None = None
    service: str | None = None
    message_pattern: str | None = None


@dataclass
class AggregationResult:
    """Statistical summary of a collection of log entries.

    Holds deterministically computed counts, distributions, and rankings.
    These numbers serve as the ground truth for reports and LLM validation.
    """

    total_entries: int = 0

    # Nginx-specific metrics
    status_counts: dict[int, int] = field(default_factory=dict)
    client_error_count: int = 0
    server_error_count: int = 0
    total_bytes: int = 0
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)

    # Syslog-specific metrics
    host_counts: dict[str, int] = field(default_factory=dict)
    service_counts: dict[str, int] = field(default_factory=dict)

    # Shared temporal metric
    entries_per_hour: dict[str, int] = field(default_factory=dict)


@dataclass
class IncidentReport:
    """Validated, structured incident report produced by LLM analysis.

    Attributes:
        title: Short descriptive title of the incident.
        severity: Incident severity level ('low', 'medium', 'high', 'critical').
        affected_service: Name of the primary service or endpoint affected.
        error_count: Number of errors (verified against deterministic aggregation).
        summary: Clear narrative describing root cause and operational impact.
        evidence_lines: List of verbatim log lines supporting the report.
    """

    title: str
    severity: str
    affected_service: str
    error_count: int
    summary: str
    evidence_lines: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    """Result of validating an LLM-generated incident report.

    Attributes:
        is_valid: True if all structural, mathematical, and evidence checks passed.
        report: The validated IncidentReport instance if is_valid is True, else None.
        errors: Detailed list of reasons explaining why validation failed.
    """

    is_valid: bool
    report: IncidentReport | None = None
    errors: list[str] = field(default_factory=list)
