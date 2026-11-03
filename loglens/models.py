"""Data models for LogLens.

This module defines the data structures that every other module
in the project imports. It is the single source of truth for
what a parsed log entry looks like.

Design decision: We use two separate dataclasses (NginxAccessEntry
and SyslogEntry) instead of one class with Optional fields. This
means every field on each class is guaranteed to exist — no None
checks needed. The trade-off is that downstream code must handle
both types, typically with isinstance() checks or Union types.
"""

from dataclasses import dataclass
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
# This lets downstream modules write functions like:
#     def filter_entries(entries: list[LogEntry]) -> list[LogEntry]:
# without committing to a specific format. Internally, they use
# isinstance() to check which type they have when format-specific
# logic is needed.
LogEntry = NginxAccessEntry | SyslogEntry

