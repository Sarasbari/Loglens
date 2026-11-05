"""Log parsing engine for LogLens.

This module provides specialized parser classes that convert raw,
unstructured text lines into typed LogEntry objects (NginxAccessEntry
and SyslogEntry), as well as a unified LogParser that automatically
detects the format.
"""

from datetime import datetime
from pathlib import Path
import re

from loglens.models import LogEntry, NginxAccessEntry, SyslogEntry

# =====================================================================
# Regular Expressions
# =====================================================================

# Nginx Combined / Common log format pattern.
# Example: 93.180.71.3 - - [05/Nov/2026:08:15:32 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "-"
NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'                         # Client IP (non-whitespace)
    r'\S+\s+\S+\s+'                            # Ident & auth user (e.g. - -)
    r'\[(?P<timestamp>[^\]]+)\]\s+'             # [05/Nov/2026:08:15:32 +0000]
    r'"(?P<method>[A-Z]+)\s+'                  # "GET, "POST, etc.
    r'(?P<path>\S+)\s+'                        # /path/to/resource
    r'(?P<protocol>[^"]+)"\s+'                 # HTTP/1.1"
    r'(?P<status_code>\d{3})\s+'               # HTTP status code (3 digits)
    r'(?P<body_bytes>\d+)'                     # Response body bytes (digits)
)

# Traditional BSD Syslog pattern (RFC 3164).
# Example: Nov  5 07:12:45 webserver01 sshd[2084]: Failed password for invalid user admin
SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'  # Nov  5 07:12:45
    r'(?P<hostname>\S+)\s+'                                         # webserver01
    r'(?P<service>[a-zA-Z0-9_\.\-]+)'                              # sshd or kernel
    r'(?:\[(?P<pid>\d+)\])?:\s+'                                   # optional [2084], followed by :
    r'(?P<message>.*)$'                                             # remaining payload
)

NGINX_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
SYSLOG_TIME_FORMAT = "%b %d %H:%M:%S"


# =====================================================================
# Parser Classes
# =====================================================================

class NginxParser:
    """Parser responsible for converting Nginx access log lines into NginxAccessEntry objects."""

    def parse_line(self, line: str) -> NginxAccessEntry | None:
        """Parse a single Nginx log line into a typed NginxAccessEntry.

        Args:
            line: A raw log line string.

        Returns:
            An NginxAccessEntry if the line matches the expected format,
            or None if the line is empty or malformed.
        """
        stripped = line.strip()
        if not stripped:
            return None

        match = NGINX_PATTERN.match(stripped)
        if not match:
            return None

        groups = match.groupdict()

        try:
            timestamp = datetime.strptime(groups["timestamp"], NGINX_TIME_FORMAT)
            status_code = int(groups["status_code"])
            body_bytes = int(groups["body_bytes"])
        except (ValueError, KeyError):
            return None

        return NginxAccessEntry(
            ip=groups["ip"],
            timestamp=timestamp,
            method=groups["method"],
            path=groups["path"],
            protocol=groups["protocol"],
            status_code=status_code,
            body_bytes=body_bytes,
            raw_line=stripped,
        )

    def parse_file(self, file_path: str | Path) -> list[NginxAccessEntry]:
        """Read an Nginx log file and parse all valid lines."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        entries: list[NginxAccessEntry] = []
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                entry = self.parse_line(line)
                if entry is not None:
                    entries.append(entry)

        return entries


class SyslogParser:
    """Parser responsible for converting Linux syslog lines into SyslogEntry objects."""

    def __init__(self, default_year: int = 2026) -> None:
        """Initialize the SyslogParser.

        Args:
            default_year: The year to assign to parsed timestamps, since
                RFC 3164 syslog entries omit the year. Defaults to 2026.
        """
        self.default_year = default_year

    def parse_line(self, line: str) -> SyslogEntry | None:
        """Parse a single syslog line into a typed SyslogEntry.

        Args:
            line: A raw syslog line string.

        Returns:
            A SyslogEntry if the line matches, or None if empty/malformed.
        """
        stripped = line.strip()
        if not stripped:
            return None

        match = SYSLOG_PATTERN.match(stripped)
        if not match:
            return None

        groups = match.groupdict()

        try:
            # Normalize internal multiple spaces (e.g. "Nov  5" -> "Nov 5")
            clean_ts = re.sub(r"\s+", " ", groups["timestamp"])
            parsed_dt = datetime.strptime(clean_ts, SYSLOG_TIME_FORMAT)
            timestamp = parsed_dt.replace(year=self.default_year)

            # pid is optional; None if not present in the line
            pid = int(groups["pid"]) if groups["pid"] is not None else None
        except (ValueError, KeyError):
            return None

        return SyslogEntry(
            timestamp=timestamp,
            hostname=groups["hostname"],
            service=groups["service"],
            pid=pid,
            message=groups["message"],
            raw_line=stripped,
        )

    def parse_file(self, file_path: str | Path) -> list[SyslogEntry]:
        """Read a syslog file and parse all valid lines."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        entries: list[SyslogEntry] = []
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                entry = self.parse_line(line)
                if entry is not None:
                    entries.append(entry)

        return entries


# =====================================================================
# Unified LogParser with Format Auto-Detection
# =====================================================================

def detect_format_from_line(line: str) -> str:
    """Sniff the format of a single log line.

    Returns:
        'nginx' if the line matches Nginx combined format,
        'syslog' if the line matches Linux syslog format.

    Raises:
        ValueError: If the line matches neither format.
    """
    stripped = line.strip()
    if NGINX_PATTERN.match(stripped):
        return "nginx"
    if SYSLOG_PATTERN.match(stripped):
        return "syslog"
    raise ValueError(f"Unable to detect log format from line: {line[:50]}...")


class LogParser:
    """Unified log parser facade that automatically detects or accepts the log format."""

    def __init__(self, format: str | None = None, default_year: int = 2026) -> None:
        """Initialize LogParser.

        Args:
            format: 'nginx', 'syslog', or None for auto-detection.
            default_year: Reference year used for syslog parsing.
        """
        if format is not None and format not in ("nginx", "syslog"):
            raise ValueError(f"Unsupported format: {format}. Expected 'nginx' or 'syslog'.")

        self.format = format
        self.nginx_parser = NginxParser()
        self.syslog_parser = SyslogParser(default_year=default_year)

    def detect_format_from_file(self, file_path: str | Path) -> str:
        """Determine format by reading the first non-empty line of a file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                stripped = line.strip()
                if stripped:
                    return detect_format_from_line(stripped)

        raise ValueError(f"Cannot detect format: file is empty: {file_path}")

    def parse_file(self, file_path: str | Path) -> list[LogEntry]:
        """Parse any supported log file, auto-detecting format if not specified."""
        fmt = self.format
        if fmt is None:
            fmt = self.detect_format_from_file(file_path)

        if fmt == "nginx":
            return list(self.nginx_parser.parse_file(file_path))
        elif fmt == "syslog":
            return list(self.syslog_parser.parse_file(file_path))
        else:
            raise ValueError(f"Unknown format: {fmt}")
