"""Tests for the LogLens parsing engine (NginxParser, SyslogParser, LogParser).

These tests verify:
1. Valid Nginx access log lines are accurately parsed into NginxAccessEntry objects.
2. Valid Linux syslog lines are accurately parsed into SyslogEntry objects.
3. Both PID-present and PID-absent syslog lines are handled cleanly.
4. Syslog timestamps with variable day spacing ('Nov  5' vs 'Nov 15') are parsed.
5. Missing year in syslog is properly assigned to the reference year.
6. Malformed and blank lines in both formats are skipped gracefully without crashing.
7. File parsing accurately loads all lines from both sample logs.
8. Status code and host distribution match Phase 1 Unix pipeline ground truths.
9. Format auto-detection successfully identifies Nginx and Syslog files.
10. Explicit format specification and invalid format handling work as intended.
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import pytest

from loglens.models import NginxAccessEntry, SyslogEntry
from loglens.parser import (
    LogParser,
    NginxParser,
    SyslogParser,
    detect_format_from_line,
)


# =====================================================================
# NginxParser Tests
# =====================================================================

class TestNginxParser:
    """Unit tests for NginxParser."""

    @pytest.fixture
    def parser(self) -> NginxParser:
        return NginxParser()

    def test_parse_valid_nginx_line(self, parser: NginxParser) -> None:
        raw_line = (
            '93.180.71.3 - - [05/Nov/2026:08:15:32 +0000] '
            '"GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"'
        )
        entry = parser.parse_line(raw_line)

        assert entry is not None
        assert isinstance(entry, NginxAccessEntry)
        assert entry.ip == "93.180.71.3"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.protocol == "HTTP/1.1"
        assert entry.status_code == 200
        assert isinstance(entry.status_code, int)
        assert entry.body_bytes == 4523
        assert isinstance(entry.body_bytes, int)
        assert entry.raw_line == raw_line

        expected_dt = datetime(2026, 11, 5, 8, 15, 32, tzinfo=timezone.utc)
        assert entry.timestamp == expected_dt

    def test_parse_empty_and_whitespace_lines(self, parser: NginxParser) -> None:
        assert parser.parse_line("") is None
        assert parser.parse_line("   ") is None
        assert parser.parse_line("\n\t  \n") is None

    def test_parse_malformed_syntax(self, parser: NginxParser) -> None:
        assert parser.parse_line("This is not a log line") is None
        assert parser.parse_line("127.0.0.1 incomplete line") is None
        assert parser.parse_line('127.0.0.1 - - [05/Nov/2026:08:15:32 +0000] GET /index.html 200 100') is None

    def test_parse_invalid_timestamp_returns_none(self, parser: NginxParser) -> None:
        malformed_date_line = (
            '93.180.71.3 - - [99/BadMonth/9999:99:99:99 +0000] '
            '"GET /index.html HTTP/1.1" 200 4523 "-" "-"'
        )
        assert parser.parse_line(malformed_date_line) is None

    def test_parse_sample_file_matches_ground_truth(self, parser: NginxParser) -> None:
        sample_path = Path("samples/nginx_sample.log")
        entries = parser.parse_file(sample_path)

        assert len(entries) == 25

        status_counts = Counter(entry.status_code for entry in entries)
        assert status_counts[200] == 12
        assert status_counts[404] == 5
        assert status_counts[500] == 4
        assert status_counts[502] == 3
        assert status_counts[304] == 1

    def test_parse_file_not_found(self, parser: NginxParser) -> None:
        with pytest.raises(FileNotFoundError):
            parser.parse_file("non_existent_directory/fake_log.log")


# =====================================================================
# SyslogParser Tests
# =====================================================================

class TestSyslogParser:
    """Unit tests for SyslogParser."""

    @pytest.fixture
    def parser(self) -> SyslogParser:
        return SyslogParser(default_year=2026)

    def test_parse_valid_syslog_with_pid(self, parser: SyslogParser) -> None:
        raw = "Nov  5 07:12:45 webserver01 sshd[2084]: Failed password for invalid user admin from 198.51.100.4"
        entry = parser.parse_line(raw)

        assert entry is not None
        assert isinstance(entry, SyslogEntry)
        assert entry.timestamp == datetime(2026, 11, 5, 7, 12, 45)
        assert entry.hostname == "webserver01"
        assert entry.service == "sshd"
        assert entry.pid == 2084
        assert isinstance(entry.pid, int)
        assert entry.message == "Failed password for invalid user admin from 198.51.100.4"
        assert entry.raw_line == raw

    def test_parse_valid_syslog_without_pid(self, parser: SyslogParser) -> None:
        raw = "Nov  5 07:45:22 webserver01 kernel: [ 4812.193021] TCP: request_sock_TCP: Possible SYN flooding"
        entry = parser.parse_line(raw)

        assert entry is not None
        assert isinstance(entry, SyslogEntry)
        assert entry.service == "kernel"
        assert entry.pid is None
        assert "Possible SYN flooding" in entry.message

    def test_parse_single_vs_double_space_day(self, parser: SyslogParser) -> None:
        # Day with double space (e.g. "Nov  5")
        entry1 = parser.parse_line("Nov  5 12:00:00 myhost app[10]: msg")
        assert entry1 is not None
        assert entry1.timestamp.day == 5

        # Day with single space (e.g. "Nov 15")
        entry2 = parser.parse_line("Nov 15 12:00:00 myhost app[10]: msg")
        assert entry2 is not None
        assert entry2.timestamp.day == 15

    def test_parse_empty_and_malformed_syslog(self, parser: SyslogParser) -> None:
        assert parser.parse_line("") is None
        assert parser.parse_line("   \n") is None
        assert parser.parse_line("Random unstructured text line") is None
        assert parser.parse_line("Nov 99 99:99:99 myhost app: invalid date") is None

    def test_parse_syslog_sample_file_matches_ground_truth(self, parser: SyslogParser) -> None:
        """Verify parity against Phase 1 Unix pipeline for samples/syslog_sample.log."""
        entries = parser.parse_file("samples/syslog_sample.log")

        # 1. Total entries: 25
        assert len(entries) == 25

        # 2. Host distribution matches Phase 1:
        # 20 webserver01, 4 db-primary, 1 cache01
        host_counts = Counter(entry.hostname for entry in entries)
        assert host_counts["webserver01"] == 20
        assert host_counts["db-primary"] == 4
        assert host_counts["cache01"] == 1

        # 3. Top services match Phase 1:
        service_counts = Counter(entry.service for entry in entries)
        assert service_counts["systemd"] == 7
        assert service_counts["sshd"] == 6
        assert service_counts["CRON"] == 4
        assert service_counts["postgresql"] == 3
        assert service_counts["nginx"] == 2
        assert service_counts["kernel"] == 2
        assert service_counts["redis"] == 1


# =====================================================================
# Unified LogParser and Auto-Detection Tests
# =====================================================================

class TestLogParserFacade:
    """Unit tests for format sniffing and the unified LogParser class."""

    def test_detect_format_from_line(self) -> None:
        nginx_line = '127.0.0.1 - - [05/Nov/2026:08:15:32 +0000] "GET / HTTP/1.1" 200 100'
        syslog_line = "Nov  5 07:12:45 webserver01 sshd[2084]: Failed password"

        assert detect_format_from_line(nginx_line) == "nginx"
        assert detect_format_from_line(syslog_line) == "syslog"

        with pytest.raises(ValueError, match="Unable to detect log format"):
            detect_format_from_line("Some random non-log string")

    def test_logparser_auto_detects_files(self) -> None:
        parser = LogParser()

        nginx_entries = parser.parse_file("samples/nginx_sample.log")
        assert len(nginx_entries) == 25
        assert all(isinstance(e, NginxAccessEntry) for e in nginx_entries)

        syslog_entries = parser.parse_file("samples/syslog_sample.log")
        assert len(syslog_entries) == 25
        assert all(isinstance(e, SyslogEntry) for e in syslog_entries)

    def test_logparser_explicit_format(self) -> None:
        parser = LogParser(format="nginx")
        assert parser.format == "nginx"
        entries = parser.parse_file("samples/nginx_sample.log")
        assert len(entries) == 25

    def test_logparser_invalid_format_raises_error(self) -> None:
        with pytest.raises(ValueError, match="Unsupported format"):
            LogParser(format="unsupported_format")
