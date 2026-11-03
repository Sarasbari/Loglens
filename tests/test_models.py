"""Tests for LogLens data models.

These tests verify that:
1. NginxAccessEntry can be created with valid data.
2. SyslogEntry can be created with valid data.
3. SyslogEntry works with pid=None (optional PID).
4. Two entries with the same data are equal (dataclass __eq__).
5. Two entries with different data are not equal.
6. The raw_line field preserves the original log line exactly.
"""

from datetime import datetime

from loglens.models import NginxAccessEntry, SyslogEntry


class TestNginxAccessEntry:
    """Tests for the NginxAccessEntry dataclass."""

    def test_create_with_valid_data(self) -> None:
        """An NginxAccessEntry can be created when all fields are provided."""
        entry = NginxAccessEntry(
            ip="93.180.71.3",
            timestamp=datetime(2015, 5, 17, 8, 5, 32),
            method="GET",
            path="/downloads/product_1",
            protocol="HTTP/1.1",
            status_code=304,
            body_bytes=0,
            raw_line='93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0',
        )

        assert entry.ip == "93.180.71.3"
        assert entry.timestamp == datetime(2015, 5, 17, 8, 5, 32)
        assert entry.method == "GET"
        assert entry.path == "/downloads/product_1"
        assert entry.protocol == "HTTP/1.1"
        assert entry.status_code == 304
        assert entry.body_bytes == 0

    def test_raw_line_preserved(self) -> None:
        """The raw_line field stores the exact original log line."""
        original = '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "POST /api/login HTTP/1.1" 200 1234'
        entry = NginxAccessEntry(
            ip="10.0.0.1",
            timestamp=datetime(2026, 1, 1, 0, 0, 0),
            method="POST",
            path="/api/login",
            protocol="HTTP/1.1",
            status_code=200,
            body_bytes=1234,
            raw_line=original,
        )

        assert entry.raw_line == original

    def test_equality_same_data(self) -> None:
        """Two NginxAccessEntry objects with identical data are equal.

        This works because @dataclass auto-generates __eq__ that
        compares all fields.
        """
        kwargs = dict(
            ip="10.0.0.1",
            timestamp=datetime(2026, 1, 1, 0, 0, 0),
            method="GET",
            path="/",
            protocol="HTTP/1.1",
            status_code=200,
            body_bytes=0,
            raw_line="test line",
        )
        entry_a = NginxAccessEntry(**kwargs)
        entry_b = NginxAccessEntry(**kwargs)

        assert entry_a == entry_b

    def test_inequality_different_data(self) -> None:
        """Two NginxAccessEntry objects with different data are not equal."""
        shared = dict(
            timestamp=datetime(2026, 1, 1, 0, 0, 0),
            method="GET",
            path="/",
            protocol="HTTP/1.1",
            status_code=200,
            body_bytes=0,
            raw_line="test line",
        )
        entry_a = NginxAccessEntry(ip="10.0.0.1", **shared)
        entry_b = NginxAccessEntry(ip="10.0.0.2", **shared)

        assert entry_a != entry_b


class TestSyslogEntry:
    """Tests for the SyslogEntry dataclass."""

    def test_create_with_pid(self) -> None:
        """A SyslogEntry can be created with a PID present."""
        entry = SyslogEntry(
            timestamp=datetime(2026, 11, 3, 10, 15, 42),
            hostname="webserver01",
            service="sshd",
            pid=12345,
            message="Failed password for root from 192.168.1.100 port 22",
            raw_line="Nov  3 10:15:42 webserver01 sshd[12345]: Failed password for root from 192.168.1.100 port 22",
        )

        assert entry.hostname == "webserver01"
        assert entry.service == "sshd"
        assert entry.pid == 12345
        assert "Failed password" in entry.message

    def test_create_without_pid(self) -> None:
        """A SyslogEntry can be created with pid=None.

        Some syslog entries don't include a PID. For example,
        kernel messages: "kernel: Out of memory" (no [PID]).
        """
        entry = SyslogEntry(
            timestamp=datetime(2026, 11, 3, 10, 15, 42),
            hostname="webserver01",
            service="kernel",
            pid=None,
            message="Out of memory: Killed process 5678",
            raw_line="Nov  3 10:15:42 webserver01 kernel: Out of memory: Killed process 5678",
        )

        assert entry.service == "kernel"
        assert entry.pid is None
        assert "Out of memory" in entry.message

    def test_raw_line_preserved(self) -> None:
        """The raw_line field stores the exact original log line."""
        original = "Nov  3 10:15:42 webserver01 cron[999]: job started"
        entry = SyslogEntry(
            timestamp=datetime(2026, 11, 3, 10, 15, 42),
            hostname="webserver01",
            service="cron",
            pid=999,
            message="job started",
            raw_line=original,
        )

        assert entry.raw_line == original

    def test_equality_same_data(self) -> None:
        """Two SyslogEntry objects with identical data are equal."""
        kwargs = dict(
            timestamp=datetime(2026, 11, 3, 10, 15, 42),
            hostname="webserver01",
            service="sshd",
            pid=12345,
            message="test message",
            raw_line="test line",
        )
        entry_a = SyslogEntry(**kwargs)
        entry_b = SyslogEntry(**kwargs)

        assert entry_a == entry_b

    def test_inequality_different_data(self) -> None:
        """Two SyslogEntry objects with different data are not equal."""
        shared = dict(
            timestamp=datetime(2026, 11, 3, 10, 15, 42),
            hostname="webserver01",
            pid=None,
            message="test",
            raw_line="test line",
        )
        entry_a = SyslogEntry(service="sshd", **shared)
        entry_b = SyslogEntry(service="cron", **shared)

        assert entry_a != entry_b

