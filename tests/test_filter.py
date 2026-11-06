"""Tests for the LogLens FilterEngine.

These tests verify:
1. Nginx entries can be filtered by HTTP status code (exact, minimum, range).
2. Nginx entries can be filtered by path regex pattern.
3. Nginx entries can be filtered by IP address.
4. Syslog entries can be filtered by service name.
5. Syslog entries can be filtered by IP address appearing in message.
6. Syslog entries can be filtered by message pattern (e.g. OOM, timeouts).
7. Time window filtering works accurately across timezone-aware and naive datetimes.
8. Multiple criteria combine using Boolean AND logic.
9. Empty criteria returns all entries.
10. Impossible criteria returns an empty list.
11. Format-specific criteria cleanly exclude mismatched entry types without crashing.
12. Filter results match Phase 1 Unix pipeline ground truths.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from loglens.filter import FilterEngine
from loglens.models import FilterCriteria, NginxAccessEntry, SyslogEntry
from loglens.parser import LogParser


@pytest.fixture
def engine() -> FilterEngine:
    return FilterEngine()


@pytest.fixture
def nginx_entries() -> list[NginxAccessEntry]:
    parser = LogParser(format="nginx")
    # Cast is safe because format="nginx" guarantees NginxAccessEntry list
    return parser.parse_file("samples/nginx_sample.log")  # type: ignore[return-value]


@pytest.fixture
def syslog_entries() -> list[SyslogEntry]:
    parser = LogParser(format="syslog")
    return parser.parse_file("samples/syslog_sample.log")  # type: ignore[return-value]


# =====================================================================
# Nginx Filter Tests
# =====================================================================

class TestNginxFiltering:
    """Tests filtering on Nginx access logs."""

    def test_filter_by_min_status_5xx_matches_ground_truth(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        """min_status=500 should yield exactly 7 entries (4 of 500, 3 of 502).

        Verifies exact parity with Phase 1 Unix pipeline:
        awk '$9 ~ /^5[0-9]{2}$/' -> 7 errors.
        """
        criteria = FilterCriteria(min_status=500)
        results = engine.filter(nginx_entries, criteria)

        assert len(results) == 7
        assert all(entry.status_code >= 500 for entry in results)

    def test_filter_by_status_range_4xx_client_errors(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        """400 <= status <= 499 should yield exactly 5 entries (all 404s)."""
        criteria = FilterCriteria(min_status=400, max_status=499)
        results = engine.filter(nginx_entries, criteria)

        assert len(results) == 5
        assert all(400 <= entry.status_code <= 499 for entry in results)

    def test_filter_by_ip(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        """Filtering by IP '10.0.0.15' should yield exactly 5 requests."""
        criteria = FilterCriteria(ip="10.0.0.15")
        results = engine.filter(nginx_entries, criteria)

        assert len(results) == 5
        assert all(entry.ip == "10.0.0.15" for entry in results)

    def test_filter_by_path_pattern(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        """Filtering by path regex '^/api/v1/checkout' should yield exactly 7 requests."""
        criteria = FilterCriteria(path_pattern=r"^/api/v1/checkout")
        results = engine.filter(nginx_entries, criteria)

        assert len(results) == 7
        assert all(entry.path == "/api/v1/checkout" for entry in results)

    def test_filter_combined_criteria_and_logic(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        """min_status=500 AND ip='10.0.0.22' should match only 10.0.0.22's 500 errors."""
        criteria = FilterCriteria(min_status=500, ip="10.0.0.22")
        results = engine.filter(nginx_entries, criteria)

        # 10.0.0.22 had 4 requests that resulted in 500
        assert len(results) == 4
        assert all(entry.ip == "10.0.0.22" and entry.status_code == 500 for entry in results)

    def test_filter_time_window(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        """Filter requests between 09:00:00 and 09:59:59 (Hour 09).

        In Phase 1 Unix pipeline: '09:00 -> 6 requests'.
        """
        criteria = FilterCriteria(
            start_time=datetime(2026, 11, 5, 9, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 11, 5, 9, 59, 59, tzinfo=timezone.utc),
        )
        results = engine.filter(nginx_entries, criteria)
        assert len(results) == 6


# =====================================================================
# Syslog Filter Tests
# =====================================================================

class TestSyslogFiltering:
    """Tests filtering on Linux Syslog entries."""

    def test_filter_by_service(
        self, engine: FilterEngine, syslog_entries: list[SyslogEntry]
    ) -> None:
        """service='sshd' should yield exactly 6 entries, matching Phase 1."""
        criteria = FilterCriteria(service="sshd")
        results = engine.filter(syslog_entries, criteria)

        assert len(results) == 6
        assert all(entry.service == "sshd" for entry in results)

    def test_filter_by_attacker_ip(
        self, engine: FilterEngine, syslog_entries: list[SyslogEntry]
    ) -> None:
        """ip='198.51.100.4' should match the 3 failed password attempts in syslog."""
        criteria = FilterCriteria(ip="198.51.100.4")
        results = engine.filter(syslog_entries, criteria)

        assert len(results) == 3
        assert all("198.51.100.4" in entry.message for entry in results)

    def test_filter_critical_outages_matches_ground_truth(
        self, engine: FilterEngine, syslog_entries: list[SyslogEntry]
    ) -> None:
        """Filtering by critical keywords should yield exactly 5 events.

        Matches Phase 1:
        grep -iE '(out of memory|oom-kill|refused|timed out|lock timeout)'
        """
        criteria = FilterCriteria(
            message_pattern=r"(out of memory|oom-kill|refused|timed out|lock timeout)"
        )
        results = engine.filter(syslog_entries, criteria)

        assert len(results) == 5

    def test_filter_syslog_time_window_naive_datetime(
        self, engine: FilterEngine, syslog_entries: list[SyslogEntry]
    ) -> None:
        """Filter syslog entries between 07:00:00 and 07:59:59 (Hour 07)."""
        criteria = FilterCriteria(
            start_time=datetime(2026, 11, 5, 7, 0, 0),
            end_time=datetime(2026, 11, 5, 7, 59, 59),
        )
        results = engine.filter(syslog_entries, criteria)
        assert len(results) == 8


# =====================================================================
# General & Edge Case Tests
# =====================================================================

class TestFilterEngineEdgeCases:
    """Tests boundary and edge conditions."""

    def test_empty_criteria_returns_all(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        criteria = FilterCriteria()
        results = engine.filter(nginx_entries, criteria)
        assert len(results) == len(nginx_entries)

    def test_impossible_criteria_returns_empty(
        self, engine: FilterEngine, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        criteria = FilterCriteria(min_status=999)
        results = engine.filter(nginx_entries, criteria)
        assert results == []

    def test_cross_format_safety(
        self, engine: FilterEngine, syslog_entries: list[SyslogEntry]
    ) -> None:
        """Filtering syslog with status_code criteria should safely exclude all syslog entries."""
        criteria = FilterCriteria(min_status=500)
        results = engine.filter(syslog_entries, criteria)
        assert results == []

