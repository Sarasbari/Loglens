"""Tests for the LogLens Aggregator.

These tests verify:
1. Nginx metrics (status counts, 4xx/5xx breakdown, top IPs, top paths, hours)
   accurately match the Phase 1 Unix pipeline ground truth.
2. Syslog metrics (host volume, service frequency, hours)
   accurately match the Phase 1 Unix pipeline ground truth.
3. Empty log collections return an empty AggregationResult without crashing.
4. Custom top_n values limit rankings appropriately.
5. Invalid top_n arguments raise ValueError.
"""

import pytest

from loglens.aggregator import Aggregator
from loglens.models import AggregationResult, NginxAccessEntry, SyslogEntry
from loglens.parser import LogParser


@pytest.fixture
def aggregator() -> Aggregator:
    return Aggregator(top_n=5)


@pytest.fixture
def nginx_entries() -> list[NginxAccessEntry]:
    parser = LogParser(format="nginx")
    return parser.parse_file("samples/nginx_sample.log")  # type: ignore[return-value]


@pytest.fixture
def syslog_entries() -> list[SyslogEntry]:
    parser = LogParser(format="syslog")
    return parser.parse_file("samples/syslog_sample.log")  # type: ignore[return-value]


class TestNginxAggregation:
    """Verifies Aggregator results for Nginx access logs against Phase 1 baseline."""

    def test_aggregate_nginx_sample_matches_ground_truth(
        self, aggregator: Aggregator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = aggregator.aggregate(nginx_entries)

        assert isinstance(result, AggregationResult)
        assert result.total_entries == 25

        # 1. Status Code Breakdown (matches Phase 1: awk '{print $9}' | sort | uniq -c)
        expected_status_counts = {200: 12, 404: 5, 500: 4, 502: 3, 304: 1}
        assert result.status_counts == expected_status_counts

        # 2. 4xx and 5xx Error Totals (matches Phase 1: 4xx=5, 5xx=7)
        assert result.client_error_count == 5
        assert result.server_error_count == 7

        # 3. Top 5 Client IPs (matches Phase 1: 10.0.0.22 (5), 10.0.0.15 (5), etc.)
        assert len(result.top_ips) == 5
        top_ip_map = dict(result.top_ips)
        assert top_ip_map["10.0.0.22"] == 5
        assert top_ip_map["10.0.0.15"] == 5
        assert top_ip_map["93.180.71.3"] == 4
        assert top_ip_map["203.0.113.88"] == 4
        assert top_ip_map["198.51.100.4"] == 4

        # 4. Top Requested Paths (matches Phase 1: /api/v1/checkout (7), /api/v1/users (3))
        assert len(result.top_paths) == 5
        top_path_map = dict(result.top_paths)
        assert top_path_map["/api/v1/checkout"] == 7
        assert top_path_map["/api/v1/users"] == 3

        # 5. Requests Per Hour (matches Phase 1: 08:00->11, 09:00->6, 10:00->8)
        expected_hours = {"08:00": 11, "09:00": 6, "10:00": 8}
        assert result.entries_per_hour == expected_hours

        # 6. Total bytes transferred
        assert result.total_bytes > 0


class TestSyslogAggregation:
    """Verifies Aggregator results for Linux Syslog against Phase 1 baseline."""

    def test_aggregate_syslog_sample_matches_ground_truth(
        self, aggregator: Aggregator, syslog_entries: list[SyslogEntry]
    ) -> None:
        result = aggregator.aggregate(syslog_entries)

        assert isinstance(result, AggregationResult)
        assert result.total_entries == 25

        # 1. Host Distribution (matches Phase 1: 20 webserver01, 4 db-primary, 1 cache01)
        expected_hosts = {"webserver01": 20, "db-primary": 4, "cache01": 1}
        assert result.host_counts == expected_hosts

        # 2. Service Distribution (matches Phase 1 top logging services)
        expected_services = {
            "systemd": 7,
            "sshd": 6,
            "CRON": 4,
            "postgresql": 3,
            "nginx": 2,
            "kernel": 2,
            "redis": 1,
        }
        assert result.service_counts == expected_services

        # 3. Entries per hour
        assert "06:00" in result.entries_per_hour
        assert "07:00" in result.entries_per_hour
        assert "08:00" in result.entries_per_hour
        assert "09:00" in result.entries_per_hour
        assert "10:00" in result.entries_per_hour


class TestAggregatorEdgeCases:
    """Verifies edge and boundary cases for Aggregator."""

    def test_empty_entries_returns_zeroed_result(self, aggregator: Aggregator) -> None:
        result = aggregator.aggregate([])

        assert result.total_entries == 0
        assert result.status_counts == {}
        assert result.client_error_count == 0
        assert result.server_error_count == 0
        assert result.total_bytes == 0
        assert result.top_ips == []
        assert result.top_paths == []
        assert result.host_counts == {}
        assert result.service_counts == {}
        assert result.entries_per_hour == {}

    def test_custom_top_n_limits_rankings(
        self, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        agg = Aggregator(top_n=3)
        result = agg.aggregate(nginx_entries)

        assert len(result.top_ips) == 3
        assert len(result.top_paths) == 3

    def test_invalid_top_n_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="top_n must be a positive integer"):
            Aggregator(top_n=0)

        with pytest.raises(ValueError, match="top_n must be a positive integer"):
            Aggregator(top_n=-5)

