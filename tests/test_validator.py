"""Tests for the LogLens IncidentValidator.

These tests verify the Three-Layer Verification pipeline:
1. Layer 1 (Structural): JSON parsing, required field presence, type checking, severity enum.
2. Layer 2 (Mathematical): Error count cross-checked against deterministic ground truth.
3. Layer 3 (Evidence): Every cited log line checked against actual source lines.
4. Clean failure reporting without crashes.
"""

import json
import pytest

from loglens.aggregator import Aggregator
from loglens.models import NginxAccessEntry
from loglens.parser import LogParser
from loglens.validator import IncidentValidator


@pytest.fixture
def validator() -> IncidentValidator:
    return IncidentValidator()


@pytest.fixture
def nginx_entries() -> list[NginxAccessEntry]:
    parser = LogParser(format="nginx")
    return parser.parse_file("samples/nginx_sample.log")  # type: ignore[return-value]


class TestIncidentValidator:
    """Unit tests for IncidentValidator."""

    def test_validate_valid_report(
        self, validator: IncidentValidator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        # 5xx=7, 4xx=5 -> total errors = 12
        real_line = nginx_entries[6].raw_line  # a 500 error line

        valid_json = json.dumps({
            "title": "Checkout Outage",
            "severity": "high",
            "affected_service": "/api/v1/checkout",
            "error_count": 12,
            "summary": "Service experienced 12 total client and server errors.",
            "evidence_lines": [real_line],
        })

        val_result = validator.validate(valid_json, result, nginx_entries)

        assert val_result.is_valid is True
        assert val_result.report is not None
        assert val_result.report.title == "Checkout Outage"
        assert val_result.report.severity == "high"
        assert val_result.report.error_count == 12
        assert val_result.errors == []

    def test_validate_malformed_json_syntax(
        self, validator: IncidentValidator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        val_result = validator.validate("{ malformed json", result, nginx_entries)

        assert val_result.is_valid is False
        assert val_result.report is None
        assert any("Invalid JSON syntax" in err for err in val_result.errors)

    def test_validate_missing_required_field(
        self, validator: IncidentValidator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        incomplete_json = json.dumps({
            "title": "Incident",
            "severity": "medium",
            # missing affected_service, error_count, summary, evidence_lines
        })

        val_result = validator.validate(incomplete_json, result, nginx_entries)

        assert val_result.is_valid is False
        assert any("Missing required field: 'summary'" in err for err in val_result.errors)
        assert any("Missing required field: 'error_count'" in err for err in val_result.errors)

    def test_validate_invalid_severity_level(
        self, validator: IncidentValidator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        invalid_severity_json = json.dumps({
            "title": "Title",
            "severity": "catastrophic",  # invalid
            "affected_service": "api",
            "error_count": 12,
            "summary": "Summary text",
            "evidence_lines": [],
        })

        val_result = validator.validate(invalid_severity_json, result, nginx_entries)

        assert val_result.is_valid is False
        assert any("Invalid severity 'catastrophic'" in err for err in val_result.errors)

    def test_validate_mathematical_count_mismatch(
        self, validator: IncidentValidator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        # Real error count is 12, but LLM hallucinates 99
        hallucinated_count_json = json.dumps({
            "title": "Title",
            "severity": "critical",
            "affected_service": "api",
            "error_count": 99,
            "summary": "Summary text",
            "evidence_lines": [],
        })

        val_result = validator.validate(hallucinated_count_json, result, nginx_entries)

        assert val_result.is_valid is False
        assert any("Mathematical mismatch" in err for err in val_result.errors)

    def test_validate_fabricated_evidence_line(
        self, validator: IncidentValidator, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        # Real error count, but the LLM made up a fake log line
        fake_log = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /made-up-hack HTTP/1.1" 500 0'
        fabricated_evidence_json = json.dumps({
            "title": "Title",
            "severity": "critical",
            "affected_service": "api",
            "error_count": 12,
            "summary": "Summary text",
            "evidence_lines": [fake_log],
        })

        val_result = validator.validate(fabricated_evidence_json, result, nginx_entries)

        assert val_result.is_valid is False
        assert any("Fabricated evidence detected" in err for err in val_result.errors)

