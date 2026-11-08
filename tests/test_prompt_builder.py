"""Tests for the LogLens PromptBuilder.

These tests verify:
1. Deterministic metrics (totals, status codes, top IPs, paths) are accurately injected into prompts.
2. Raw log evidence lines are included verbatim.
3. The max_evidence truncation limit is strictly respected.
4. Syslog metrics (hosts, services) are included when present.
5. Anti-hallucination instructions and the required JSON schema are always present.
6. Invalid max_evidence values raise ValueError.
"""

import pytest

from loglens.aggregator import Aggregator
from loglens.models import NginxAccessEntry, SyslogEntry
from loglens.parser import LogParser
from loglens.prompt_builder import PromptBuilder


@pytest.fixture
def prompt_builder() -> PromptBuilder:
    return PromptBuilder(max_evidence=5)


@pytest.fixture
def nginx_entries() -> list[NginxAccessEntry]:
    parser = LogParser(format="nginx")
    return parser.parse_file("samples/nginx_sample.log")  # type: ignore[return-value]


@pytest.fixture
def syslog_entries() -> list[SyslogEntry]:
    parser = LogParser(format="syslog")
    return parser.parse_file("samples/syslog_sample.log")  # type: ignore[return-value]


class TestPromptBuilder:
    """Unit tests for PromptBuilder."""

    def test_build_prompt_with_nginx_aggregation(
        self, prompt_builder: PromptBuilder, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        aggregator = Aggregator(top_n=5)
        result = aggregator.aggregate(nginx_entries)

        prompt = prompt_builder.build_prompt(result, evidence_entries=nginx_entries)

        # 1. Verified facts are present
        assert "DETERMINISTIC GROUND TRUTH" in prompt
        assert "Total Entries Analyzed: 25" in prompt
        assert "5xx Server Errors: 7" in prompt
        assert "4xx Client Errors: 5" in prompt
        assert "/api/v1/checkout" in prompt
        assert "10.0.0.22" in prompt

        # 2. Strict constraints and schema are present
        assert "INSTRUCTIONS AND CONSTRAINTS" in prompt
        assert "DO NOT hallucinate" in prompt
        assert "DO NOT fabricate log lines" in prompt
        assert '"severity": "<low|medium|high|critical>"' in prompt

    def test_build_prompt_with_syslog_aggregation(
        self, prompt_builder: PromptBuilder, syslog_entries: list[SyslogEntry]
    ) -> None:
        aggregator = Aggregator(top_n=5)
        result = aggregator.aggregate(syslog_entries)

        prompt = prompt_builder.build_prompt(result, evidence_entries=syslog_entries)

        assert "webserver01" in prompt
        assert "sshd" in prompt
        assert "systemd" in prompt

    def test_build_prompt_includes_verbatim_evidence(
        self, prompt_builder: PromptBuilder, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        sample_entries = nginx_entries[:3]
        prompt = prompt_builder.build_prompt(
            result=Aggregator().aggregate(sample_entries),
            evidence_entries=sample_entries,
        )

        assert "RAW LOG EVIDENCE" in prompt
        for entry in sample_entries:
            assert entry.raw_line in prompt

    def test_build_prompt_respects_max_evidence_limit(
        self, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        # Builder limited to 3 evidence lines
        builder = PromptBuilder(max_evidence=3)
        prompt = builder.build_prompt(
            result=Aggregator().aggregate(nginx_entries),
            evidence_entries=nginx_entries,  # 25 entries passed
        )

        # Only [1], [2], [3] should exist; [4] should not
        assert "[1] " in prompt
        assert "[2] " in prompt
        assert "[3] " in prompt
        assert "[4] " not in prompt

    def test_build_prompt_without_evidence_entries(
        self, prompt_builder: PromptBuilder, nginx_entries: list[NginxAccessEntry]
    ) -> None:
        result = Aggregator().aggregate(nginx_entries)
        prompt = prompt_builder.build_prompt(result, evidence_entries=None)

        assert "No specific raw evidence lines provided." in prompt

    def test_invalid_max_evidence_raises_error(self) -> None:
        with pytest.raises(ValueError, match="max_evidence must be a positive integer"):
            PromptBuilder(max_evidence=0)

        with pytest.raises(ValueError, match="max_evidence must be a positive integer"):
            PromptBuilder(max_evidence=-2)

