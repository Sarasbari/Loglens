"""Unit and integration tests for the Gemini LLM client and CLI summarization.

Per project engineering rules:
- All LLM interactions are strictly mocked using unittest.mock.
- No live external API calls or token consumptions occur during automated tests.
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from loglens.cli import main
from loglens.llm_client import GeminiClient


class TestGeminiClient:
    """Unit tests for GeminiClient."""

    def test_client_raises_error_when_api_key_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When GEMINI_API_KEY is not set in env and not passed explicitly, raise ValueError."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

        with pytest.raises(ValueError, match="GEMINI_API_KEY is not set"):
            GeminiClient()

    def test_client_initializes_with_explicit_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When api_key is provided explicitly, initialization succeeds."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with patch("google.genai.Client") as mock_genai:
            client = GeminiClient(api_key="custom-test-key")
            assert client.api_key == "custom-test-key"
            assert client.model == "gemini-2.0-flash"
            mock_genai.assert_called_once_with(api_key="custom-test-key")

    def test_generate_summary_calls_api_with_json_mime_type(self) -> None:
        """Verify prompt is sent with response_mime_type='application/json'."""
        with patch("google.genai.Client") as mock_genai:
            mock_instance = MagicMock()
            mock_genai.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.text = '{"title": "Test Incident", "severity": "high"}'
            mock_instance.models.generate_content.return_value = mock_response

            client = GeminiClient(api_key="test-api-key")
            result = client.generate_summary("Analyze this error log")

            assert result == '{"title": "Test Incident", "severity": "high"}'

            mock_instance.models.generate_content.assert_called_once()
            call_kwargs = mock_instance.models.generate_content.call_args.kwargs
            assert call_kwargs["model"] == "gemini-2.0-flash"
            assert call_kwargs["contents"] == "Analyze this error log"
            assert call_kwargs["config"].response_mime_type == "application/json"

    def test_generate_summary_raises_runtime_error_on_api_failure(self) -> None:
        """Verify API errors are caught and re-raised cleanly as RuntimeError."""
        with patch("google.genai.Client") as mock_genai:
            mock_instance = MagicMock()
            mock_genai.return_value = mock_instance
            mock_instance.models.generate_content.side_effect = ConnectionError("Network down")

            client = GeminiClient(api_key="test-api-key")
            with pytest.raises(RuntimeError, match="Gemini API request failed"):
                client.generate_summary("test prompt")


class TestCLISummarizeIntegration:
    """Tests for the CLI --summarize flag with mocked LLM responses."""

    # 12 total errors (7 server 5xx + 5 client 4xx), and line 7 verbatim from samples/nginx_sample.log
    MOCK_VALID_INCIDENT_JSON = json.dumps({
        "title": "Checkout Service Outage",
        "severity": "high",
        "affected_service": "/api/v1/checkout",
        "error_count": 12,
        "summary": "Upstream connection failure caused crashes on the checkout endpoint.",
        "evidence_lines": [
            '10.0.0.22 - - [05/Nov/2026:08:42:19 +0000] "GET /api/v1/checkout HTTP/1.1" 500 240 "-" "MobileApp/2.4"'
        ],
    })

    def test_cli_analyze_summarize_table_output_verified(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "dummy-test-key")

        with patch("loglens.cli.GeminiClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.generate_summary.return_value = self.MOCK_VALID_INCIDENT_JSON

            exit_code = main(["analyze", "samples/nginx_sample.log", "--summarize"])
            captured = capsys.readouterr()

            assert exit_code == 0
            assert "Total Entries Analyzed: 25" in captured.out
            assert "Verified LLM Incident Analysis (Gemini)" in captured.out
            assert "Checkout Service Outage" in captured.out
            assert "HIGH" in captured.out
            assert "12 (Verified ✅)" in captured.out
            assert "10.0.0.22" in captured.out

    def test_cli_analyze_summarize_json_output_verified(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "dummy-test-key")

        with patch("loglens.cli.GeminiClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.generate_summary.return_value = self.MOCK_VALID_INCIDENT_JSON

            exit_code = main([
                "analyze", "samples/nginx_sample.log", "--summarize", "--format", "json"
            ])
            captured = capsys.readouterr()

            assert exit_code == 0
            data = json.loads(captured.out)
            assert data["total_entries"] == 25
            assert "incident_report" in data
            assert data["incident_report"]["title"] == "Checkout Service Outage"
            assert data["incident_report"]["error_count"] == 12

    def test_cli_analyze_summarize_validation_failure_fallback(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When LLM hallucinates an invalid count, CLI displays warning and deterministic report."""
        monkeypatch.setenv("GEMINI_API_KEY", "dummy-test-key")

        invalid_json = json.dumps({
            "title": "Fabricated Incident",
            "severity": "high",
            "affected_service": "/api",
            "error_count": 9999,  # Mismatch! Real is 12
            "summary": "Fake summary",
            "evidence_lines": [],
        })

        with patch("loglens.cli.GeminiClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.generate_summary.return_value = invalid_json

            exit_code = main(["analyze", "samples/nginx_sample.log", "--summarize"])
            captured = capsys.readouterr()

            assert exit_code == 0
            # Deterministic report is still presented
            assert "Total Entries Analyzed: 25" in captured.out
            # Warning is clearly announced
            assert "[WARNING] LLM Incident Report Failed Validation" in captured.out
            assert "Mathematical mismatch" in captured.out
