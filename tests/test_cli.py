"""End-to-end and integration tests for the LogLens CLI and Formatter.

These tests verify:
1. 'analyze' command succeeds on Nginx log files with default table output.
2. 'analyze --format json' outputs valid, parsable JSON matching schema.
3. Filtering via CLI flags (--status, --min-status, --ip, --service) accurately reduces metrics.
4. Syslog files can be analyzed via CLI and filtered by service.
5. Missing file paths exit with code 1 and write an error to stderr.
6. Empty log files are handled gracefully without crashing (0 entries analyzed).
7. Binary or unrecognized file formats exit cleanly with an informative error message.
8. The -v / --verbose flag outputs diagnostic information to stderr.
"""

import json
from pathlib import Path
import pytest

from loglens.cli import main


class TestCLIAnalyzeCommand:
    """End-to-end tests for `loglens analyze`."""

    def test_analyze_nginx_table_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "samples/nginx_sample.log"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "LogLens Analysis Report" in captured.out
        assert "Total Entries Analyzed: 25" in captured.out
        assert "200:   12" in captured.out
        assert "5xx Server Errors: 7" in captured.out
        assert "/api/v1/checkout" in captured.out

    def test_analyze_nginx_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "samples/nginx_sample.log", "--format", "json"])
        captured = capsys.readouterr()

        assert exit_code == 0
        data = json.loads(captured.out)
        assert data["total_entries"] == 25
        assert data["status_counts"]["200"] == 12
        assert data["status_counts"]["500"] == 4
        assert data["client_error_count"] == 5
        assert data["server_error_count"] == 7
        assert len(data["top_ips"]) == 5

    def test_analyze_with_exact_status_filter(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "samples/nginx_sample.log", "--status", "500"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Total Entries Analyzed: 4" in captured.out
        assert "500:    4  (100.0%)" in captured.out
        assert "10.0.0.22" in captured.out

    def test_analyze_with_min_status_filter(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "samples/nginx_sample.log", "--min-status", "500", "--format", "json"])
        captured = capsys.readouterr()

        assert exit_code == 0
        data = json.loads(captured.out)
        assert data["total_entries"] == 7
        assert data["server_error_count"] == 7
        assert "200" not in data["status_counts"]

    def test_analyze_syslog_with_service_filter(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "samples/syslog_sample.log", "--service", "sshd"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Total Entries Analyzed: 6" in captured.out
        assert "sshd               :    6" in captured.out

    def test_analyze_file_not_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "non_existent_file.log"])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "Error: Log file not found" in captured.err

    def test_analyze_empty_filter_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["analyze", "samples/nginx_sample.log", "--status", "999"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Total Entries Analyzed: 0" in captured.out
        assert "No entries found matching criteria." in captured.out

    def test_analyze_empty_file_handled_gracefully(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An empty file (0 bytes) should report 0 entries without crashing."""
        empty_file = tmp_path / "empty.log"
        empty_file.write_text("")

        exit_code = main(["analyze", str(empty_file)])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "Total Entries Analyzed: 0" in captured.out
        assert "No entries found matching criteria." in captured.out

    def test_analyze_unsupported_or_binary_file_returns_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A file with non-log binary contents returns a clean error on stderr."""
        binary_file = tmp_path / "corrupted.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfdThis is not a log file")

        exit_code = main(["analyze", str(binary_file)])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert "Error: Unable to detect log format" in captured.err

    def test_analyze_verbose_flag_prints_diagnostics(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        exit_code = main(["analyze", "samples/nginx_sample.log", "--verbose"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert "[VERBOSE] Target file:" in captured.err
        assert "Detected format: nginx" in captured.err
        assert "Successfully parsed 25 valid log entries." in captured.err
