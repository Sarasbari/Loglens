"""Structured output validation engine for LogLens.

This module acts as the uncompromising trust boundary between external LLM
generations and the user. It enforces a Three-Layer Verification pipeline:
1. Structural schema validation (valid JSON, correct types, allowed enums).
2. Mathematical cross-checking (LLM error count matches deterministic metrics).
3. Evidence verification (every cited log line must exist in source logs).
"""

from collections.abc import Sequence
import json

from loglens.models import AggregationResult, IncidentReport, LogEntry, ValidationResult

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


class IncidentValidator:
    """Validates and cross-checks LLM-generated incident reports."""

    def validate(
        self,
        raw_llm_json: str,
        result: AggregationResult,
        source_entries: Sequence[LogEntry],
    ) -> ValidationResult:
        """Execute three-layer verification on raw LLM output.

        Args:
            raw_llm_json: The raw JSON string returned by Gemini.
            result: The deterministic AggregationResult (mathematical ground truth).
            source_entries: The parsed LogEntry objects from the original file
                (used to verify evidence authenticity).

        Returns:
            A ValidationResult indicating success or containing specific failure reasons.
        """
        errors: list[str] = []

        # -------------------------------------------------------------
        # Layer 1: Syntactic & Structural Schema Validation
        # -------------------------------------------------------------
        try:
            data = json.loads(raw_llm_json)
        except (json.JSONDecodeError, TypeError) as err:
            return ValidationResult(
                is_valid=False,
                errors=[f"Invalid JSON syntax from LLM: {err}"],
            )

        if not isinstance(data, dict):
            return ValidationResult(
                is_valid=False,
                errors=["Expected top-level JSON object (dictionary), got list or primitive."],
            )

        # Check required fields
        required_fields = (
            "title",
            "severity",
            "affected_service",
            "error_count",
            "summary",
            "evidence_lines",
        )
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: '{field}'")

        if errors:
            return ValidationResult(is_valid=False, errors=errors)

        # Validate types and values
        title = data.get("title")
        if not isinstance(title, str) or not title.strip():
            errors.append("Field 'title' must be a non-empty string.")

        severity_raw = str(data.get("severity", "")).strip().lower()
        if severity_raw not in ALLOWED_SEVERITIES:
            errors.append(
                f"Invalid severity '{severity_raw}'. Must be one of: {sorted(ALLOWED_SEVERITIES)}"
            )

        affected_service = data.get("affected_service")
        if not isinstance(affected_service, str) or not affected_service.strip():
            errors.append("Field 'affected_service' must be a non-empty string.")

        error_count = data.get("error_count")
        if not isinstance(error_count, int) or isinstance(error_count, bool):
            errors.append("Field 'error_count' must be an integer.")

        summary = data.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            errors.append("Field 'summary' must be a non-empty string.")

        evidence_lines = data.get("evidence_lines")
        if not isinstance(evidence_lines, list) or not all(isinstance(x, str) for x in evidence_lines):
            errors.append("Field 'evidence_lines' must be a list of strings.")

        # If structural validation failed, return immediately before cross-checking
        if errors:
            return ValidationResult(is_valid=False, errors=errors)

        # -------------------------------------------------------------
        # Layer 2: Mathematical Cross-Checking
        # -------------------------------------------------------------
        expected_errors = (
            result.server_error_count + result.client_error_count
            if (result.server_error_count or result.client_error_count)
            else result.total_entries
        )

        if error_count != expected_errors:
            errors.append(
                f"Mathematical mismatch: LLM claimed error_count={error_count}, "
                f"but verified ground truth is {expected_errors}."
            )

        # -------------------------------------------------------------
        # Layer 3: Verbatim Evidence Verification (Anti-Fabrication)
        # -------------------------------------------------------------
        valid_raw_lines = {entry.raw_line.strip() for entry in source_entries}

        for cited_line in evidence_lines:
            cleaned_line = cited_line.strip()
            if cleaned_line not in valid_raw_lines:
                errors.append(
                    f"Fabricated evidence detected: Cited line does not exist in source log: '{cleaned_line}'"
                )

        if errors:
            return ValidationResult(is_valid=False, errors=errors)

        # All 3 layers passed!
        report = IncidentReport(
            title=title,
            severity=severity_raw,
            affected_service=affected_service,
            error_count=error_count,
            summary=summary,
            evidence_lines=evidence_lines,
        )

        return ValidationResult(is_valid=True, report=report, errors=[])

