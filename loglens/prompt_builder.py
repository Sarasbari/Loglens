"""Prompt builder engine for LogLens.

This module constructs structured, anti-hallucination prompts for LLM
analysis. It injects deterministic metrics as verified facts and appends
a curated sample of raw evidence lines, directing the LLM to return
a structured JSON incident report.
"""

from collections.abc import Sequence

from loglens.models import AggregationResult, LogEntry


class PromptBuilder:
    """Builds structured prompts for LLM-assisted incident analysis."""

    def __init__(self, max_evidence: int = 10) -> None:
        """Initialize the PromptBuilder.

        Args:
            max_evidence: Maximum number of raw log evidence lines to include
                in the prompt to prevent context bloat. Defaults to 10.

        Raises:
            ValueError: If max_evidence is not a positive integer.
        """
        if max_evidence <= 0:
            raise ValueError(f"max_evidence must be a positive integer, got {max_evidence}")
        self.max_evidence = max_evidence

    def build_prompt(
        self,
        result: AggregationResult,
        evidence_entries: Sequence[LogEntry] | None = None,
    ) -> str:
        """Construct a structured prompt containing verified facts and raw evidence.

        Args:
            result: The deterministic AggregationResult containing calculated numbers.
            evidence_entries: An optional sequence of LogEntry objects (e.g. filtered
                error lines) to provide as cited evidence.

        Returns:
            A string prompt ready to send to the LLM API.
        """
        sections: list[str] = []

        # -------------------------------------------------------------
        # 1. System Role & Mission
        # -------------------------------------------------------------
        sections.append(
            "You are a Senior Site Reliability Engineer (SRE) and Security Analyst.\n"
            "Your task is to analyze server log evidence and produce a structured\n"
            "incident summary in JSON format."
        )

        # -------------------------------------------------------------
        # 2. Deterministic Ground Truth (Verified Facts)
        # -------------------------------------------------------------
        facts: list[str] = [
            "### DETERMINISTIC GROUND TRUTH (VERIFIED FACTS — DO NOT CONTRADICT)",
            f"- Total Entries Analyzed: {result.total_entries}",
        ]

        if result.status_counts:
            status_str = ", ".join(f"{k}: {v}" for k, v in result.status_counts.items())
            facts.append(f"- HTTP Status Distribution: {status_str}")
            facts.append(f"- 4xx Client Errors: {result.client_error_count}")
            facts.append(f"- 5xx Server Errors: {result.server_error_count}")

        if result.top_ips:
            top_ips_str = ", ".join(f"{ip} ({cnt})" for ip, cnt in result.top_ips)
            facts.append(f"- Top Client IPs: {top_ips_str}")

        if result.top_paths:
            top_paths_str = ", ".join(f"{path} ({cnt})" for path, cnt in result.top_paths)
            facts.append(f"- Top Requested Paths: {top_paths_str}")

        if result.host_counts:
            hosts_str = ", ".join(f"{h}: {c}" for h, c in result.host_counts.items())
            facts.append(f"- Hosts: {hosts_str}")

        if result.service_counts:
            services_str = ", ".join(f"{s}: {c}" for s, c in result.service_counts.items())
            facts.append(f"- Services: {services_str}")

        if result.entries_per_hour:
            hours_str = ", ".join(f"{hr}: {c}" for hr, c in result.entries_per_hour.items())
            facts.append(f"- Activity by Hour: {hours_str}")

        sections.append("\n".join(facts))

        # -------------------------------------------------------------
        # 3. Raw Log Evidence
        # -------------------------------------------------------------
        evidence_lines: list[str] = [
            "### RAW LOG EVIDENCE (VERBATIM SAMPLE FROM LOG FILE)"
        ]

        if evidence_entries:
            selected_entries = evidence_entries[: self.max_evidence]
            for i, entry in enumerate(selected_entries, 1):
                evidence_lines.append(f"[{i}] {entry.raw_line}")
        else:
            evidence_lines.append("No specific raw evidence lines provided.")

        sections.append("\n".join(evidence_lines))

        # -------------------------------------------------------------
        # 4. Strict Instructions and Target JSON Schema
        # -------------------------------------------------------------
        total_errors = (
            result.server_error_count + result.client_error_count
            if (result.server_error_count or result.client_error_count)
            else result.total_entries
        )

        instructions = (
            "### INSTRUCTIONS AND CONSTRAINTS\n"
            "1. Output ONLY a valid JSON object matching the schema below. No markdown backticks, no prose outside JSON.\n"
            "2. DO NOT hallucinate or change numbers: use the verified error count provided above.\n"
            "3. DO NOT fabricate log lines: every string in `evidence_lines` MUST be copied verbatim from the RAW LOG EVIDENCE.\n"
            "4. Choose severity from: 'low', 'medium', 'high', 'critical'.\n\n"
            "### REQUIRED JSON SCHEMA\n"
            "{\n"
            '  "title": "<short descriptive incident title>",\n'
            '  "severity": "<low|medium|high|critical>",\n'
            '  "affected_service": "<name of service or primary endpoint affected>",\n'
            f'  "error_count": {total_errors},\n'
            '  "summary": "<2-3 sentence narrative explaining root cause, pattern, and operational impact>",\n'
            '  "evidence_lines": [\n'
            '    "<exact raw log line copied verbatim from evidence above>"\n'
            "  ]\n"
            "}"
        )
        sections.append(instructions)

        return "\n\n".join(sections)

