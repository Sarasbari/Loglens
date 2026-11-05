#!/usr/bin/env bash
# scripts/syslog_pipeline.sh: Deterministic Syslog analysis with Unix pipelines.
#
# Usage:
#   ./scripts/syslog_pipeline.sh [path_to_log_file]

set -euo pipefail

LOG_FILE="${1:-samples/syslog_sample.log}"

if [[ ! -f "$LOG_FILE" ]]; then
    echo "Error: Log file not found: $LOG_FILE" >&2
    exit 1
fi

echo "=================================================="
echo " LogLens — Linux Syslog Analysis (Unix Pipeline) "
echo " File: $LOG_FILE"
echo "=================================================="
echo ""

# 1. Total Entries
echo "--- 1. Total Syslog Entries ---"
awk 'NF' "$LOG_FILE" | wc -l
echo ""

# 2. Log Volume by Hostname
# Column 4 is hostname (webserver01, db-primary, cache01)
echo "--- 2. Log Volume by Host ---"
awk 'NF {print $4}' "$LOG_FILE" | sort | uniq -c | sort -rn
echo ""

# 3. Top Logging Services (Stripping [PID] and colons)
echo "--- 3. Top Logging Services ---"
awk 'NF {print $5}' "$LOG_FILE" | sed -E 's/(\[[0-9]+\])?:?$//' | sort | uniq -c | sort -rn
echo ""

# 4. Security: Failed SSH Authentication Attempts by IP
echo "--- 4. SSH Failed Login Attempts by IP ---"
grep 'Failed password' "$LOG_FILE" | grep -oE 'from [0-9.]+ ' | awk '{print $2}' | sort | uniq -c | sort -rn || true
echo ""

# 5. Critical System Errors and Outages
echo "--- 5. Critical Failures, Timeouts & OOM Events ---"
grep -iE '(out of memory|oom-kill|refused|timed out|lock timeout)' "$LOG_FILE" || true
echo ""

