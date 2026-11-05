#!/usr/bin/env bash
# scripts/nginx_pipeline.sh: Deterministic Nginx log analysis with Unix pipelines.
#
# Usage:
#   ./scripts/nginx_pipeline.sh [path_to_log_file]

set -euo pipefail

LOG_FILE="${1:-samples/nginx_sample.log}"

if [[ ! -f "$LOG_FILE" ]]; then
    echo "Error: Log file not found: $LOG_FILE" >&2
    exit 1
fi

echo "=================================================="
echo " LogLens — Nginx Log Analysis (Unix Pipeline) "
echo " File: $LOG_FILE"
echo "=================================================="
echo ""

# 1. Total Requests (ignoring empty lines)
echo "--- 1. Total Requests ---"
awk 'NF' "$LOG_FILE" | wc -l
echo ""

# 2. HTTP Status Code Summary
# $9 is the status code field in standard Nginx Combined format
echo "--- 2. HTTP Status Code Breakdown ---"
awk 'NF {print $9}' "$LOG_FILE" | sort | uniq -c | sort -rn
echo ""

# 3. 4xx vs 5xx Errors (Field-aware parsing with awk)
# Note: Simple 'grep 500' is dangerous because body bytes (e.g. 512 bytes)
# or port numbers can accidentally match. awk '$9 ~ ...' guarantees we check the status code!
echo "--- 3. Client (4xx) vs Server (5xx) Errors ---"
echo -n "4xx Client Errors: "
awk '$9 ~ /^4[0-9]{2}$/' "$LOG_FILE" | wc -l
echo -n "5xx Server Errors: "
awk '$9 ~ /^5[0-9]{2}$/' "$LOG_FILE" | wc -l
echo ""

# 4. Top 5 Client IPs
# $1 is the client IP address
echo "--- 4. Top 5 Client IPs ---"
awk 'NF {print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -n 5
echo ""

# 5. Requests Per Hour
# Field $4 is formatted as: [05/Nov/2026:08:15:32
# Splitting by ':' gives field 2 as the hour '08'
echo "--- 5. Requests per Hour ---"
awk 'NF {print $4}' "$LOG_FILE" | cut -d: -f2 | sort | uniq -c | awk '{print $2 ":00 -> " $1 " requests"}'
echo ""

# 6. Top 5 Requested Endpoints
# $7 is the URL path (e.g. /api/v1/checkout)
echo "--- 6. Top 5 Requested Paths ---"
awk 'NF {print $7}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -n 5
echo ""
