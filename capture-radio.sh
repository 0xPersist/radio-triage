#!/usr/bin/env bash
# capture-radio.sh — capture the Android radio logcat buffer for radio-triage.
#
# Usage: ./capture-radio.sh <label>
# Output: <label>-radio.txt (owner-only permissions)
set -euo pipefail

LABEL="${1:?usage: ./capture-radio.sh <label>}"
if ! [[ "$LABEL" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; then
    echo "error: label must be 1-32 chars of [A-Za-z0-9_-] (path traversal guard)" >&2
    exit 1
fi
OUT="${LABEL}-radio.txt"

if ! command -v adb >/dev/null 2>&1; then
    echo "error: adb not found in PATH" >&2; exit 1
fi
if ! adb get-state >/dev/null 2>&1; then
    echo "error: no authorized device" >&2; exit 1
fi

umask 077
rm -f -- "$OUT"
adb logcat -b radio -v threadtime -d > "$OUT"
echo "done: $OUT ($(wc -l < "$OUT") lines)"
