#!/bin/bash
# autorun — entry point from USB
# Detects Python, falls back to bash_collector.sh if absent
# All output goes to USB/evidence/ only

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE_DIR="${SCRIPT_DIR}/forensic_suite"
OUTPUT_DIR="${SCRIPT_DIR}/evidence"
EMBEDDED_PYTHON="${SCRIPT_DIR}/python_runtime/bin/python3"

if [ "$(id -u)" -ne 0 ]; then
    printf 'error: must run as root\n' >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# Locate Python — embedded first, then system
PYTHON_BIN=""
if [ -x "${EMBEDDED_PYTHON}" ]; then
    PYTHON_BIN="${EMBEDDED_PYTHON}"
elif command -v python3 > /dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python > /dev/null 2>&1; then
    PYTHON_BIN="python"
else
    for p in /usr/bin/python3 /usr/local/bin/python3 /opt/python3/bin/python3; do
        if [ -x "${p}" ]; then
            PYTHON_BIN="${p}"
            break
        fi
    done
fi

# Add static binaries from USB to PATH if present
if [ -d "${SCRIPT_DIR}/bin_static" ]; then
    export PATH="${SCRIPT_DIR}/bin_static:${PATH}"
fi

if [ -n "${PYTHON_BIN}" ]; then
    cd "${SUITE_DIR}"
    "${PYTHON_BIN}" main.py \
        --output "${OUTPUT_DIR}" \
        --investigator "${INVESTIGATOR:-unknown}" \
        --case "${CASE_ID:-}" \
        --pcap-duration "${PCAP_DURATION:-60}" \
        "$@"
else
    bash "${SUITE_DIR}/bash_collector.sh" \
        "${OUTPUT_DIR}" \
        "${INVESTIGATOR:-unknown}"
fi
