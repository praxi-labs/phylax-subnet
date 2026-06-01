#!/bin/sh
set -eu

BUNDLE_PATH="${1:-/skill}"
NONCE="${2:-0}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"

mkdir -p "$EVIDENCE_DIR"

exec python /harness/mcp_client.py "$BUNDLE_PATH" "$NONCE" "$EVIDENCE_DIR"
