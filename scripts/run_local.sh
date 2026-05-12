#!/usr/bin/env bash
# scripts/run_local.sh
#
# Bring up a local Phylax dev stack via docker compose.
# Logs are streamed to stdout; CTRL+C stops everything.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
    echo "✗ .env not found. Copy .env.example to .env and fill in your values."
    exit 1
fi

# Build sandbox image first — miner shells out to it
echo "→ Building phylax-sandbox image…"
docker build -f docker/Dockerfile.sandbox -t phylax-sandbox:latest .

echo "→ Starting docker compose stack…"
docker compose -f docker/docker-compose.yml up --build
