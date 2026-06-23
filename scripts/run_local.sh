#!/usr/bin/env bash
# scripts/run_local.sh
#
# Bring up a local Phylax subnet dev stack (miner + validator) via docker
# compose. Builds the reference agent base image first so a submitted agent
# has something to run inside. Requires a reachable phylax-server set via
# PHYLAX_SERVER_URL in .env. Logs stream to stdout; CTRL+C stops everything.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
    echo "✗ .env not found. Copy .env.example to .env and fill in your values."
    exit 1
fi

echo "→ Building phylax-agent:reference base image…"
docker build -f docker/Dockerfile.agent -t phylax-agent:reference .

echo "→ Starting docker compose stack (miner + validator)…"
docker compose -f docker/docker-compose.yml up --build
