#!/usr/bin/env bash
# register.sh — register this miner into its track and submit its agent
# (code + sandbox image + inference key) to the phylax-server.
#
# Reads config from the miner .env file. Walks up two directories from this
# script's path (src/scripts -> src -> miner install dir) to find the .env.
# Override by passing a path: ./register.sh /path/to/.env
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_ENV="$(cd "$HERE/../.." && pwd)/.env"
ENV_PATH="${1:-$DEFAULT_ENV}"

if [ ! -f "$ENV_PATH" ]; then
  echo "ERROR: .env not found at $ENV_PATH" >&2
  echo "       Pass a path explicitly: $0 /path/to/.env" >&2
  exit 1
fi

exec python3 "$HERE/register_miner.py" "$ENV_PATH"
