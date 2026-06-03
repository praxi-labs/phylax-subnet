#!/usr/bin/env bash
# build-sandbox.sh — build and push a custom sandbox image from this source.
#
# Run from the miner install dir or anywhere; the script locates the source
# relative to its own path.
#
# Usage:
#   ./src/scripts/build-sandbox.sh <skill_type> <registry/image>:<tag>
#
# Example:
#   ./src/scripts/build-sandbox.sh executable_python ghcr.io/myorg/phylax-sandbox-python:v1
#
# After build + push, copy the printed PHYLAX_SANDBOX_DIGEST into your .env
# and run: docker compose up -d --force-recreate

set -euo pipefail

SKILL="${1:-}"
IMG="${2:-}"

case "$SKILL" in
  executable_python|executable_script|mcp_server|agent_composition) ;;
  *)
    echo "Usage: $0 <executable_python|executable_script|mcp_server|agent_composition> <registry/image>:<tag>" >&2
    exit 2
    ;;
esac

if [ -z "$IMG" ]; then
  echo "ERROR: target image tag required, e.g. ghcr.io/<you>/phylax-sandbox-python:v1" >&2
  exit 2
fi

SRC="$(cd "$(dirname "$0")/.." && pwd)"
CONTAINER_DIR="$SRC/phylax/harness/$SKILL/container"
DOCKERFILE="$CONTAINER_DIR/Dockerfile"

if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Dockerfile not found at $DOCKERFILE" >&2
  exit 1
fi

echo "==> Building $IMG from $DOCKERFILE"
docker build -t "$IMG" -f "$DOCKERFILE" "$CONTAINER_DIR"

echo "==> Pushing $IMG"
docker push "$IMG"

DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$IMG" | awk -F'@' '{print $2}')"

cat <<EOM

==> Built and pushed successfully.

   Image:  $IMG
   Digest: $DIGEST

Update your .env with:

   PHYLAX_SANDBOX_IMAGE=$IMG
   PHYLAX_SANDBOX_DIGEST=$DIGEST

Then restart the miner:

   docker compose up -d --force-recreate

EOM
