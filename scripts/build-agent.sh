#!/usr/bin/env bash
# build-agent.sh — build and push your Phylax agent image, then print the
# image reference + digest you register with the server.
#
# The validator pulls this exact image (by digest) to run your agent jailed,
# so the digest is what makes async reruns reproducible. Build from the
# reference base (docker/Dockerfile.agent) or your own Dockerfile.
#
# Usage:
#   ./scripts/build-agent.sh <registry/image>:<tag> [path/to/Dockerfile]
#
# Example:
#   ./scripts/build-agent.sh ghcr.io/myorg/phylax-agent-skills:v1
#
# After build + push, copy the printed values into .env:
#   PHYLAX_SANDBOX_IMAGE=...
#   PHYLAX_SANDBOX_DIGEST=sha256:...
# then run: ./scripts/register.sh

set -euo pipefail

IMG="${1:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="${2:-$SRC/docker/Dockerfile.agent}"

if [ -z "$IMG" ]; then
  echo "Usage: $0 <registry/image>:<tag> [path/to/Dockerfile]" >&2
  exit 2
fi
if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: Dockerfile not found at $DOCKERFILE" >&2
  exit 1
fi

echo "==> Building $IMG from $DOCKERFILE"
docker build -t "$IMG" -f "$DOCKERFILE" "$SRC"

echo "==> Pushing $IMG"
docker push "$IMG"

DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$IMG" | awk -F'@' '{print $2}')"

cat <<EOM

==> Built and pushed successfully.

   Image:  $IMG
   Digest: $DIGEST

Add to your .env:

   PHYLAX_SANDBOX_IMAGE=$IMG
   PHYLAX_SANDBOX_DIGEST=$DIGEST

Then register + submit your agent:

   ./scripts/register.sh

EOM
