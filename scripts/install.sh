#!/usr/bin/env bash
#
# Phylax neuron bootstrap. One command to lay down a working miner or validator
# install on a fresh host.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
#   curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
#
# After this finishes, run:
#   cd ~/phylax/<role>
#   docker compose pull
#   docker compose up -d
#
# The script is idempotent — re-running upgrades the compose file in place
# but never overwrites .env (so your edits survive).

set -euo pipefail

ROLE="${1:-}"
case "$ROLE" in
  miner|validator) ;;
  *)
    echo "Usage: install.sh <miner|validator>" >&2
    exit 2
    ;;
esac

REPO_RAW="https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main"
TARGET="${PHYLAX_INSTALL_DIR:-$HOME/phylax/$ROLE}"

# If GITHUB_TOKEN is set, use it. Lets the bootstrap work against a private
# repo (or rate-limited anonymous fetches). Once the repo is public this is
# unnecessary and the operator can ignore it.
CURL_AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  CURL_AUTH=(-H "Authorization: token ${GITHUB_TOKEN}")
fi
fetch() { curl -fsSL "${CURL_AUTH[@]}" "$@"; }

echo "==> Installing phylax-$ROLE into $TARGET"
mkdir -p "$TARGET/evidence"

# ---------------------------------------------------------------------------
# Sanity checks the operator should not have to debug at runtime
# ---------------------------------------------------------------------------
command -v docker >/dev/null || {
  echo "ERROR: docker is not installed. See https://docs.docker.com/engine/install/" >&2
  exit 1
}
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: cannot talk to the docker daemon. Add yourself to the 'docker' group:" >&2
  echo "       sudo usermod -aG docker \$USER  &&  newgrp docker" >&2
  exit 1
fi
docker compose version >/dev/null 2>&1 || {
  echo "ERROR: 'docker compose' plugin is missing. Install docker-compose-plugin." >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Compose file — always overwrite, this is repo-authored config
# ---------------------------------------------------------------------------
echo "==> Fetching deploy/$ROLE/docker-compose.yml"
fetch "$REPO_RAW/deploy/$ROLE/docker-compose.yml" -o "$TARGET/docker-compose.yml"

# Validator needs a persistent SQLite file for the attestation registry; the
# compose mount is a bind, so the host path must exist or docker will create
# a directory instead of mounting our file.
if [ "$ROLE" = "validator" ]; then
  touch "$TARGET/registry.sqlite3"
fi

# ---------------------------------------------------------------------------
# .env — only write if missing; never clobber an existing one
# ---------------------------------------------------------------------------
if [ -f "$TARGET/.env" ]; then
  echo "==> Keeping existing $TARGET/.env (delete it manually if you want to start over)"
else
  echo "==> Seeding $TARGET/.env from .env.example"
  fetch "$REPO_RAW/.env.example" -o "$TARGET/.env"

  # Append host UID/GID so the compose file's user: directive resolves
  # correctly, and so the sandbox bind mount stays writable. Also pin the
  # host's docker group GID so the container (which runs as a non-root UID
  # with no /etc/group entry) can still open /var/run/docker.sock — without
  # this the miner/validator can't launch the sandbox and the evidence axis
  # silently scores 0 on every run.
  DOCKER_GID="$(getent group docker | cut -d: -f3)"
  if [ -z "$DOCKER_GID" ]; then
    echo "==> WARNING: no 'docker' group on this host. Sandbox launches will fail." >&2
    DOCKER_GID=999
  fi
  {
    echo ""
    echo "# --- Host identity (written by install.sh) ---"
    echo "HOST_UID=$(id -u)"
    echo "HOST_GID=$(id -g)"
    echo "DOCKER_GID=$DOCKER_GID"
    echo "BITTENSOR_DIR=$HOME/.bittensor"
  } >> "$TARGET/.env"

  if [ "$ROLE" = "validator" ]; then
    cat >&2 <<EOF

==> Validator extra step required:
    Edit $TARGET/.env and fill in:
      PHYLAX_SERVER_URL=https://<your-phylax-server>
      PHYLAX_SERVER_HOTKEY=<hex from /v1/server-identity, pinned anti-impersonation>
      PHYLAX_VALIDATOR_LABEL=<friendly label for dashboards>

    Get PHYLAX_SERVER_HOTKEY with:
      curl -fsSL https://<your-phylax-server>/v1/server-identity

EOF
  fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
cat <<EOF

==> Installed at: $TARGET

Next:
  cd $TARGET
  docker compose pull
  docker compose up -d
  docker compose logs -f

EOF
