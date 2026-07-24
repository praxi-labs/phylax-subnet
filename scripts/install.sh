#!/usr/bin/env bash
#
# Phylax bootstrap (code-only submission model). One command to lay down a
# working miner or validator install on a fresh host.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
#   curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
#
# After this finishes, cd ~/phylax/<role> and follow the onboarding steps printed
# at the end: miners submit their agent with register.sh (no neuron to run);
# validators run docker compose up.
#
# Idempotent — re-running upgrades the compose file in place but never
# overwrites .env (so your edits survive).

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

CURL_AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  CURL_AUTH=(-H "Authorization: token ${GITHUB_TOKEN}")
fi
fetch() { curl -fsSL "${CURL_AUTH[@]}" "$@"; }

echo "==> Installing phylax-$ROLE into $TARGET"
mkdir -p "$TARGET"

# ---------------------------------------------------------------------------
# Sanity checks
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

# ---------------------------------------------------------------------------
# .env — only write if missing; never clobber an existing one
# ---------------------------------------------------------------------------
if [ -f "$TARGET/.env" ]; then
  echo "==> Keeping existing $TARGET/.env (delete it manually to start over)"
else
  echo "==> Seeding $TARGET/.env from .env.example"
  fetch "$REPO_RAW/.env.example" -o "$TARGET/.env"

  {
    echo ""
    echo "# --- Host identity (written by install.sh) ---"
    echo "HOST_UID=$(id -u)"
    echo "HOST_GID=$(id -g)"
    echo "BITTENSOR_DIR=$HOME/.bittensor"
    echo "PHYLAX_TRACK=skills"
  } >> "$TARGET/.env"

  # Only the validator runs untrusted agent images, so only it needs docker
  # socket access (and therefore the host docker group GID).
  if [ "$ROLE" = "validator" ]; then
    DOCKER_GID="$(getent group docker | cut -d: -f3)"
    if [ -z "$DOCKER_GID" ]; then
      echo "==> WARNING: no 'docker' group on this host. Agent runs will fail." >&2
      DOCKER_GID=999
    fi
    echo "DOCKER_GID=$DOCKER_GID" >> "$TARGET/.env"
    cat >&2 <<EOF

==> Validator extra step required:
    Edit $TARGET/.env and fill in:
      PHYLAX_SERVER_URL=https://<your-phylax-server>
      PHYLAX_SERVER_HOTKEY=<hex from /v1/server-identity, pinned anti-impersonation>
      PHYLAX_VALIDATOR_LABEL=<friendly label for dashboards>
      PHYLAX_TRACK=<skills|mcp_servers|packages|repositories>

    Get PHYLAX_SERVER_HOTKEY with:
      curl -fsSL https://<your-phylax-server>/v1/server-identity

EOF
  fi
fi

# ---------------------------------------------------------------------------
# Miner-only: clone source so the operator can build + submit an agent.
# Validators do not need source on disk.
# ---------------------------------------------------------------------------
if [ "$ROLE" = "miner" ]; then
  SRC_DIR="$TARGET/src"
  REPO_URL_GIT="https://github.com/praxi-labs/phylax-subnet.git"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    REPO_URL_GIT="https://${GITHUB_TOKEN}@github.com/praxi-labs/phylax-subnet.git"
  fi

  if [ -d "$SRC_DIR/.git" ]; then
    echo "==> Updating existing source at $SRC_DIR"
    git -C "$SRC_DIR" pull --ff-only origin main || \
      echo "==> WARNING: git pull failed; leaving existing source as-is"
  else
    echo "==> Cloning phylax-subnet source into $SRC_DIR (for agent submission)"
    if ! git clone --depth 1 "$REPO_URL_GIT" "$SRC_DIR" 2>/dev/null; then
      echo "==> WARNING: git clone failed."
      echo "    If the repo is private, export GITHUB_TOKEN first and re-run."
    fi
  fi

  if [ -d "$SRC_DIR" ]; then
    chmod +x "$SRC_DIR/scripts/"*.sh 2>/dev/null || true
    chmod +x "$SRC_DIR/scripts/"*.py 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
if [ "$ROLE" = "miner" ]; then
  cat <<EOF

==> Installed at: $TARGET

Files:
  $TARGET/.env                 your config (edit before submitting)
  $TARGET/src/                 phylax-subnet source + scripts
  $TARGET/docker-compose.yml   OPTIONAL neuron (AgentSynapse fallback only)

Onboarding (submit-only — there is no neuron to run):
  1. Register your hotkey on the subnet yourself with btcli (netuid 76):
       btcli subnet register --netuid 76 --network finney --wallet.name <name> --wallet.hotkey <hotkey>
  2. Edit $TARGET/.env: PHYLAX_TRACK, PHYLAX_EXECUTION_API_KEY, PHYLAX_AGENT_CODE_PATH
  3. Submit your agent to the backend:
       cd $TARGET && ./src/scripts/register.sh

To ship a new version later, edit your agent and re-run ./src/scripts/register.sh;
validators pull it from the backend at the start of each round. (The compose file
is optional — only for keeping the peer-to-peer AgentSynapse fallback alive.)

EOF
else
  cat <<EOF

==> Installed at: $TARGET

Next:
  cd $TARGET
  # fill in PHYLAX_SERVER_URL / PHYLAX_SERVER_HOTKEY / PHYLAX_TRACK in .env
  ./scripts/register_chain.sh validator   # chain registration + stake
  docker compose pull
  docker compose up -d
  docker compose logs -f

EOF
fi
