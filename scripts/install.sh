#!/usr/bin/env bash
#
# Phylax bootstrap (code-only submission model). One command to lay down a
# working miner or validator install on a fresh host.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
#   curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
#
# Writes a clean role-specific .env: a validator install contains only validator
# settings, a miner install only miner settings.
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
SERVER_URL="https://api.phyi.dev"
SERVER_HOTKEY="a53f8e390446e31cd077517e44e585c0e0474bbd5b1db5864c52fb07bcbe541c"

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
# .env — role-specific, only written if missing; never clobbers an existing one
# ---------------------------------------------------------------------------
gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    od -vN 24 -An -tx1 /dev/urandom | tr -d ' \n'
  fi
}

if [ -f "$TARGET/.env" ]; then
  echo "==> Keeping existing $TARGET/.env (delete it manually to start over)"
elif [ "$ROLE" = "validator" ]; then
  DOCKER_GID="$(getent group docker | cut -d: -f3)"
  if [ -z "$DOCKER_GID" ]; then
    echo "==> WARNING: no 'docker' group on this host. Agent runs will fail." >&2
    DOCKER_GID=999
  fi
  PROXY_TOKEN="$(gen_token)"
  echo "==> Writing validator .env (server identity pinned, proxy token generated, docker gid detected)"
  cat > "$TARGET/.env" <<EOF
# Phylax validator configuration. Do NOT commit this file.
# A validator evaluates all four tracks every round; there is no track to pick.
# Round length, budgets, and thresholds are pinned by docs/mechanism.md.

PHYLAX_NETUID=76
SUBTENSOR_NETWORK=finney
WALLET_NAME=validator
WALLET_HOTKEY=default
BITTENSOR_DIR=$HOME/.bittensor

# Phylax backend and its pinned ed25519 identity. Verify anytime with:
#   curl -s https://api.phyi.dev/v1/server-identity
PHYLAX_SERVER_URL=$SERVER_URL
PHYLAX_SERVER_HOTKEY=$SERVER_HOTKEY

# Shared secret between your validator and your proxy containers only.
# Generated at install; regenerate anytime with: openssl rand -hex 24
PHYLAX_PROXY_ADMIN_TOKEN=$PROXY_TOKEN

# Host docker group gid, detected at install.
DOCKER_GID=$DOCKER_GID

# Optional friendly label shown in dashboards.
PHYLAX_VALIDATOR_LABEL=

# Host identity, detected at install.
HOST_UID=$(id -u)
HOST_GID=$(id -g)
EOF
else
  echo "==> Writing miner .env"
  cat > "$TARGET/.env" <<EOF
# Phylax miner configuration. Do NOT commit this file.

PHYLAX_NETUID=76
SUBTENSOR_NETWORK=finney
WALLET_NAME=miner
WALLET_HOTKEY=default
BITTENSOR_DIR=$HOME/.bittensor

# Phylax backend and its pinned ed25519 identity. Verify anytime with:
#   curl -s https://api.phyi.dev/v1/server-identity
PHYLAX_SERVER_URL=$SERVER_URL
PHYLAX_SERVER_HOTKEY=$SERVER_HOTKEY

# REQUIRED: the single track your agent competes in.
# One of: skills | mcp_servers | packages | repositories
PHYLAX_TRACK=skills

# REQUIRED: inference key that funds your agent. Must start with 'cpk_'
# (Chutes) or 'sk-or-' (OpenRouter). Validators meter reruns through this key.
PHYLAX_EXECUTION_API_KEY=

# Your agent file and entrypoint. Defaults to the bundled reference agent.
# You submit code only; the validator owns the sandbox image.
PHYLAX_AGENT_CODE_PATH=
PHYLAX_AGENT_ENTRYPOINT=agent_main

# Optional model id passed to your agent.
PHYLAX_INFERENCE_MODEL=
# Optional dependency manifest stored alongside the submission.
PHYLAX_DEPENDENCY_MANIFEST=
# Optional friendly label shown in dashboards.
PHYLAX_MINER_LABEL=

# Only used if you run the OPTIONAL peer-to-peer fallback neuron.
PHYLAX_AXON_PORT=8091
PHYLAX_AXON_EXTERNAL_IP=
PHYLAX_MINER_INTERVAL=20

# Host identity, detected at install.
HOST_UID=$(id -u)
HOST_GID=$(id -g)
EOF
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
validators pull it from the backend at the start of each round.

EOF
else
  cat <<EOF

==> Installed at: $TARGET

Your .env is complete: server identity pinned, proxy token generated, docker
gid detected. Nothing to edit (PHYLAX_VALIDATOR_LABEL is optional).

Next:
  btcli subnet register --netuid 76 --network finney --wallet.name validator --wallet.hotkey default
  btcli stake add --wallet.name validator --wallet.hotkey default --amount <TAO>
  cd $TARGET
  docker compose pull
  docker compose up -d
  docker compose logs -f

EOF
fi
