#!/usr/bin/env bash
# scripts/register_testnet.sh
#
# One-command registration for a fresh Phylax miner or validator on the
# Bittensor testnet. Reads config from .env in the project root.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
    echo "✗ .env not found. Copy .env.example to .env and fill in your values."
    exit 1
fi
# shellcheck disable=SC1091
source .env

: "${PHYLAX_NETUID:?must be set in .env}"
: "${WALLET_NAME:?must be set in .env}"
: "${WALLET_HOTKEY:?must be set in .env}"
: "${SUBTENSOR_NETWORK:=test}"

ROLE="${1:-miner}"
if [[ "$ROLE" != "miner" && "$ROLE" != "validator" ]]; then
    echo "Usage: $0 [miner|validator]"
    exit 1
fi

echo "→ Role:           $ROLE"
echo "→ Netuid:         $PHYLAX_NETUID"
echo "→ Network:        $SUBTENSOR_NETWORK"
echo "→ Wallet name:    $WALLET_NAME"
echo "→ Wallet hotkey:  $WALLET_HOTKEY"
echo

# Verify wallet exists
if ! btcli wallet list --wallet.name "$WALLET_NAME" >/dev/null 2>&1; then
    echo "✗ Wallet '$WALLET_NAME' not found. Create it first:"
    echo "    btcli wallet create --wallet.name $WALLET_NAME --wallet.hotkey $WALLET_HOTKEY"
    exit 1
fi

echo "→ Registering on subnet $PHYLAX_NETUID …"
btcli subnet register \
    --netuid "$PHYLAX_NETUID" \
    --subtensor.network "$SUBTENSOR_NETWORK" \
    --wallet.name "$WALLET_NAME" \
    --wallet.hotkey "$WALLET_HOTKEY"

if [[ "$ROLE" == "validator" ]]; then
    echo
    echo "→ Validator requires stake. Run:"
    echo "    btcli stake add --wallet.name $WALLET_NAME --wallet.hotkey $WALLET_HOTKEY --amount <TAO>"
fi

echo
echo "✓ Registration complete."
