#!/usr/bin/env bash
# scripts/register_testnet.sh
#
# Step 1 of onboarding: register a fresh Phylax miner or validator hotkey on
# the Bittensor testnet (chain identity only). Reads config from .env.
#
# Miners then run ./scripts/register.sh to declare their track and submit their
# agent. Validators establish eligibility on-chain via permit + vtrust (stake +
# active weight-setting); there is no manual approval step.

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
echo "→ Track:          ${PHYLAX_TRACK:-skills}"
echo

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
    echo "→ Validator eligibility needs stake (permit) and active weight-setting (vtrust):"
    echo "    btcli stake add --wallet.name $WALLET_NAME --wallet.hotkey $WALLET_HOTKEY --amount <TAO>"
else
    echo
    echo "→ Next: declare your track and submit your agent:"
    echo "    ./scripts/build-agent.sh <registry/image>:<tag>   # build + push, copy digest to .env"
    echo "    ./scripts/register.sh"
fi

echo
echo "✓ Chain registration complete."
