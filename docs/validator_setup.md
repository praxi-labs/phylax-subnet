# Validator Guide

A validator scores **one track**. Miners run the primary task themselves and return
signed SSSAs over Bittensor; the validator dispatches tasks, verifies the proof,
scores, reruns a sample to keep miners honest, and sets weights on chain. It needs
no server: it scores locally against the bundled benchmark.

## Choose your track

Like miners, a validator commits one hotkey to one track and only audits that
track's miners. Set `PHYLAX_TRACK` to one of `skills`, `mcp_servers`, `packages`,
`repositories`.

## Eligibility

Eligibility is on-chain and permissionless. You need both:

- a validator **permit**, granted by stake weight, and
- positive **vtrust**, which proves you are actively setting weights.

There is no central register and no team approval.

## Requirements

- A Linux host with Docker and `docker compose`. The validator reruns untrusted
  miner agents, so it needs docker socket access (the install script wires the host
  docker group).
- `btcli` installed: `pip install bittensor-cli`.
- A Bittensor wallet with enough stake to hold a permit.
- A metered inference proxy endpoint reachable from the jailed sandbox. No server is
  required; the benchmark ships with the subnet under `corpora/`.

## Step 1: Create your wallet

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
```

Back up the mnemonics. On testnet, fund it from the faucet:

```bash
btcli wallet faucet --wallet.name validator --network test
btcli wallet balance --wallet.name validator --network test
```

## Step 2: Register on netuid 486

Put your hotkey on the metagraph. Phylax is **netuid 486** on testnet.

```bash
btcli subnet register \
  --netuid 486 \
  --network test \
  --wallet.name validator \
  --wallet.hotkey default
```

Use `--network finney` for mainnet. Verify you landed on the metagraph:

```bash
btcli subnet metagraph --netuid 486 --network test
```

## Step 3: Stake for a permit

A validator permit is granted by stake weight. Add stake to your hotkey:

```bash
btcli stake add --wallet.name validator --wallet.hotkey default --amount <TAO>
```

Confirm your stake and watch for the permit and vtrust to appear once you start
setting weights:

```bash
btcli wallet overview --wallet.name validator --network test
```

`./scripts/register_testnet.sh validator` runs the same `btcli subnet register` call
from your `.env` and then reminds you to stake.

## Step 4: Install and configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
cd ~/phylax/validator
```

Fill in `.env`. A validator needs no server: it dispatches to miners, scores locally
against the bundled benchmark, and sets weights on chain.

```ini
PHYLAX_NETUID=486
SUBTENSOR_NETWORK=test
WALLET_NAME=validator
WALLET_HOTKEY=default

PHYLAX_TRACK=skills
PHYLAX_INFERENCE_PROXY_URL=<metered egress for the jailed sandbox>
DOCKER_GID=<host docker group gid>
```

To apply the 5% contribution pool, set `PHYLAX_CONTRIBUTOR_AUTHORITY` to the hotkey
whose on-chain commitment holds the recognized-contributor set (the subnet owner
publishes it with `scripts/publish_contributors.py`). Leave it blank to keep the
pool dormant.

## Step 5: Run

```bash
docker compose pull && docker compose up -d
docker compose logs -f
```

## What the validator does each round

Everything below runs validator to miner over Bittensor, or locally. The server is
not involved.

1. **Dispatch.** Pick an artifact from the bundled benchmark for your track, derive a
   fresh nonce and probe, and send a `TaskSynapse` to your track's miners over the
   dendrite.
2. **Verify.** For each returned SSSA, confirm the probe effects appear in the traces
   (the evidence gate) and verify the miner's signature.
3. **Score.** Score the verdict and evidence on the per-track spine against your local
   labels, and update the miner's running `score` (kept locally). See
   [scoring.md](scoring.md).
4. **Rerun a sample.** Pull a sampled miner's agent over an `AgentSynapse`, pull its
   image by digest, rerun the task network-jailed, and fold whether the verdict
   reproduced into that miner's `rerun_pass_rate`.
5. **Set weights.** Every `WEIGHT_UPDATE_INTERVAL` blocks, rank miners by
   `score x rerun_pass_rate`, apply the per-track shares and the 5% contribution pool,
   map hotkeys to UIDs, and call `set_weights`.

A verdict that does not reproduce drives the miner's `rerun_pass_rate` down, which
pushes it out of the top-3 emission slots. Every validator does this independently,
and Yuma consensus aggregates the weights by stake.
