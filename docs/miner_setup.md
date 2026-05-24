# Miner Setup Guide

Run a Phylax miner on testnet (netuid 486) from a clean Ubuntu host. Copy-paste from top to bottom.

## 1. Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose version` must work).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, 50 GB free disk.
- Inbound TCP **8091** open to the public internet (validators dial this port).
- Your shell user is in the `docker` group: `sudo usermod -aG docker $USER && newgrp docker`.

## 2. Wallet, register

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
```

Fund the **coldkey** with testnet TAO from the Bittensor Discord `#faucet` channel (~1 TAO is enough).

```bash
btcli subnet register \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name miner \
  --wallet.hotkey default
```

Verify the hotkey is registered:

```bash
btcli wallet overview --wallet.name miner --subtensor.network test
# Look for the validator/default row showing a UID on subnet 486.
```

## 3. Install

One command lays down the compose file, a seeded `.env`, and the evidence directory under `~/phylax/miner/`:

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
```

The script is idempotent — re-running upgrades the compose file but never clobbers `.env`.

## 4. Run

```bash
cd ~/phylax/miner
docker compose pull   # also pulls phylax-sandbox via the image config
docker compose up -d
docker compose logs -f
```

Within ~30 seconds the log should show:

```
Axon serving on [::]:8091
```

Within a couple of minutes (once a validator finds your axon on the metagraph):

```
Received scan request: sha256:...
Running Layer 3: Sandbox detonation (seed=...)
```

You also need the sandbox image present locally:

```bash
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
```

## 5. Updating

```bash
cd ~/phylax/miner
docker compose pull
docker compose up -d
```

`.env` and your evidence directory persist across updates.

## How the miner answers each query

| Step | Whitepaper § | Description |
|---|---|---|
| Receive | §5.1 | Synapse carries `skill_bundle`, `nonce`, `round_id`, `deadline_unix` |
| Layer 1 | §4.1 | Static pattern scan + prompt-injection rules |
| Layer 2 | §4.1 | SBOM + osv.dev CVE lookup + typosquat + install-hook scan |
| Layer 3 | §4.1 | Sandbox detonation seeded by `synapse.nonce` |
| Assemble | §3 | Build SSSA with capabilities, findings, policy, evidence pack |
| Sign | §3 | ED25519 signature with the miner hotkey |
| Return | §5.1 | Reply within the deadline |

The miner refuses to detonate if no nonce is supplied — running with a hardcoded seed would break the subnet's anti-copy guarantee.

## Tuning

Edit `~/phylax/miner/.env` and `docker compose up -d` to apply.

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_TIMEOUT` | `60` | Per-detonation timeout (seconds), 5× for `deep` profile |
| `PHYLAX_LOG_LEVEL` | `INFO` | Stdlib logger level |
| `PHYLAX_EVIDENCE_DIR` | `/opt/phylax/evidence` | Where evidence packs are written (the compose file already bind-mounts the host's `./evidence` here — don't change this) |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Sandbox image the detonator launches |
| `AXON_PORT` | `8091` | Host port that maps to the miner's axon |
| `PHYLAX_IMAGE_TAG` | `latest` | Pin to `sha-<short>` for reproducible deploys |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker compose: command not found` | docker compose plugin missing | `sudo apt install docker-compose-plugin` |
| Container exits immediately | Hotkey not found in `~/.bittensor` | Check `ls ~/.bittensor/wallets/miner/hotkeys/default` |
| `Cannot connect to the Docker daemon` from inside container | docker.sock mount not propagated | Ensure `/var/run/docker.sock` exists on the host |
| `Permission denied: '/opt/phylax/evidence'` | `HOST_UID`/`HOST_GID` in `.env` don't match your shell user | Re-run `scripts/install.sh` or hand-edit `.env` |
| No `Received scan request` lines after 5 min | Inbound 8091 closed or axon not on metagraph yet | Open the port; wait ~12 blocks (~2 min) after `subnet register` |
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` reachability from inside the container |
| Sandbox timeouts | Heavy bundles, `deep` profile | Bump `SANDBOX_TIMEOUT` in `.env`, `docker compose up -d` |
| ε scored 0 on the leaderboard | Sandbox produced no trace files | `ls ~/phylax/miner/evidence/$(ls -1t ~/phylax/miner/evidence \| head -1)` — should contain `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`. If only `log.txt`, read that for the harness error |
