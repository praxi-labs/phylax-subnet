# Miner Setup Guide

Run a Phylax miner on testnet (netuid 486) from a clean Ubuntu host. Copy-paste from top to bottom.

## 1. Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose version` must work).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, **80 GB free disk** (image layers + bundle staging + evidence dirs add up fast — 50 GB has bitten operators).
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
# Look for the miner/default row showing a UID on subnet 486.
```

## 3. Install

One command lays down the compose file, a seeded `.env` (with the host UID/GID and docker group GID needed for the sandbox bind mount), and the evidence directory under `~/phylax/miner/`:

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
```

The script is idempotent — re-running upgrades the compose file but never clobbers `.env`.

If your AWS Security Group / firewall is restrictive, open **TCP 8091 inbound** to the public internet now. Without it, validators can't dial your axon.

## 4. Run

```bash
cd ~/phylax/miner
docker compose pull   # pulls phylax-miner + phylax-sandbox
docker compose up -d
docker compose logs -f
```

Within ~30 seconds the log should show:

```text
Axon serving on [::]:8091
```

Within a couple of minutes (once a validator finds your axon on the metagraph):

```text
Received scan request: sha256:...
Running Layer 1: Static analysis…
Running Layer 2: SBOM + supply-chain…
Running Layer 3: Sandbox detonation (seed=...)
Scan complete: sha256:... → Verdict.ALLOW risk=X duration=...ms
```

If you don't see `Layer 3` lines for STANDARD/DEEP-profile requests, the sandbox isn't launching — check the troubleshooting table below.

## 5. Updating

### Automatic (recommended) — opt-in Watchtower

The cleanest way to stay in sync with the network. A small companion container polls GHCR every 6 hours, pulls new miner images, recreates the container, and prunes old layers (which also solves the disk-pressure problem operators kept hitting).

```bash
cd ~/phylax/miner
docker compose --profile auto-update up -d
```

Only containers carrying the `com.centurylinklabs.watchtower.enable=true` label are touched, so nothing else on the host is affected. Tune the cadence:

```bash
echo "WATCHTOWER_POLL_INTERVAL=3600" >> .env   # 1h instead of 6h
docker compose --profile auto-update up -d
```

Disable later:

```bash
docker compose stop watchtower && docker compose rm -f watchtower
```

### Manual

```bash
cd ~/phylax/miner
docker compose pull
docker compose up -d
```

`.env` and your evidence directory persist across updates either way.

## How the miner answers each query

| Step | Description |
|---|---|
| Receive | Synapse carries `skill_bundle`, `nonce`, `round_id`, `canary_id`, `canary_val`, `deadline_unix` |
| Layer 1 | Static pattern scan + prompt-injection rules |
| Layer 2 | SBOM (cyclonedx) + supply-chain checks |
| Layer 3 | Sandbox detonation seeded by `synapse.nonce` (refuses to detonate without a real nonce) |
| Discrepancy | Compares observed sandbox behavior to the bundle's declared SKILL.md manifest (or Implicit Zero-Trust default) |
| Verdict | Combines discrepancy + static findings + SBOM CVEs into the final verdict |
| Sign | ed25519 signature with the miner hotkey |
| Return | Reply within the deadline |

The miner refuses to detonate if no nonce is supplied — running with a hardcoded seed would break the subnet's anti-copy guarantee, and validators will mark such responses invalid.

## What scoring rewards (and what it punishes)

The validator scores you on four axes. The fastest path to high emissions is **honest, deterministic work**:

| Axis | What earns weight | What loses weight |
|---|---|---|
| **Evidence** | Sandbox actually executes and produces real trace files | Skipping the sandbox, returning hand-crafted SSSAs, faking trace hashes — all detectable and zero-scored |
| **Detection** | Your verdict matches the validator's (deterministic given the bundle + manifest) | Wrong verdict, or verdict that disagrees with the validator's independent re-run |
| **Policy** | Your `recommended_policy` precisely covers what the skill actually does | Over-permissive policies (matters more than under-permissive) |
| **Efficiency** | Fast, honest responses | Implausibly fast responses are floored to zero (proves you didn't do the work) |

A few specific things to know:

- The validator does additional intelligence lookups (threat-intel feeds, CVE databases) that the reference miner doesn't ship with. If your verdict differs from the validator's on a skill that touches a known-bad domain or has a vulnerable dependency, you'll take a **false-negative penalty** (λ=1.0 — heavy). Running your own equivalent integrations is the way to stay competitive.
- The subnet has built-in **integrity checks** that detect lying and coordinated cheating. The specifics aren't documented intentionally. The robust strategy is to run the pipeline honestly on every request and let your scores speak for themselves.
- Reference-implementation miners earn baseline weights. Operationally-excellent miners (faster pulls, smarter caching, better infrastructure) earn more. Adding your own intelligence sources on top earns more still.

## Tuning

Edit `~/phylax/miner/.env` and `docker compose up -d` to apply.

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_TIMEOUT` | `60` | Per-detonation timeout (seconds), 5× for `deep` profile |
| `PHYLAX_LOG_LEVEL` | `INFO` | Stdlib logger level |
| `PHYLAX_EVIDENCE_DIR` | `/opt/phylax/evidence` | Where evidence packs are written inside the container (don't change — the compose file bind-mounts the host's `./evidence` here) |
| `PHYLAX_EVIDENCE_HOST_DIR` | _set by install.sh_ | Absolute host-side path of the bind mount. Required for docker-in-docker so the sandbox container sees the same dir the miner does. |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Sandbox image the detonator launches |
| `DOCKER_GID` | _set by install.sh_ | Host's `docker` group GID. The miner container joins this group via `group_add` so it can open `/var/run/docker.sock`. |
| `HOST_UID` / `HOST_GID` | _set by install.sh_ | Your shell user's UID/GID. The container runs as this user so the evidence bind mount stays writable. |
| `AXON_PORT` | `8091` | Host port that maps to the miner's axon |
| `PHYLAX_IMAGE_TAG` | `latest` | Pin to `sha-<short>` for reproducible deploys |
| `WATCHTOWER_POLL_INTERVAL` | `21600` | When auto-update profile is active: GHCR poll interval in seconds (default 6h) |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker compose: command not found` | docker compose plugin missing | `sudo apt install docker-compose-plugin` |
| Container exits immediately | Hotkey not found in `~/.bittensor` | Check `ls ~/.bittensor/wallets/miner/hotkeys/default` |
| `PermissionError: '~/phylax/evidence/...'` (literal tilde) | Old `.env` with `~/...` in `PHYLAX_EVIDENCE_DIR` | Set it to `/opt/phylax/evidence` (the in-container path); see the Tuning table |
| `permission denied while trying to connect to the docker API` | Container UID not in host docker group | Confirm `DOCKER_GID` in `.env` matches `getent group docker`, re-run `up -d` |
| Sandbox produces only `log.txt`, no `network.jsonl` etc. | `PHYLAX_EVIDENCE_HOST_DIR` not set or wrong | Re-run `scripts/install.sh`, or set it to the absolute host path of `~/phylax/miner/evidence` |
| Sandbox crashes with `PermissionError: '/evidence/process.jsonl'` | Docker-in-docker bind mount creating root-owned dir | Same as above — fix `PHYLAX_EVIDENCE_HOST_DIR` |
| `Cannot connect to the Docker daemon` from inside container | docker.sock mount not propagated | Ensure `/var/run/docker.sock` exists on the host |
| `Permission denied: '/opt/phylax/evidence'` | `HOST_UID`/`HOST_GID` in `.env` don't match your shell user | Re-run `scripts/install.sh` or hand-edit `.env` |
| No `Received scan request` lines after 5 min | Inbound 8091 closed, axon not on metagraph yet | Open the port; wait ~12 blocks (~2 min) after `subnet register`; verify `axon.is_serving == True` via `btcli subnet list` |
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` reachability from inside the container |
| Sandbox timeouts | Heavy bundles, `deep` profile | Bump `SANDBOX_TIMEOUT` in `.env`, `docker compose up -d` |
| Disk fills up | Old image layers accumulating | Either enable the auto-update profile (Watchtower prunes automatically) or `docker image prune -af` manually |
| Evidence axis stuck at 0 on the leaderboard | Sandbox produced no trace files | `ls ~/phylax/miner/evidence/$(ls -1t ~/phylax/miner/evidence \| head -1)` — should contain `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`. If only `log.txt`, read that for the harness error |
