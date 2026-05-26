# Miner Setup Guide

Run a Phylax miner on testnet (netuid 486) from a clean Ubuntu host. Copy-paste from top to bottom.

## 1. Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose version` must work).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, **80 GB free disk** (image layers + bundle staging + evidence dirs add up).
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

One command lays down the compose file, a seeded `.env` (with the host UID/GID and docker-group GID needed for the sandbox bind mount), and the evidence directory under `~/phylax/miner/`:

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

A small companion container polls GHCR every 6 hours, pulls new miner images, recreates the container, and prunes old layers (which also solves the disk-pressure problem operators kept hitting).

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

## What the miner pipeline does

For every scan request, the miner runs three layers in order and returns a signed Signed Skill Safety Attestation (SSSA):

| Layer | Module | What it does |
|---|---|---|
| 1 — Static | `phylax/pipeline/static.py` | AST + regex scan: dangerous API patterns, prompt-injection signatures, permission discrepancies |
| 2 — SBOM | `phylax/pipeline/sbom.py` | Dependency graph (cyclonedx + syft), typosquat detection, install-hook scan |
| 3 — Sandbox | `phylax/pipeline/sandbox.py` | Behavioural detonation inside a locked container; harness records every observable behavior to JSONL traces |
| Assemble | `neurons/miner.py` | Combines observed behaviour with the skill's declared `SKILL.md` manifest, produces verdict + recommended policy |
| Sign | `phylax/attestation/signer.py` | ed25519 signature with the miner hotkey |

The miner refuses to detonate if no nonce is supplied — running with a hardcoded seed would invalidate your response.

## Where you can customize

The reference miner runs out of the box and earns baseline weights. If you want to differentiate yourself, the cleanest places to extend are:

| Module | What's there |
|---|---|
| `phylax/pipeline/static.py` | The bandit + custom-rule scanner. Add your own AST checks or regex signatures here. |
| `phylax/pipeline/sbom.py` | SBOM generation and the typosquat / install-hook heuristics. Plug in additional dependency-graph analysis. |
| `phylax/pipeline/sandbox.py` | The detonator wrapper around the harness container. Extend if you want richer trace parsing or additional observation hooks. |
| `phylax/scoring/discrepancy.py` | The manifest-vs-observed comparison that drives the verdict. Add your own discrepancy rules here. |
| `phylax/policy/generator.py` | Turns observations into a recommended `RecommendedPolicy`. Tighten the constraint logic. |
| `neurons/miner.py` | The top-level pipeline orchestration. Most customizations don't need to touch this directly. |

You can also integrate external data sources of your own choosing (threat-intel feeds, vulnerability databases, etc.) anywhere in the pipeline — the contract you owe the validator is a well-formed signed SSSA returned within the deadline. How you arrive at the verdict is up to you.

Fork the repo, make your changes, build your own image, and point the compose file at it:

```bash
# Build your custom image
docker build -t my-miner:custom -f docker/Dockerfile.miner .

# Edit ~/phylax/miner/docker-compose.yml to use your image:
#   image: my-miner:custom
# (or push to your own registry and pull from there)

docker compose up -d --force-recreate
```

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
| Sandbox runs but produces no JSONL trace files | Run dir contains only `log.txt`; read it for the harness error | `ls ~/phylax/miner/evidence/$(ls -1t ~/phylax/miner/evidence \| head -1)` |
