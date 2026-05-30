# Validator Setup Guide

Run a Phylax validator on testnet (netuid 486) from a clean Ubuntu host. Copy-paste from top to bottom.

A Phylax validator independently re-runs the same three-layer pipeline that miners run (whitepaper §5.2) and consumes additional server-side intelligence (threat-intel feeds, CVE database, miner reputation) that the reference miner doesn't have access to. It therefore needs Docker on the host AND a path to talk to the phylax-server control plane.

## 1. Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose version` must work).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, **80 GB free disk** (image layers + bundle staging + evidence dirs + registry add up — 50 GB has bitten operators).
- Outbound HTTPS to your phylax-server URL (no inbound ports required unless you also expose the optional local attestation API on TCP 8080).
- Your shell user is in the `docker` group: `sudo usermod -aG docker $USER && newgrp docker`.

## 2. Wallet, register, stake

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
```

Fund the **coldkey** with testnet TAO from the Bittensor Discord `#faucet` channel — you need TAO for the registration fee and for stake.

```bash
btcli subnet register \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name validator \
  --wallet.hotkey default

btcli stake add \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name validator \
  --wallet.hotkey default \
  --amount 1
```

Verify:

```bash
btcli wallet overview --wallet.name validator --subtensor.network test
# Look for validator/default with non-zero STAKE on subnet 486.
```

## 3. Get on the phylax-server allowlist

The validator pulls task batches from phylax-server and **cannot push weights on-chain without a fresh server-issued attestation**. The operator running phylax-server must add your hotkey to its allowlist before any of this works.

Send the phylax-server operator:

- Your validator hotkey ss58 (from `btcli wallet overview` above, the `HOTKEY_SS58` for `validator/default`).
- The source IP your validator will dial from.

They reply with the phylax-server base URL and the server's signing-key hotkey (which you'll pin in `.env` so a rogue impostor server can't trick you).

## 4. Install

One command lays down the compose file, a seeded `.env` (with host UID/GID, docker-group GID, and host-side evidence path), an empty `registry.sqlite3`, and the evidence directory under `~/phylax/validator/`:

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
```

The script is idempotent — re-running upgrades the compose file but never clobbers `.env`.

## 5. Configure `.env`

Open `~/phylax/validator/.env` and confirm these values **before** the first `docker compose up`. The template ships with placeholders that will silently leave you on the wrong subnet or pointing at the wrong wallet:

| Variable | What to set | Why it matters |
|---|---|---|
| `PHYLAX_NETUID` | `486` | Template defaults to `1`. Wrong netuid = the validator never sees Phylax miners. |
| `SUBTENSOR_NETWORK` | `test` | `finney` (mainnet) won't see netuid 486. |
| `WALLET_NAME` | `validator` | Must match the **folder name** in `~/.bittensor/wallets/`, not a role. If your folder is called something else (e.g. you transferred a wallet from another host), use that name. Mismatch = container fails to find the hotkey. |
| `WALLET_HOTKEY` | `default` | Whatever hotkey under that wallet you registered with. |
| `PHYLAX_SERVER_URL` | `https://<your-phylax-server>` | Required. Without it the validator can't pull task batches or push weights. |
| `PHYLAX_SERVER_HOTKEY` | `<hex from /v1/server-identity>` | Recommended. Pins the server signing key so a rogue impostor server can't trick you. |
| `PHYLAX_VALIDATOR_LABEL` | `my-org-validator` | Friendly label that shows up in server-side dashboards. |

Fetch and pin the server signing key (defends against impersonators):

```bash
curl -fsSL https://<your-phylax-server>/v1/server-identity
# Copy the "hotkey" field into PHYLAX_SERVER_HOTKEY in .env
```

Quick sanity check after editing:

```bash
grep -E '^(PHYLAX_NETUID|SUBTENSOR_NETWORK|WALLET_NAME|WALLET_HOTKEY|PHYLAX_SERVER_URL|PHYLAX_SERVER_HOTKEY)=' ~/phylax/validator/.env
```

You should see all six lines populated with non-placeholder values.

`PHYLAX_OFFLINE_FALLBACK=true` lets the validator keep scoring against the local corpus when the server is unreachable, but weights stay blocked because no fresh attestation can be issued. Default is `false` (skip the round entirely).

If you started the validator before fixing these, edit `.env` and recreate the container — `docker compose restart` is not enough because env vars are only read at container creation:

```bash
cd ~/phylax/validator
docker compose up -d --force-recreate
```

## 6. Run

```bash
cd ~/phylax/validator
docker compose pull
docker compose up -d
docker compose logs -f
```

Within ~30 seconds the log should show:

```text
registered with phylax-server at https://...
starting Phylax validator on netuid=486 hotkey=...
```

Within a couple of minutes:

```text
round <id> | miners=N server_curated=5 local_synth=2 server_owned=True
round <id> done | top_score=0.XXX
set_weights | attestation <id> expires ...
```

If `top_score` stays at `0.000` for several rounds, there's no miner serving on netuid 486 yet (or all miners are returning invalid SSSAs).

## 7. Optional: expose the local attestation API

Runtimes can query the validator's signed attestations directly. This is the **subnet-side** API, separate from phylax-server's public registry.

```bash
docker run -d --name phylax-api --restart=unless-stopped \
  -p 8080:8080 \
  -v "$HOME/phylax/validator/registry.sqlite3:/opt/phylax/registry.sqlite3:ro" \
  -e PHYLAX_REGISTRY_PATH=/opt/phylax/registry.sqlite3 \
  ghcr.io/praxi-labs/phylax-validator:latest \
  python -m phylax.api.server
```

Open inbound TCP 8080 in your firewall if you want this reachable from outside the host.

## 8. Updating

### Automatic (recommended) — opt-in Watchtower

The cleanest way to stay in sync with the network. A small companion container polls GHCR every 6 hours, pulls new validator images, recreates the container, and prunes old layers (which also solves the disk-pressure problem operators kept hitting).

```bash
cd ~/phylax/validator
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
cd ~/phylax/validator
docker compose pull
docker compose up -d
```

`.env`, your evidence dir, and `registry.sqlite3` persist across updates either way.

## What the validator does each round

| Step | Description |
|---|---|
| Fetch task batch | `POST /v1/tasks/batch` to phylax-server — every validator gets a comparable curated batch (plus its own private canaries) |
| Add local synthetic | Validator generates its own private synthetic challenges on top of the curated batch |
| Per-miner nonce + canary | Unique determinism nonce + proof-of-execution canary token issued per (miner, task) |
| Query miners | Broadcast PhylaxSynapse over dendrite, wait for SSSAs within `QUERY_TIMEOUT` |
| Run baseline | Validator locally runs the same three-layer pipeline under each nonce to get ground truth |
| Threat-intel + CVE | Validator queries the server's intel proxy for every observed domain/IP and SBOM package |
| Discrepancy + verdict | Compare observed sandbox behavior to the bundle's declared SKILL.md manifest (or Implicit Zero-Trust default); combine with static findings + CVE hits |
| Score | Compute α (detection), ε (evidence), π (policy), η (efficiency) per miner and the composite Q |
| Apply reputation | Multiply per-miner weights by their server-tracked reputation (defends against systematic cheating) |
| Consensus | Quality-weighted argmax verdict; countersign the winning SSSA |
| Publish | Write consensus SSSA locally and push to phylax-server's public registry |
| Push results | `POST /v1/rounds/{round_id}/results` so the server can validate the next weight push |
| Request weight attestation | `POST /v1/weights/report` → server signs a short-TTL `WeightAttestation` |
| `set_weights` | On-chain push — only happens if the local attestation verifier passes |

## What makes the validator strictly stronger than the reference miner

The validator consumes server-only signals miners cannot access:

- **Threat-intel** (urlhaus host blacklist, Spamhaus DROP/EDROP for IPs) — known C2 domains and hostile networks become CRITICAL findings regardless of what the skill's manifest declared.
- **CVE database** (osv.dev) — every SBOM package gets a vulnerability lookup; vulnerable deps escalate the verdict.
- **Miner reputation** — derived from each miner's accuracy on validator-pinned canary tasks (private tasks miners can't memorize answers for). Suspected cheaters get their emission weight de-multiplied; coordinated collusion rings get the same treatment.

These run automatically when `PHYLAX_SERVER_URL` is configured. They're not optional — running without them produces a weaker validator and worse weight signals. If the server is briefly unreachable, the validator falls back to a local disk cache of recent responses (`phylax_intel_cache.sqlite3` next to your registry); only sustained outages degrade scoring.

## Tuning

Edit `~/phylax/validator/.env` and `docker compose up -d` to apply.

| Variable | Default | Meaning |
|---|---|---|
| `PHYLAX_SERVER_URL` | _empty_ | **Required.** Base URL of the phylax-server control plane. |
| `PHYLAX_SERVER_HOTKEY` | _empty_ | **Recommended.** Pinned server signing key; defends against impersonators. |
| `PHYLAX_VALIDATOR_LABEL` | _empty_ | Friendly label shown in server dashboards. |
| `PHYLAX_OFFLINE_FALLBACK` | `false` | If `true`, score against local corpus when server unreachable (weights still blocked). |
| `TASKS_PER_ROUND` | `8` | Curated tasks requested from phylax-server each round. |
| `SYNTHETIC_TASKS_PER_ROUND` | `2` | Local synthetic challenges injected per round. |
| `QUERY_TIMEOUT` | `60` | Seconds to wait per miner. |
| `WEIGHT_UPDATE_INTERVAL` | `100` | Blocks between `set_weights` pushes. |
| `EMA_ALPHA` | `0.2` | Per-round smoothing factor. |
| `SANDBOX_TIMEOUT` | `60` | Per-detonation timeout (seconds), 5× for `deep` profile. |
| `PHYLAX_REGISTRY_PATH` | `/opt/phylax/registry.sqlite3` | Local attestation registry cache (compose bind-mounts `./registry.sqlite3` here). |
| `PHYLAX_EVIDENCE_DIR` | `/opt/phylax/evidence` | In-container path the sandbox harness writes to. |
| `PHYLAX_EVIDENCE_HOST_DIR` | _set by install.sh_ | Absolute host-side path of the bind mount. Required for docker-in-docker so the sandbox container sees the same dir the validator does. |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Image tag the baseline runner launches. |
| `DOCKER_GID` | _set by install.sh_ | Host's `docker` group GID; container joins this group via `group_add` to open `/var/run/docker.sock`. |
| `HOST_UID` / `HOST_GID` | _set by install.sh_ | Your shell user's UID/GID; the container runs as this user so bind mounts stay writable. |
| `PHYLAX_API_ADMIN_TOKEN` | _empty_ | Required for `phylax.api.server`'s local `/v1/attestation/{hash}/invalidate` endpoint. **Not** the same as the phylax-server admin token. |
| `PHYLAX_IMAGE_TAG` | `latest` | Pin to `sha-<short>` for reproducible deploys. |
| `WATCHTOWER_POLL_INTERVAL` | `21600` | When auto-update profile is active: GHCR poll interval in seconds (default 6h). |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker compose: command not found` | docker compose plugin missing | `sudo apt install docker-compose-plugin` |
| Container exits immediately | Hotkey not found in `~/.bittensor` | Check `ls ~/.bittensor/wallets/validator/hotkeys/default` |
| Container starts but uses the wrong hotkey | `WALLET_NAME` in `.env` doesn't match your wallet folder | `btcli w list` to see actual folder names; align `WALLET_NAME` with the folder containing the registered validator hotkey, then `docker compose up -d --force-recreate` |
| Validator subscribes to the wrong subnet | `PHYLAX_NETUID` left at template default `1` | Set to `486` in `.env`, then `docker compose up -d --force-recreate` |
| Validator dials `0.0.0.0:<port>` instead of the miner's public IP | Validator and miner on the same host (e.g. same EC2) — bittensor's dendrite anti-loopback rewrites a destination IP that equals the validator's own external IP | Run the miner on a different host. Same-host validator+miner is not a supported topology. |
| `.env` edits not taking effect | `docker compose restart` reuses the existing container's baked-in env | Use `docker compose up -d --force-recreate` instead — env vars are only read at container creation |
| `PermissionError: '~/phylax/evidence/...'` (literal tilde) | Old `.env` with `~/...` in `PHYLAX_EVIDENCE_DIR` | Set it to `/opt/phylax/evidence` (the in-container path) |
| `permission denied while trying to connect to the docker API` | Container UID not in host docker group | Confirm `DOCKER_GID` in `.env` matches `getent group docker`, re-run `up -d` |
| Sandbox produces only `log.txt`, no `network.jsonl` etc. | `PHYLAX_EVIDENCE_HOST_DIR` not set or wrong | Re-run `scripts/install.sh`, or set it to the absolute host path of `~/phylax/validator/evidence` |
| Sandbox crashes with `PermissionError: '/evidence/process.jsonl'` | Docker-in-docker bind mount creating root-owned dir | Same as above — fix `PHYLAX_EVIDENCE_HOST_DIR` |
| `registry write failed: no such table: attestations` | `PHYLAX_REGISTRY_PATH` is empty / points at a non-bind-mounted path | Set it to `/opt/phylax/registry.sqlite3` in `.env`, restart |
| `phylax-server registration failed: 403 Forbidden` | Your hotkey/source-IP isn't on the server allowlist | Contact the server operator |
| `phylax-server identity mismatch` | Server's signing key changed, or `PHYLAX_SERVER_HOTKEY` is wrong | Re-fetch `/v1/server-identity` and update `.env` |
| Rounds taking 5+ minutes, `409 Conflict` on results push | Sandbox detonations exceed the server's round deadline | Lower `SANDBOX_TIMEOUT` and/or `QUERY_TIMEOUT` in `.env` |
| `top_score` stuck at `0.000` | No miner returning valid SSSAs | Check there's a miner registered on netuid 486 and its axon is reachable from this host |
| `set_weights returned False` | Stake too low for permit | `btcli stake add` more TAO |
| `set_weights: phylax-server refused to issue a weight attestation` | Your hotkey was de-allowlisted, or you haven't pushed any results yet | Contact server operator / check round-results push log |
| `intel refresh failed; serving stale cache` warnings | Brief server outage, validator falling back to local intel cache | Non-fatal; no action needed unless it persists more than a few minutes |
| Disk fills up | Old image layers accumulating | Either enable the auto-update profile (Watchtower prunes automatically) or `docker image prune -af` manually |
| `evidence` axis stuck at `0` on the public leaderboard | Sandbox produces only `log.txt`, no JSONL trace files | Pull the latest `phylax-sandbox:latest`; verify run dirs in `~/phylax/validator/evidence` contain `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl` |
| Registry not growing | Consensus aggregator never produces a winner | Inspect miner verdict diversity in logs |
