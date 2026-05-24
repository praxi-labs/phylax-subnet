# Validator Setup Guide

Run a Phylax validator on testnet (netuid 486) from a clean host. Copy-paste from top to bottom.

A Phylax validator runs the **same three-layer pipeline that miners run** to produce ground truth (whitepaper §5.2). It therefore needs Docker on the host AND a path to talk to the phylax-server control plane.

## 1. Prerequisites

- Docker 24+ (`docker` runnable by your user; add yourself to the `docker` group if not).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, 50 GB free disk.
- Outbound HTTPS to `https://<your-phylax-server>` (no inbound ports required unless you also run the optional local attestation API).

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
# Look for the validator/default row with non-zero STAKE on subnet 486.
```

## 3. Pull the images

```bash
docker pull ghcr.io/praxi-labs/phylax-validator:latest
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
```

## 4. Get on the phylax-server allowlist

The validator pulls task batches from phylax-server and **cannot push weights on-chain without a fresh server-issued attestation**. The operator running phylax-server must add your hotkey to its allowlist before any of this works.

Send the phylax-server operator:

- Your validator hotkey ss58 (`btcli wallet overview --wallet.name validator` → the `HOTKEY_SS58` column for `validator/default`).
- The source IP your validator will dial from.

They reply with the phylax-server base URL and the server's signing-key hotkey (which you'll pin in `.env` so a rogue impostor server can't trick you).

## 5. Configuration

```bash
mkdir -p ~/phylax && cd ~/phylax
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/.env.example -o .env
mkdir -p evidence
touch registry.sqlite3

# Edit .env and fill these — the rest of the file already has sensible defaults:
#   PHYLAX_SERVER_URL=https://<your-phylax-server>
#   PHYLAX_SERVER_HOTKEY=<hex from the server operator, or fetch via /v1/server-identity>
#   PHYLAX_VALIDATOR_LABEL=my-org-validator
```

Fetch and pin the server signing key (defends against impersonators):

```bash
curl -fsSL https://<your-phylax-server>/v1/server-identity
# Copy the "hotkey" field into PHYLAX_SERVER_HOTKEY in .env
```

`PHYLAX_OFFLINE_FALLBACK=true` (in `.env`) lets the validator keep scoring against the local corpus when the server is unreachable, but weights stay blocked because no fresh attestation can be issued. Default is `false` (skip the round entirely).

## 6. Run

```bash
docker run -d --name phylax-validator --restart=unless-stopped \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/.bittensor:/root/.bittensor:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/phylax/evidence:/opt/phylax/evidence" \
  -v "$HOME/phylax/registry.sqlite3:/opt/phylax/registry.sqlite3" \
  --env-file "$HOME/phylax/.env" \
  ghcr.io/praxi-labs/phylax-validator:latest \
  python neurons/validator.py \
    --netuid 486 \
    --subtensor.network test \
    --wallet.name validator \
    --wallet.hotkey default \
    --logging.debug
```

What each mount does:

| Mount | Why |
|---|---|
| `~/.bittensor` (read-only) | Hotkey to sign SSSAs and to call `set_weights` |
| `/var/run/docker.sock` | `BaselineRunner` shells out to docker to launch the sandbox for ground-truth detonation |
| `~/phylax/evidence` | Host-side scratch for per-scan trace artefacts (shared with the sandbox by bind mount) |
| `~/phylax/registry.sqlite3` | Persists the attestation registry across restarts |
| `--user $(id -u):$(id -g)` | Required so the sandbox's bind-mounted `/evidence` is writable |

## 7. Verify

```bash
# Container is up
docker ps --filter name=phylax-validator --format 'table {{.Names}}\t{{.Status}}'

# Tail logs — within ~30s look for these signposts:
docker logs -f phylax-validator
#   registered with phylax-server at https://...
#   starting Phylax validator on netuid=486 hotkey=...
#   round <id> | miners=N server_curated=5 local_synth=2 server_owned=True
#   round <id> done | top_score=0.XXX
#   set_weights | non-zero=N
#   set_weights | attestation <id> expires ...
```

If `top_score` stays at `0.000` for several rounds, miners aren't returning valid SSSAs (or there's no miner serving on netuid 486 yet).

## 8. Optional: expose the local attestation API

Runtimes can query the validator's signed attestations directly. This is the **subnet-side** API, separate from phylax-server's public registry.

```bash
docker run -d --name phylax-api --restart=unless-stopped \
  -p 8080:8080 \
  -v "$HOME/phylax/registry.sqlite3:/opt/phylax/registry.sqlite3:ro" \
  -e PHYLAX_REGISTRY_PATH=/opt/phylax/registry.sqlite3 \
  ghcr.io/praxi-labs/phylax-validator:latest \
  python -m phylax.api.server
```

Open inbound TCP 8080 in your firewall if you want this reachable from outside the host.

## 9. Updating

```bash
docker pull ghcr.io/praxi-labs/phylax-validator:latest
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
docker rm -f phylax-validator
# Re-run the docker run command from step 6. registry.sqlite3 persists.
```

## What the validator does each round

| Step | Description |
|---|---|
| Fetch task batch | `POST /v1/tasks/batch` to phylax-server — every validator gets a comparable curated batch |
| Add local synthetic | Validator generates its own private synthetic challenges on top of the curated batch |
| Per-miner nonce | Generate η_i for every miner; broadcast (S, η_i, deadline) over dendrite |
| Run baseline | Validator locally runs the same three-layer pipeline under each η_i to get ground truth |
| Score | Compute α, ε, π, η per miner and the composite Q |
| Consensus | Quality-weighted argmax verdict; countersign the winning SSSA |
| Publish | Write consensus SSSA locally and push to phylax-server's public registry |
| Push results | `POST /v1/rounds/{round_id}/results` so the server can validate the next weight push |
| Request weight attestation | `POST /v1/weights/report` → server signs a short-TTL `WeightAttestation` |
| `set_weights` | On-chain push — only happens if the local attestation verifier passes |

## Tuning

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
| `PHYLAX_REGISTRY_PATH` | `/opt/phylax/registry.sqlite3` | Local attestation registry cache (mount from host to persist). |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Image tag the baseline runner launches. |
| `PHYLAX_API_ADMIN_TOKEN` | _empty_ | Required for `phylax.api.server`'s local `/v1/attestation/{hash}/invalidate` endpoint. **Not** the same as the phylax-server admin token — that one lives on the control-plane host, not here. |

## Adding canary tasks

Canaries are private — never committed to the public repo (whitepaper §7.3 / §7.4). Drop JSON files into `corpora/canaries/` on each validator host (you'd need to use a source install for this, or mount the directory into the container at `/opt/phylax/corpora/canaries/`); they are auto-loaded by the `CorpusLoader` if the directory exists.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Container exits immediately | Wallet not mounted, or hotkey doesn't exist | Confirm `~/.bittensor/wallets/validator/hotkeys/default` exists on the host |
| `Permission denied: '/opt/phylax/evidence'` | You omitted `--user "$(id -u):$(id -g)"` | Add the flag |
| `Cannot connect to the Docker daemon` from inside container | Forgot to mount `/var/run/docker.sock` | Add the `-v /var/run/docker.sock:/var/run/docker.sock` flag |
| `phylax-server registration failed: 403 Forbidden` | Your hotkey/source-IP isn't on the server allowlist | Contact the server operator |
| `phylax-server identity mismatch` | Server's signing key changed, or `PHYLAX_SERVER_HOTKEY` is wrong | Re-fetch `/v1/server-identity` and update `.env` |
| Rounds taking 5+ minutes, `409 Conflict` on results push | Sandbox detonations exceed the server's round deadline | Lower `SANDBOX_TIMEOUT` and/or `QUERY_TIMEOUT` in `.env` |
| `top_score` stuck at `0.000` | No miner returning valid SSSAs | Check there's a miner registered on netuid 486 and its axon is reachable from this host |
| `set_weights returned False` | Stake too low for permit | `btcli stake add` more TAO |
| `set_weights: phylax-server refused to issue a weight attestation` | Your hotkey was de-allowlisted, or you haven't pushed any results yet | Contact server operator / check round-results push log |
| `evidence` axis stuck at `0` on the public leaderboard | Sandbox produces only `log.txt`, no JSONL trace files | Pull the latest `phylax-sandbox:latest`; verify run dirs in `~/phylax/evidence` contain `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl` |
| Registry not growing | Consensus aggregator never produces a winner | Inspect miner verdict diversity in logs |
