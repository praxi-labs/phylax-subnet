# Validator Setup Guide

A Phylax validator runs the **same three-layer pipeline that miners run** to produce ground truth (whitepaper §5.2). It therefore needs Docker and the sandbox image on the host — not just a network link to miners.

## 1. Prerequisites

- Python 3.10+
- Docker 24+ with rootless support if running unprivileged
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli))
- 16 GB RAM, 4+ CPU cores, 50 GB free disk
- Stable network connection (low latency to the Bittensor chain)

Optional:
- `syft` for high-fidelity SBOMs
- `bandit` for richer static findings

## 2. Install

```bash
git clone https://github.com/praxi-labs/phylax-subnet.git
cd phylax-subnet
pip install -e .
```

## 3. Pull the sandbox image

The validator's `BaselineRunner` shells out to docker to launch the
sandbox for ground-truth detonation. The image is published by CI to
GHCR, so the normal path is a pull, not a build:

```bash
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
```

Then point the baseline runner at it in your `.env`:

```bash
PHYLAX_SANDBOX_IMAGE=ghcr.io/praxi-labs/phylax-sandbox:latest
```

If you need to build from source (developing the harness, pinning a
commit), the Dockerfile is at `docker/Dockerfile.sandbox`:

```bash
docker build -f docker/Dockerfile.sandbox -t phylax-sandbox:latest .
```

## 4. Wallet + stake

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default

btcli subnet register \
    --netuid $PHYLAX_NETUID \
    --subtensor.network test \
    --wallet.name validator \
    --wallet.hotkey default

btcli stake add \
    --wallet.name validator \
    --wallet.hotkey default \
    --amount 1000
```

## 5. Configure phylax-server access

The validator pulls its task batch from the phylax-server control plane and **cannot push weights on-chain without a fresh server-issued attestation**. The operator running phylax-server must add your hotkey to its allowlist; you then point at the server URL via env vars:

```bash
# In .env (see .env.example)
PHYLAX_SERVER_URL=https://your-phylax-server.example
PHYLAX_SERVER_HOTKEY=<32-byte ed25519 pubkey hex from /v1/server-identity>
PHYLAX_VALIDATOR_LABEL=my-org-validator
PHYLAX_OFFLINE_FALLBACK=false
```

`PHYLAX_SERVER_HOTKEY` pins the server identity. Fetch it once with `curl <server>/v1/server-identity` and bake it into `.env` — the client will then refuse any server that presents a different key, defending against a rogue impersonator.

`PHYLAX_OFFLINE_FALLBACK=true` lets the validator keep scoring against the local corpus when the server is unreachable, but weights stay blocked because no fresh attestation can be issued. Default is `false` (skip the round entirely).

## 6. Run

```bash
python neurons/validator.py \
    --netuid $PHYLAX_NETUID \
    --subtensor.network test \
    --wallet.name validator \
    --wallet.hotkey default \
    --logging.debug
```

Optionally, expose the local REST API in a second process so runtimes can query attestations directly (this is the **subnet-side** API — separate from phylax-server's public registry):

```bash
python -m phylax.api.server
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
| set_weights | On-chain push — only happens if the local attestation verifier passes |

## Tuning

| Variable | Default | Meaning |
|---|---|---|
| `PHYLAX_SERVER_URL` | _empty_ | **Required.** Base URL of the phylax-server control plane. |
| `PHYLAX_SERVER_HOTKEY` | _empty_ | **Recommended.** Pinned server signing key; defends against impersonators. |
| `PHYLAX_VALIDATOR_LABEL` | _empty_ | Friendly label shown in server dashboards. |
| `PHYLAX_OFFLINE_FALLBACK` | `false` | If `true`, score against local corpus when server unreachable (weights still blocked). |
| `TASKS_PER_ROUND` | 8 | Curated tasks requested from phylax-server each round. |
| `SYNTHETIC_TASKS_PER_ROUND` | 2 | Local synthetic challenges injected per round. |
| `QUERY_TIMEOUT` | 180 | Seconds to wait per miner. |
| `WEIGHT_UPDATE_INTERVAL` | 100 | Blocks between set_weights pushes. |
| `EMA_ALPHA` | 0.2 | Per-round smoothing factor. |
| `SANDBOX_TIMEOUT` | 120 | Per-detonation timeout (seconds). |
| `PHYLAX_REGISTRY_PATH` | `./phylax_registry.sqlite3` | Local attestation registry cache. |
| `PHYLAX_SANDBOX_IMAGE` | `phylax-sandbox:latest` | Image tag the baseline runner launches. |
| `PHYLAX_API_ADMIN_TOKEN` | _empty_ | Required for `phylax.api.server`'s local `/v1/attestation/{hash}/invalidate` endpoint. **Not** the same as the phylax-server admin token — that one lives on the control-plane host, not here. |

## Adding canary tasks

Canaries are private — never committed to the public repo (whitepaper §7.3 / §7.4). Drop JSON files into `corpora/canaries/` on each validator host; they are auto-loaded by the `CorpusLoader` if the directory exists.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `validator did not supply a nonce` from a miner | Old miner build | Tell the operator to upgrade — pre-1.1.0 miners are incompatible |
| Empty `ground_truth_evidence` in score logs | Bundle URL unreachable | Inline `bundle_bytes_b64` into the task, or host the URL |
| `set_weights returned False` | Stake too low for permit | Stake more TAO |
| `set_weights: phylax-server client not initialised` | `PHYLAX_SERVER_URL` not set | Add it to `.env` and restart |
| `set_weights: phylax-server refused to issue a weight attestation` | Your hotkey is not on the server's allowlist (or was revoked) | Contact the server operator |
| `phylax-server identity mismatch` | The server's signing key changed, or `PHYLAX_SERVER_HOTKEY` is wrong | Re-fetch `/v1/server-identity` and update `.env` |
| Registry not growing | Consensus aggregator never produces a winner | Inspect miner verdict diversity in logs |
