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

## 3. Build the sandbox image

The validator's `BaselineRunner` shells out to docker to launch `phylax-sandbox:latest` for ground-truth detonation:

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

## 5. Run

```bash
python neurons/validator.py \
    --netuid $PHYLAX_NETUID \
    --subtensor.network test \
    --wallet.name validator \
    --wallet.hotkey default \
    --logging.debug
```

Optionally, expose the REST API in a second process so runtimes can query attestations:

```bash
python -m phylax.api.server
```

## What the validator does each round

| Step | Whitepaper § | Description |
|---|---|---|
| Sample tasks | §7 | Stratified pick across the seven corpus families + synthetic |
| Per-miner nonce | §5.1 | Generate η_i for every miner; broadcast (S, η_i, deadline) |
| Run baseline | §5.2 | Validator locally runs the same pipeline under each η_i to get GT(S, η_i) |
| Score | §5.3 | Compute α, ε, π, η per miner and the composite Q |
| Consensus | §6.2 | Quality-weighted argmax verdict; countersign the winning SSSA |
| Publish | §6.3 | Write consensus SSSA to the content-addressed registry |
| Aggregate | §5.4 | Epoch average → EMA → set_weights on chain |

## Tuning

| Variable | Default | Meaning |
|---|---|---|
| `TASKS_PER_ROUND` | 8 | Corpus tasks sampled per round |
| `SYNTHETIC_TASKS_PER_ROUND` | 2 | Synthetic challenges injected per round |
| `QUERY_TIMEOUT` | 180 | Seconds to wait per miner |
| `WEIGHT_UPDATE_INTERVAL` | 100 | Blocks between set_weights pushes |
| `EMA_ALPHA` | 0.2 | Per-round smoothing factor |
| `SANDBOX_TIMEOUT` | 120 | Per-detonation timeout (seconds) |
| `PHYLAX_REGISTRY_PATH` | `./phylax_registry.sqlite3` | Where the attestation registry lives |
| `PHYLAX_SANDBOX_IMAGE` | `phylax-sandbox:latest` | Image tag the baseline runner launches |
| `PHYLAX_API_ADMIN_TOKEN` | _empty_ | Required for the /v1/attestation/{hash}/invalidate endpoint |

## Adding canary tasks

Canaries are private — never committed to the public repo (whitepaper §7.3 / §7.4). Drop JSON files into `corpora/canaries/` on each validator host; they are auto-loaded by the `CorpusLoader` if the directory exists.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `validator did not supply a nonce` from a miner | Old miner build | Tell the operator to upgrade — pre-1.1.0 miners are incompatible |
| Empty `ground_truth_evidence` in score logs | Bundle URL unreachable | Inline `bundle_bytes_b64` into the task, or host the URL |
| `set_weights returned False` | Stake too low for permit | Stake more TAO |
| Registry not growing | Consensus aggregator never produces a winner | Inspect miner verdict diversity in logs |
