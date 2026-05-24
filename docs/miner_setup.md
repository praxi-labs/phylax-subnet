# Miner Setup Guide

Complete walkthrough for running a Phylax miner on testnet.

## 1. Prerequisites

- Python 3.10+
- Docker 24+ with rootless support if running unprivileged
- `btcli`
- 16 GB RAM, 4+ CPU cores, 50 GB free disk

Optional:
- `syft` for high-quality SBOMs
- `bandit` for static analysis (`pip install bandit`)
- `semgrep` for additional rules (`pip install semgrep`)

## 2. Clone + install

```bash
git clone https://github.com/praxi-labs/phylax-subnet.git
cd phylax-subnet
pip install -e .
```

## 3. Wallet

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
```

Fund the coldkey with testnet TAO from the Bittensor Discord `#faucet` channel.

## 4. Configure

```bash
cp .env.example .env
# Edit .env: PHYLAX_NETUID, WALLET_NAME, WALLET_HOTKEY, SUBTENSOR_NETWORK
```

## 5. Pull the sandbox image

The sandbox is published by CI to GHCR. You should not need to build it
locally — just pull the latest tag:

```bash
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
```

Then set the image tag in your `.env` so the miner's detonator finds it:

```bash
PHYLAX_SANDBOX_IMAGE=ghcr.io/praxi-labs/phylax-sandbox:latest
```

If you need to build from source (developing the harness, debugging a
pinned commit), the Dockerfile is at `docker/Dockerfile.sandbox`:

```bash
docker build -f docker/Dockerfile.sandbox -t phylax-sandbox:latest .
```

## 6. Register

```bash
bash scripts/register_testnet.sh miner
```

## 7. Run

```bash
python neurons/miner.py \
    --netuid $PHYLAX_NETUID \
    --subtensor.network test \
    --wallet.name miner \
    --wallet.hotkey default \
    --axon.port 8091 \
    --logging.debug
```

## How the miner answers each query

| Step | Whitepaper § | Description |
|---|---|---|
| Receive | §5.1 | Synapse carries skill_bundle, `nonce`, round_id, deadline_unix |
| Layer 1 | §4.1 | Static pattern scan + prompt-injection rules |
| Layer 2 | §4.1 | SBOM + osv.dev CVE lookup + typosquat + install-hook scan |
| Layer 3 | §4.1 | Sandbox detonation seeded by `synapse.nonce` |
| Assemble | §3 | Build SSSA with capabilities, findings, policy, evidence pack |
| Sign | §3 | ED25519 signature with the miner hotkey |
| Return | §5.1 | Reply within the deadline |

The miner refuses to detonate if no nonce is supplied — running with the old hardcoded seed would break the subnet's anti-copy guarantee.

## Tuning

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_TIMEOUT` | 120 | Per-detonation timeout (seconds) |
| `PHYLAX_LOG_LEVEL` | INFO | Stdlib logger level |
| `PHYLAX_EVIDENCE_DIR` | /tmp/... | Where evidence packs are written before hashing |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` reachability |
| `validator did not supply a nonce` | Talking to a pre-1.1.0 validator | Upgrade the validator |
| `docker: not found` | Docker CLI missing in container | Use `Dockerfile.miner`, not raw Python |
| Sandbox timeouts | Heavy bundles, deep profile | Bump `SANDBOX_TIMEOUT` |
| ε scored 0 | Evidence hashes don't match validator replay | Confirm `PHYLAX_SEED` is wired through to the harness inside the sandbox |
