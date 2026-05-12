# Miner Setup Guide

Complete walkthrough for running a Phylax miner on testnet.

## 1. Prerequisites

- Python 3.10+
- Docker 24+ (with rootless support if running unprivileged)
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli))
- 16GB RAM, 4+ CPU cores, 50GB free disk

Optional but recommended:
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
# Edit .env: set PHYLAX_NETUID, WALLET_NAME, WALLET_HOTKEY, SUBTENSOR_NETWORK
```

## 5. Build the sandbox image

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

## Monitoring

The miner emits structured logs to stderr. To follow them:

```bash
tail -f ~/.bittensor/miners/miner/default/netuid$PHYLAX_NETUID/miner.log
```

Useful operational metrics:
- **Scan throughput** — scans per minute
- **Verdict distribution** — drift detector for miner pipeline bugs
- **Sandbox failures** — usually Docker daemon issues
- **Signing failures** — usually wallet path or hotkey permissions

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` reachability |
| `docker: not found` | Docker CLI missing in container | Use the miner Dockerfile, not raw Python |
| Stuck at metagraph sync | Subtensor endpoint dead | Switch with `--subtensor.network finney` |
| Sandbox timeouts | Heavy bundles, deep profile | Bump `SANDBOX_TIMEOUT` env var |
