# Validator Setup Guide

Walkthrough for running a Phylax validator on testnet.

Validators do **not** need Docker or the sandbox — they only need to query
miners over the dendrite and score responses.

## 1. Prerequisites

- Python 3.10+
- `btcli`
- 4GB RAM, 2 CPU cores
- Stable network connection (low latency to the Bittensor chain)

## 2. Install

```bash
git clone https://github.com/your-org/phylax-subnet.git
cd phylax-subnet
pip install -e .
```

## 3. Wallet + stake

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default

btcli subnet register \
    --netuid $PHYLAX_NETUID \
    --subtensor.network test \
    --wallet.name validator \
    --wallet.hotkey default

# Stake to be eligible for the top-64 validator slots
btcli stake add \
    --wallet.name validator \
    --wallet.hotkey default \
    --amount 1000
```

## 4. Run

```bash
python neurons/validator.py \
    --netuid $PHYLAX_NETUID \
    --subtensor.network test \
    --wallet.name validator \
    --wallet.hotkey default \
    --logging.debug
```

## Tuning

Environment variables read at startup:

| Variable | Default | Meaning |
|---|---|---|
| `TASKS_PER_ROUND` | 10 | Tasks sampled from corpora per scoring round |
| `QUERY_TIMEOUT` | 120 | Seconds to wait for a miner response |
| `PHYLAX_LOG_LEVEL` | INFO | Python logger level |

## Operating the validator

- **Sync metagraph** every ~5 blocks (~60s)
- **Push weights** every `WEIGHT_UPDATE_INTERVAL` (100 blocks ~= 20 min)
- **EMA decay (`alpha=0.1`)** smooths out per-round noise

## Adding canary tasks

Canary tasks are held back from the public repo (see `corpora/README.md`).
Place private canary JSON files in `corpora/canaries/` — they will be
auto-loaded if the directory exists. Do not commit them.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `No active miners found` | All miner axons stale | Wait ~60s, check `metagraph.axons` |
| All-zero scores | Miners returning errors | Inspect miner logs |
| `Failed to set weights` | Stake too low for permit | Stake more TAO |
