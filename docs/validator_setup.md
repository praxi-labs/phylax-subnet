# Validator setup

A validator evaluates one track. Each round it fetches the participating agents,
derives the task set from the chain, executes every agent in the docker jail,
scores against ground truth, and sets graduated weights.

## Requirements

- A Linux host with Docker and `docker compose`. The jail is mandatory: the
  validator refuses to evaluate if `PHYLAX_EXECUTOR` is not `docker`.
- `btcli`: `pip install bittensor-cli`.
- Enough stake to hold a validator permit.
- Capacity for `agents x tasks x repetitions x timeout` per round (divided by
  your parallelism).

## 1. Create and fund a wallet

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
btcli wallet faucet --wallet.name validator --network test
```

## 2. Register on netuid 486

```bash
btcli subnet register \
  --netuid 486 \
  --network test \
  --wallet.name validator \
  --wallet.hotkey default
```

## 3. Stake for a permit

```bash
btcli stake add --wallet.name validator --wallet.hotkey default --amount <TAO>
btcli wallet overview --wallet.name validator --network test
```

Eligibility is on chain and permissionless: a permit by stake weight and positive
vtrust once you start setting weights.

## 4. Install and configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
cd ~/phylax/validator
```

```ini
PHYLAX_NETUID=486
SUBTENSOR_NETWORK=test
WALLET_NAME=validator
WALLET_HOTKEY=default

PHYLAX_TRACK=skills
PHYLAX_EXECUTOR=docker
PHYLAX_INFERENCE_PROXY_URL=<metered egress for the jailed sandbox>
DOCKER_GID=<host docker group gid>
```

Optional tuning: `PHYLAX_ROUND_BLOCKS`, `PHYLAX_TASKS_PER_ROUND`,
`PHYLAX_REPETITIONS`, `PHYLAX_TASK_TIMEOUT`, `PHYLAX_SCORE_THRESHOLD`,
`PHYLAX_RELIABILITY_FRACTION`.

## 5. Run

```bash
docker compose pull && docker compose up -d
docker compose logs -f
```

## What happens each round

1. **Round boundary.** The round starts when the chain crosses the track's block
   window; every validator agrees on the boundary from block height alone.
2. **Fetch and screen.** Fetch each serving miner's submission over
   `AgentSynapse`; verify the hotkey signature over the submission digest and the
   agent hash; screen for size, entrypoint, and image pin.
3. **Derive tasks.** `round_seed = sha256(start_block_hash : track)` seeds
   deterministic selection from the bundled corpus, identical for every
   validator.
4. **Execute.** Run each pinned agent on every task, `r` times, in the jail,
   bounded by the per track timeout, funded by the miner's inference key through
   the metered proxy. The executor observes the probe file itself.
5. **Score.** Gate on proof of execution, score risk distance against the label
   (recall for repositories), apply the reliability rule, and average over the
   whole task set.
6. **Weights.** Apply the quality threshold, set graduated weights
   (0.50/0.30/0.20) on your top eligible agents, and submit before the window
   closes. Yuma consensus reconciles all validators by stake weighted median with
   clipping.
