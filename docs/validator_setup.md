# Validator setup

A validator evaluates one track. When the server schedules a round it fetches the
participating agents, derives the task set from the round seed, runs every agent's
**code** inside its own hardened sandbox image, scores against ground truth, posts
signed results to the server, and sets graduated weights on chain.

![The validator evaluation pipeline](images/validator-pipeline.webp)

## Requirements

- A Linux host with Docker and `docker compose`. The jail is mandatory: the
  validator refuses to evaluate if `PHYLAX_EXECUTOR` is not `docker`.
- `btcli`: `pip install bittensor-cli`.
- Enough stake to hold a validator permit.
- Capacity for `agents x tasks x repetitions x timeout` per round (divided by
  your parallelism). Each sandbox run is capped at `PHYLAX_SANDBOX_MEMORY` (2 GB)
  and `PHYLAX_SANDBOX_CPUS` (2) by default, so N agents in parallel need roughly
  N × 2 GB RAM. A practical starting point is **8 vCPU / 16 GB RAM / 40 GB disk**.
- Outbound access to `ghcr.io`. The host pulls four public images —
  `phylax-validator`, `phylax-proxy`, `phylax-agent` (the sandbox), and
  `containrrr/watchtower` — so no registry login is needed. If your evaluations
  fail with `image pull failed`, the sandbox image is not reachable: confirm
  `phylax-agent` and `phylax-proxy` are Public on GHCR, or log in with a token.

## 1. Create and fund a wallet

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
btcli wallet balance --wallet.name validator --network finney
```

Mainnet has no faucet — fund the coldkey with real TAO; registering on netuid 76 burns the current recycle cost. (Testnet: `btcli wallet faucet --wallet.name validator --network test`.)

## 2. Register on netuid 76

Phylax is live on Bittensor mainnet — [subnet 76 on taostats](https://taostats.io/subnets/76).

```bash
btcli subnet register \
  --netuid 76 \
  --network finney \
  --wallet.name validator \
  --wallet.hotkey default
```

## 3. Stake for a permit

```bash
btcli stake add --wallet.name validator --wallet.hotkey default --amount <TAO>
btcli wallet overview --wallet.name validator --network finney
```

Eligibility is on chain and permissionless: a permit by stake weight and positive
vtrust once you start setting weights.

## 4. Install and configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
cd ~/phylax/validator
```

```ini
PHYLAX_NETUID=76
SUBTENSOR_NETWORK=finney
WALLET_NAME=validator
WALLET_HOTKEY=default

PHYLAX_TRACK=skills
PHYLAX_EXECUTOR=docker
PHYLAX_SANDBOX_IMAGE=ghcr.io/praxi-labs/phylax-agent:latest
PHYLAX_INFERENCE_PROXY_URL=http://phylax-proxy:8900
PHYLAX_SERVER_URL=https://api.phyi.dev
PHYLAX_SERVER_HOTKEY=
PHYLAX_PROXY_ADMIN_TOKEN=
DOCKER_GID=
```

Most of these are already correct for mainnet, so leave them as they are:

* `PHYLAX_TRACK` is the one track this validator evaluates. Change it only if you want a track other than skills. Valid values are `skills`, `mcp_servers`, `packages`, `repositories`.
* `PHYLAX_SANDBOX_IMAGE` is the hardened runtime that Phylax publishes at `ghcr.io/praxi-labs/phylax-agent`. Every miner's untrusted code runs inside this image, which belongs to you, never inside an image a miner supplies. You do not build it. The deploy pulls it from GHCR, where it is public. Leave the value as it is.
* `PHYLAX_INFERENCE_PROXY_URL` is the address of your inference proxy. The deploy runs it as a container named `phylax-proxy` on port 8900. It is the only outbound path the sandbox has, so every agent's LLM call passes through it and can be metered. Leave it as `http://phylax-proxy:8900`.
* `PHYLAX_SERVER_URL` is the Phylax backend. Leave it as `https://api.phyi.dev`. If you leave it empty, the validator falls back to a block timed loop for local development.

Three values you fill in yourself:

`PHYLAX_SERVER_HOTKEY` pins the backend's on chain identity so your validator refuses an impostor that tries to feed it fake rounds or agents. It is a fixed public value that every validator uses. Fetch it once and copy the `hotkey` field into your `.env`:

```bash
curl -s https://api.phyi.dev/v1/server-identity
```

`PHYLAX_PROXY_ADMIN_TOKEN` is a secret that you choose. Your validator uses it to ask the proxy whether each agent actually made metered inference, which is the liveness check used in scoring. No one issues it to you. Your validator and your proxy just read the same value from this `.env`, so any random string works. Generate one:

```bash
openssl rand -hex 24
```

`DOCKER_GID` is your host's docker group id. The validator launches sandbox containers by talking to the docker socket, so it must belong to that group. Look it up:

```bash
getent group docker | cut -d: -f3
```

Optional tuning: `PHYLAX_TASKS_PER_ROUND`, `PHYLAX_REPETITIONS`,
`PHYLAX_TASK_TIMEOUT`, `PHYLAX_SCORE_THRESHOLD`, `PHYLAX_RELIABILITY_FRACTION`,
`PHYLAX_CORRECTNESS_FLOOR`, `PHYLAX_STATE_DIR`.

## 5. Run

```bash
docker compose pull && docker compose up -d
docker compose logs -f
```

This starts three containers: the validator neuron, the inference proxy, and
Watchtower.

### Confirm it's healthy

The logs should show the validator connect and start polling:

```text
starting Phylax validator on netuid=76 track=skills ...
```

After that, per round phase, you see either a `submission` wait while miners are
still submitting, or task execution once the window closes. Quick checks:

* `docker compose ps` shows the validator, proxy, and watchtower all `Up`.
* `btcli wallet overview --wallet.name validator --network finney` confirms your hotkey is on netuid 76 with a validator permit, and shows your vtrust once you set weights.
* `curl -s https://api.phyi.dev/v1/server-identity` returns the same hotkey you put in `PHYLAX_SERVER_HOTKEY`.

Common failures and their cause: `image pull failed` means the sandbox image is not reachable (see Requirements). `PHYLAX_EXECUTOR must be docker` means the wrong executor is set in `.env`. A docker socket permission error means a wrong `DOCKER_GID`.

## Staying current (auto-updates)

Watchtower is part of the validator deploy and runs automatically — it is not
optional. It watches the containers labelled
`com.centurylinklabs.watchtower.enable=true` (the validator and the proxy) and,
when we publish a new image, pulls it and restarts that container in place, one at
a time. This keeps every validator on the same build without anyone re-running
`docker compose pull`. It polls hourly by default; override with
`WATCHTOWER_POLL_INTERVAL` (seconds) in `.env`.

The **sandbox image** (`phylax-agent`) is handled separately and does not need
Watchtower: the executor runs `docker pull` on `PHYLAX_SANDBOX_IMAGE` before every
agent run, so as long as you leave `PHYLAX_SANDBOX_DIGEST` unset it always resolves
the latest `phylax-agent`. Pin `PHYLAX_SANDBOX_DIGEST` only when you deliberately
want a frozen, reproducible sandbox — that disables the per-run refresh.

## What happens each round

1. **Round trigger.** The validator polls the server (`/v1/rounds/next`). While the
   round's **submission window** is open the server reports a `submission` phase and
   the validator waits — miners are still submitting. When the window closes the
   server returns the round id, the shared seed, and the frozen participant set, and
   evaluation begins. Every validator working the round gets the same seed and set,
   so all evaluate the identical task set. (Without a server, a block-derived
   fallback seeds the round for local dev.)
2. **Fetch and screen.** For each participant in the round's frozen list, pull the
   agent from the backend (`GET /v1/specialization/agent/{hotkey}/runnable`); verify
   the fetched code hash matches the hash the backend froze; screen for size,
   entrypoint, and copied code (token-level similarity across submissions).
3. **Derive tasks.** The round seed deterministically selects tasks from the
   corpus, identically for every validator.
4. **Execute.** Run each agent's code on every task, `r` times, inside the
   validator-owned sandbox image (`cap-drop=ALL`, `no-new-privileges`, non-root,
   `--internal` network), funded by the miner's inference key through the metered
   proxy — the sandbox's only outbound path.
5. **Score.** Correctness against the label dominates (recall for repositories).
   A behavioural run must also pass liveness (the probe was observed, or real
   inference was metered for that task). The reliability rule counts runs the
   agent got *correct*, then averages over the task set.
6. **Publish + weights.** Post signed per-agent results and attestations to the
   server (`/v1/rounds/results`) — the server records them for the leaderboard and
   marketplace but never decides the winner. Apply the quality threshold, set
   graduated weights (0.50/0.30/0.20) on your top eligible agents on chain; Yuma
   consensus reconciles all validators by stake-weighted median with clipping.
   Each round also leaves a local record under `PHYLAX_STATE_DIR`.
