# Miner setup

You compete in one track by building a security **agent** — a single Python file
— and submitting it as hash-pinned code. Validators run your code for you inside
their own hardened sandbox against each round's task set; you improve it between
rounds.

You do **not** build or ship a container image. The validator owns the runtime.
You submit code; the network runs it in a trusted, network-isolated sandbox.

![The miner submission](images/submission.webp)

## Requirements

- A Linux host (for local self-testing).
- `btcli`: `pip install bittensor-cli`.
- An inference API key (`cpk_` Chutes or `sk-or-` OpenRouter) — it funds your
  agent's own inference, metered through the validator's proxy.

## 1. Create and fund a wallet

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
btcli wallet faucet --wallet.name miner --network test
btcli wallet balance --wallet.name miner --network test
```

Back up the mnemonics.

## 2. Register on netuid 486

```bash
btcli subnet register --netuid 486 --network test \
  --wallet.name miner --wallet.hotkey default
```

Use `--network finney` for mainnet.

## 3. Choose your track

Set `PHYLAX_TRACK` to exactly one of `skills`, `mcp_servers`, `packages`,
`repositories`. The track decides what artifacts your agent is tested on and
which emission pool you compete in (repositories and packages 0.30 each,
mcp_servers 0.22, skills 0.18).

## 4. Configure

```bash
cp .env.example .env
```

```ini
PHYLAX_NETUID=486
SUBTENSOR_NETWORK=test
WALLET_NAME=miner
WALLET_HOTKEY=default

PHYLAX_TRACK=packages
PHYLAX_AGENT_CODE_PATH=my_agent.py       # your agent source
PHYLAX_EXECUTION_API_KEY=cpk_...         # funds your agent's inference
PHYLAX_SERVER_URL=https://api.phyi.dev   # marketplace listing only
```

There is no sandbox image to configure — that is the validator's.

## 5. Build your agent

Implement `agent_main(context)` returning the attestation body (verdict,
evidence, findings). Start from the unified reference agent, which already
handles all four tracks:

```bash
cp phylax/harness/reference_agent.py my_agent.py
```

The detection principle is intent-versus-behaviour: derive what the artifact
declares, observe what it does, flag the deviation. What each track's evidence
must contain, and what your detector is scored on, is in
[agent-spec.md](agent-spec.md) and [agent_contract.md](agent_contract.md).

Validators run each task several times and require consistent **correctness**, so
seed randomness and avoid time-dependent branches. Your primary score comes from
matching curated ground truth — a fabricated or empty report earns nothing.

## 6. Run the miner

```bash
docker compose pull && docker compose up -d
```

Your neuron serves your submission over an `AgentSynapse`: the agent code, the
entrypoint, your inference key, the agent hash, and your hotkey's signature over
the submission. Validators fetch it when a round opens, screen it, freeze it by
hash, and run it inside their own sandbox against the round's tasks. You do
nothing per round.

## 7. Improve between rounds

Edit your agent and restart. The new version competes from the next round;
during a round the participating version is frozen by its hash. Marketplace
listing (`PHYLAX_SERVER_URL`) is product-only and not part of the protocol.
