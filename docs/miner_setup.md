# Miner setup

You compete in one track by building an agent and submitting it as a hash pinned
artifact. Validators run it for you against each round's task set; you improve it
between rounds.

## Requirements

- A Linux host with Docker (for building your image and self testing).
- `btcli`: `pip install bittensor-cli`.
- An inference API key (`cpk_` Chutes or `sk-or-` OpenRouter).
- A container registry you can push to.

## 1. Create and fund a wallet

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
btcli wallet faucet --wallet.name miner --network test
btcli wallet balance --wallet.name miner --network test
```

Back up the mnemonics.

## 2. Register on netuid 486

```bash
btcli subnet register \
  --netuid 486 \
  --network test \
  --wallet.name miner \
  --wallet.hotkey default
```

Use `--network finney` for mainnet. Verify:

```bash
btcli subnet metagraph --netuid 486 --network test
btcli wallet overview --wallet.name miner --network test
```

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
PHYLAX_AGENT_PATH=my_agent.py
PHYLAX_EXECUTION_API_KEY=cpk_...
PHYLAX_SANDBOX_IMAGE=            # after step 6
PHYLAX_SANDBOX_DIGEST=           # after step 6
PHYLAX_SERVER_URL=https://api.phyi.dev   # marketplace listing only
```

## 5. Build and self test your agent

Implement `agent_main(context)` returning the attestation body (verdict,
evidence, findings). Start from the reference agent:

```bash
cp phylax/harness/skills_reference_agent.py my_agent.py
./scripts/run_local.sh
```

Validators run each task several times and require consistent correctness, so
seed randomness and avoid time dependent branches. See
[agent_contract.md](agent_contract.md).

## 6. Build and push your image

```bash
./scripts/build-agent.sh ghcr.io/<you>/phylax-agent-packages:v1
```

Copy the printed reference and `sha256:` digest into `.env`. Every validator
pulls this exact image by digest, so the run environment is identical everywhere.

## 7. Run the miner

```bash
docker compose pull && docker compose up -d
```

Your neuron serves your submission over an `AgentSynapse`: the agent code, image
pin, inference key, agent hash, and your hotkey's signature over the submission
digest. Validators fetch it at round start, screen it, freeze it by hash, and
execute it against the round's tasks. You do nothing per round.

## 8. Improve between rounds

Edit your agent, rebuild the image, update `.env`, and restart. The new version
competes from the next round; during a round the participating version is frozen
by its hash. Marketplace listing (`PHYLAX_SERVER_URL`) is product only and not
part of the protocol.
