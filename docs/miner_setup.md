# Miner Guide

You compete in **one track** by building an agent that analyses that track's
artifacts. Your miner node serves a Bittensor axon: when a validator dispatches a
task, your agent runs on the artifact and returns a signed SSSA, and the validator
reruns a sample to audit you. You earn by being among the **top three agents in
your track**, plus a share of the contribution pool if you also help build the
codebase.

## What you submit

You register a hotkey on chain, declare it into one track, and submit three things
bound to that track and signed by your hotkey:

- **Agent code** — a program implementing `agent_main(context)` that returns an SSSA.
- **Sandbox image** — the image your agent runs in (reference + digest), so the validator can rerun it.
- **Inference key** — funds inference; the validator also uses it through its metered proxy on reruns.

## Step 0: Choose your track

A hotkey lives in exactly **one** track. The track decides what artifacts you are
sent, what evidence you must produce, and which emission pool you compete in. To
run in a second track you register a second hotkey and a second node.

| `PHYLAX_TRACK` | You analyse | Your agent must | Emission share |
|---|---|---|---|
| `skills` | Agent-skill bundles (`SKILL.md` + code) | Detonate in a sandbox, thread the probe, report dual-plane evidence | 0.18 |
| `mcp_servers` | MCP server packages | Detonate, plus map the tool surface and check declared-vs-observed schema | 0.22 |
| `packages` | pip / npm packages | Detonate across install-time and import-time, plus supply-chain signals | 0.30 |
| `repositories` | Source repositories | Statically audit source and report vulnerabilities (no probe) | 0.30 |

Pick based on where your edge is. `repositories` and `packages` carry the largest
emission share and have the clearest objective ground truth (known vulnerabilities,
known-bad packages), so a strong agent there is rewarded most. `skills` is the most
mature and tooled, so the bar is high for a smaller share. Valid values are exactly
`skills`, `mcp_servers`, `packages`, `repositories`.

## Requirements

- A Linux host with Docker and the `docker compose` plugin.
- `btcli` installed: `pip install bittensor-cli`.
- An inference API key for a supported provider (`cpk_` for Chutes, `sk-or-` for OpenRouter).
- A container registry you can push to (for example `ghcr.io`).

## Step 1: Create your wallet

A wallet is a coldkey (holds funds, kept offline) plus a hotkey (signs on the
network). This creates both:

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
```

Back up the mnemonics it prints. If you already have a coldkey and only need a
hotkey:

```bash
btcli wallet new_hotkey --wallet.name miner --wallet.hotkey default
```

## Step 2: Fund the wallet on testnet

Registration burns a small amount of recycled TAO. On testnet you can pull free
test TAO from the faucet:

```bash
btcli wallet faucet --wallet.name miner --network test
```

The faucet is proof-of-work and can be rate-limited. Confirm your balance:

```bash
btcli wallet balance --wallet.name miner --network test
```

## Step 3: Register your hotkey on netuid 486

This is the on-chain registration that puts your hotkey on the metagraph. Phylax is
**netuid 486** on testnet.

```bash
btcli subnet register \
  --netuid 486 \
  --network test \
  --wallet.name miner \
  --wallet.hotkey default
```

Use `--network finney` for mainnet. btcli shows the current recycle cost and asks
you to confirm before it burns. When it succeeds your hotkey has a UID on the
subnet. Verify you are on the metagraph:

```bash
btcli subnet metagraph --netuid 486 --network test
btcli wallet overview --wallet.name miner --network test
```

`./scripts/register_testnet.sh miner` runs exactly the `btcli subnet register` call
above after reading `PHYLAX_NETUID`, `WALLET_NAME`, and `WALLET_HOTKEY` from your
`.env`. The manual command and the script do the same thing.

## Step 4: Configure your node

Copy the example env and fill it in:

```bash
cp .env.example .env
```

The keys that matter for registration and submission:

```bash
PHYLAX_NETUID=486
SUBTENSOR_NETWORK=test
WALLET_NAME=miner
WALLET_HOTKEY=default

PHYLAX_SERVER_URL=https://api.phyi.dev
PHYLAX_TRACK=packages            # the one track you chose in Step 0

PHYLAX_EXECUTION_API_KEY=cpk_... # your inference key (cpk_ or sk-or-)
PHYLAX_AXON_PORT=8091            # the port your axon serves on
PHYLAX_SANDBOX_IMAGE=            # filled in after Step 7
PHYLAX_SANDBOX_DIGEST=           # filled in after Step 7
```

## Step 5: Build your agent

Implement `agent_main(context) -> SSSA`. The simplest start is to copy the
reference agent and edit it:

```bash
cp phylax/harness/skills_reference_agent.py my_agent.py
# then set PHYLAX_AGENT_PATH=my_agent.py in .env
```

Your agent receives one task at a time and returns one SSSA. See
[agent_contract.md](agent_contract.md) for the full input and output, and
[sssa_schema.md](sssa_schema.md) for the envelope and the probe you must thread.

## Step 6: Self-test against the track corpus

Run your agent against the labelled corpus for your track until your verdicts and
evidence match the labels. The corpus lives under `corpora/<track>/` with
`known-good` and `known-bad` examples:

```bash
./scripts/run_local.sh
```

Tune your agent until it is reliably correct before you spend a registration on a
weak one.

## Step 7: Build and push your agent image

The validator pulls this exact image **by digest** to rerun your agent, so the
digest is what makes reruns reproducible.

```bash
./scripts/build-agent.sh ghcr.io/<you>/phylax-agent-packages:v1
```

It builds from `docker/Dockerfile.agent`, pushes, and prints the image reference and
`sha256:` digest. Copy both into `.env`:

```bash
PHYLAX_SANDBOX_IMAGE=ghcr.io/<you>/phylax-agent-packages:v1
PHYLAX_SANDBOX_DIGEST=sha256:...
```

## Step 8: Register your agent for the marketplace

Mining itself does not require the server. Validators dispatch tasks to your neuron
over Bittensor, and reruns fetch your agent from you directly. Registration is how
your agent becomes discoverable and rentable in the marketplace, and it is the one
and only time the miner talks to the server.

`POST /v1/specialization/agent` stores your agent (code, entrypoint, sandbox image
and digest, inference model) under your hotkey and track. Run:

```bash
./scripts/register.sh
```

It loads your `.env`, signs the request with your hotkey, and posts it. Your track
for the protocol is whatever `PHYLAX_TRACK` you set; your neuron only answers tasks
for that track, so there is no separate on-chain track binding to manage.

## Step 9: Run the miner neuron

```bash
docker compose pull && docker compose up -d
```

Your neuron serves a Bittensor **axon** on `PHYLAX_AXON_PORT` (publish it so
validators can reach it). Validators on your track dispatch tasks to it; for each
one your agent runs on the artifact, threads the probe, signs the SSSA with your
hotkey, and returns it on the synapse. When a validator audits you, your neuron
serves your agent back so it can be rerun. The top three agents in your track earn
that round's emissions; honest, reproducible verdicts keep you there.

## What your agent receives per task

A validator dispatches each task to your neuron as a `TaskSynapse`; your agent sees
it as a context dict:

```json
{
  "artifact_dir": "/task/artifact",
  "track": "packages",
  "nonce": "…",
  "probe": { "file_path": "/skill/.probe_…", "file_content": "…",
             "dns_host": "….probe.phylax.ai", "process_echo": "…", "canary": "…" },
  "inference": { "api": "<proxy url>", "api_key": "<your key>", "provider": "…", "model": "…" },
  "sandbox": { "image": "…", "digest": "sha256:…" }
}
```

The validator generates the nonce and probe. On the detonation tracks (`skills`,
`mcp_servers`, `packages`) your agent must thread the probe (write the file, look up
the DNS host, echo the process token) so the proof-of-execution holds. Missing or
mismatched probe evidence fails the evidence gate and scores 0. The `repositories`
track audits statically and has no probe.

## What you return

One SSSA per task (see [sssa_schema.md](sssa_schema.md)). You fill `verdict`,
`evidence`, and `findings`, and your miner signs the envelope with your hotkey
before returning it to the validator on the synapse.

Report **canonical capability names** (see [scoring.md](scoring.md)). Fabricated or
off-track names do not raise evidence integrity.
