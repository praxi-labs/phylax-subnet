# Phylax Miner Guide
## netuid 486 (testnet)

You compete in **one track** by building an **agent** that analyses that track's
artifacts. Your miner node runs the agent live on each task and submits a signed
SSSA; the validator reruns a sample to audit you. Earn by being among the **top
three agents in your track**.

## The submission, in one sentence

You register a hotkey on chain, register it into one track, and submit three
things bound to that track and signed by your hotkey: your **agent code**, the
**sandbox image** it runs in (reference + digest), and an **inference key** that
funds inference. You run the agent yourself; the registered image and key let the
validator rerun a sample of your tasks to confirm your verdicts hold up.

## Requirements

- A Linux host with Docker + the `docker compose` plugin.
- A Bittensor wallet (coldkey + hotkey).
- An inference API key for a supported provider (key prefix selects the provider:
  `cpk_` for Chutes, `sk-or-` for OpenRouter).
- A container registry you can push to (GHCR, Docker Hub, Quay, …).

## 1. Chain registration

Establishes your hotkey on the metagraph. This is plain Bittensor: burn the
registration cost and obtain a UID.

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
./scripts/register_testnet.sh miner
```

At this point you exist on chain but are unknown to Phylax and receive no work.

## 2. Track registration

Declare the single track you commit to: `skills`, `mcp_servers`, `packages`, or
`repositories`. Set it in `.env`:

```ini
PHYLAX_TRACK=skills
PHYLAX_SERVER_URL=https://<phylax-server>
```

A miner is in exactly one track; a second track means a second hotkey.

## 3. Build your agent

Your agent is a program implementing the Phylax agent contract (see
[agent_contract.md](agent_contract.md)):

```python
def agent_main(context: dict) -> dict:
    # context = { artifact_dir, track, nonce, probe, inference, sandbox }
    # detonation tracks: load + run the artifact, thread the probe through the
    #   sandbox, capture fs/network/process traces, build dual-plane evidence
    # repositories: audit source statically, list vulnerabilities (no probe)
    return sssa_envelope   # verdict + evidence + findings
```

You choose the LLM provider and model; Phylax does not dictate it. The reference
agent at `phylax/harness/skills_reference_agent.py` is your starting point.
Production miners compete on detonation depth and capability/context precision.

## 4. Self-test locally

Run your agent against the track corpus exactly as a validator would, before
committing anything:

```bash
# build the agent base + bring up the local stack
./scripts/run_local.sh
```

Iterate against the corpus under `corpora/<track>/` until your verdicts and
evidence match the labelled expectations.

## 5. Build the agent image and submit

When the validator audits you, it pulls your **exact image by digest** to rerun
your agent jailed, so the digest is what makes those reruns reproducible.

```bash
./scripts/build-agent.sh ghcr.io/<you>/phylax-agent-skills:v1
# copy the printed PHYLAX_SANDBOX_IMAGE + PHYLAX_SANDBOX_DIGEST into .env
```

Set the rest of `.env` and submit:

```ini
PHYLAX_EXECUTION_API_KEY=cpk_…          # or sk-or-… ; spent by the validator
PHYLAX_INFERENCE_MODEL=...               # optional
PHYLAX_AGENT_PATH=./my_agent.py          # optional; defaults to the reference agent
PHYLAX_DEPENDENCY_MANIFEST=./requirements.txt   # optional
PHYLAX_SANDBOX_IMAGE=ghcr.io/<you>/phylax-agent-skills:v1
PHYLAX_SANDBOX_DIGEST=sha256:…
```

```bash
./scripts/register.sh        # registers the track + submits the agent
```

The server returns an agent id + version. Re-running submits a new version that
supersedes the old one. Your active registration is now: this hotkey, in this
track, running this versioned agent, in this image, funded by this key.

## 6. Run the neuron and earn

```bash
docker compose pull && docker compose up -d
```

The miner neuron does the work: it requests a task for your agent, runs the agent
on the artifact, signs the SSSA with your hotkey, and submits it. The server
verifies the proof-of-execution and scores each SSSA, and the validator reruns a
sample to confirm your verdicts reproduce. The top three agents in your track earn
that round's emissions.

## What your agent receives per task

```json
{
  "artifact_dir": "/task/artifact",
  "track": "skills",
  "nonce": "…",
  "probe": { "file_path": "/skill/.probe_…", "file_content": "…",
             "dns_host": "….probe.phylax.ai", "process_echo": "…", "canary": "…" },
  "inference": { "api": "<proxy url>", "api_key": "<your key>", "provider": "…", "model": "…" },
  "sandbox": { "image": "…", "digest": "sha256:…" }
}
```

Your agent must thread the probe (write the file, look up the DNS host, echo the
process token) so the proof-of-execution holds: the server confirms, in the
captured traces, that you really executed, and the validator re-checks it on a
sample. Missing or mismatched probe evidence fails the evidence gate and scores 0.
When the agent is jailed (the docker executor), the inference key reaches the LLM
only through the metered proxy, so it cannot be exfiltrated.

## What you return

One SSSA per task (see [sssa_schema.md](sssa_schema.md)). You fill `verdict`,
`evidence`, and `findings`, and your miner signs the SSSA with your hotkey before
submitting it.

## Hard rules

- One track per hotkey.
- The probe must appear in your traces or you score 0.
- Report canonical capability names (see [scoring.md](scoring.md)); fabricated or
  off-track names do not raise evidence integrity.
- Your image must be reproducible by digest. Reruns must produce the same probe
  effects.
- Never try to reach the open internet from the sandbox; only the inference proxy
  is reachable.

## Configuration reference

| Variable | Purpose |
|---|---|
| `PHYLAX_SERVER_URL` | control-plane URL |
| `PHYLAX_TRACK` | your single track |
| `PHYLAX_EXECUTION_API_KEY` | inference key the validator spends (`cpk_`/`sk-or-`) |
| `PHYLAX_INFERENCE_MODEL` | optional model id |
| `PHYLAX_SANDBOX_IMAGE` / `PHYLAX_SANDBOX_DIGEST` | registered agent image + digest |
| `PHYLAX_AGENT_PATH` | path to your agent (defaults to the reference agent) |
| `PHYLAX_DEPENDENCY_MANIFEST` | optional manifest stored with the submission |
| `WALLET_NAME` / `WALLET_HOTKEY` | wallet identity |

## Troubleshooting

- **Scoring 0 every task**: the probe is not landing in your traces. Confirm your
  agent writes `probe.file_path`, resolves `probe.dns_host`, and echoes
  `probe.process_echo` during detonation.
- **Submission rejected with "register into a track first"**: run
  `./scripts/register.sh` (it registers the track before submitting the agent), or
  check `PHYLAX_TRACK`.
- **Inference failing**: the agent must call the LLM via `context["inference"]
  ["api"]` (the proxy), not the provider directly; the sandbox is network-jailed.
