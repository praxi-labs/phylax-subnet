# Architecture

![Phylax architecture](images/architecture.webp)

Phylax spans two codebases. `phylax-subnet` is the decentralized part: the miner
and validator neurons, the round model, the sandbox, and the scoring code.
`phylax-server` is the product layer (marketplace, leaderboard) and also schedules
rounds and records results — but it never scores or picks winners.

## The design decision

The miner submits **code**, and the validators run it inside their own hardened
sandbox image. Because the network holds the code, the evaluated agent is the
served agent; because the validator owns the runtime, untrusted code runs in a
trusted jail rather than a miner-supplied image; because every validator runs the
same agents on the same tasks (a shared round seed), a dishonest validator is
visible; and because scoring is against held-out ground truth, a fabricated
report earns nothing. The server schedules and records; the chain decides.

## Module map

| Path | Role |
|---|---|
| `scripts/register_miner.py` | signs and submits a miner's agent (code + key) to the backend |
| `neurons/validator.py` | round loop: fetch agents from the backend, derive tasks, execute, score, set weights |
| `phylax/server_client.py` | validator and miner client for the backend (submit, round, results, fetch) |
| `phylax/protocol.py` | `AgentSynapse`: legacy peer-to-peer fetch, kept as the local-dev fallback |
| `phylax/rounds.py` | round boundaries, the round seed, deterministic task selection |
| `phylax/screening.py` | agent similarity detection against copied submissions |
| `phylax/analysis/` | scoring spine, proof verification, capability taxonomy, per track evaluators |
| `phylax/harness/runner.py` | runs one agent on one task (docker for validators) |
| `phylax/harness/executor.py` | the network isolated jail, plus the probe file observation |
| `phylax/harness/inference_proxy.py` | metered LLM egress for the jailed sandbox |
| `phylax/harness/corpus.py` | loads the labelled benchmark; ground truth never ships to agents |
| `phylax/utils/hashing.py` | canonical JSON, SSSA digest, submission digest |

## Agent distribution

The backend is the source of truth for agent code. Miners submit to it
(`POST /v1/specialization/agent`, signed by the hotkey); validators pull each
round's participants from it (`GET /v1/specialization/agent/{hotkey}/runnable`).
Miners run no serving neuron. The old peer-to-peer `AgentSynapse` (validator to
miner) remains only as a local-dev fallback when no backend is configured.

## The round

Rounds are scheduled by the server (`/v1/rounds/next`), not by block windows. When
the submission window closes, the server freezes the participant set (each active
agent and its code hash). The validator pulls each participant's agent from the
backend, verifies the fetched code hash against the frozen pin, screens for size,
entrypoint, and copied code, derives the task set from the round's shared seed,
runs every agent's code on every task `r` times inside the validator-owned sandbox
with the per-track timeout, scores against ground truth, posts signed results to
the server, and sets graduated weights above the quality threshold. Without a
server configured, a block-derived fallback seeds rounds from the chain for local
dev.

## Isolation

Miner code runs only inside the validator-owned sandbox image: an internal docker
network whose sole egress is the metered inference proxy, with CPU, memory, and
PID caps, capabilities dropped (`cap-drop=ALL`, `no-new-privileges`), and a
non-root user. The validator refuses to evaluate at all if the jail is
unavailable. Liveness for a behavioural run requires either the validator
observing the probe file inside the container or real metered inference for that
task — self-reported traces alone do not count.

## Eligibility and consensus

Validator eligibility is on chain and permissionless: a permit granted by stake
weight and positive vtrust from actively setting weights. Each validator sets
weights independently and Yuma consensus reconciles them by stake weighted median
with clipping.
