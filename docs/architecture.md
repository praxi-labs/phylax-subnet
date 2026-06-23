# Phylax Architecture

Phylax is a Bittensor subnet that scores AI-supply-chain security analysis across
four isolated tracks. Miners compete by submitting an **agent** (versioned code +
sandbox image + inference key); validators run that agent on dispatched artifacts,
verify it really executed, score the result, and set on-chain weights.

## The four tracks

Each miner and validator commits to exactly one track. Tracks are isolated: a
miner registered for `skills` is never dispatched a `packages` artifact, and
scoring/weights are computed per track.

| Track | Artifact | Verification model |
|---|---|---|
| `skills`        | Agent-skill bundles | detonation + dual-plane + proof-of-execution |
| `mcp_servers`   | MCP server packages | detonation + dual-plane + proof + tool surface |
| `packages`      | pip/npm packages | detonation + install/import lifecycle + supply chain |
| `repositories`  | source repositories | static audit scored by benchmark recall (no probe) |

Three tracks **detonate** (run the artifact and observe it); `repositories`
**audits** (static analysis scored against known vulnerabilities).

## Agent-as-artifact

The unit of competition is the agent, not a live-answering node.

1. The miner builds an agent implementing `agent_main(context) -> SSSA`.
2. The miner submits it once: **code + sandbox image (ref + digest) + inference
   key + track binding**, signed with the hotkey, versioned.
3. The miner runs its own agent live on each dispatched task, signs the SSSA
   with its hotkey, and submits it. The server verifies the proof-of-execution
   and scores the result.
4. The validator independently reruns a sampled subset of attested tasks in the
   miner's registered image and reports whether the verdict reproduces.

The submitted agent (code + image) is what makes the validator's rerun possible:
the miner is an operator running live, and every verdict carries a proof of
execution the validator can re-check.

## End-to-end flow

```
miner:     register track, then submit the agent (code + image + key) once
miner:     dispatch_track_task     -> server picks an artifact, issues nonce + probe
miner:     run own agent on the task, thread the probe, sign the SSSA
miner:     submit_track_attestation -> server verifies probe-in-traces, scores,
                                        updates AgentScore
validator: rerun-sample            -> server returns a random subset of attested tasks
validator: rerun each in the registered image, compare the verdict
validator: report rerun            -> server folds reproduced/not into rerun_pass_rate
validator: track/weights           -> top-3 per track x emission weight x rerun_pass_rate
validator: set_weights on chain
```

## Proof-of-execution and verification layers

The server issues a fresh nonce per task and derives a **probe** from it: a
specific file write, DNS lookup, and process echo the agent's sandbox must
perform. The agent threads the probe through detonation and returns it (plus
captured fs/network/process traces) inside the SSSA.

- **L1: every task.** The server confirms the probe effects actually appear in
  the captured traces. This is the evidence gate: an agent that did not really
  run the artifact cannot fabricate matching traces. Insufficient or inconsistent
  evidence scores 0. (`repositories` replaces this with benchmark comparison.)
- **L2: sampled.** A random subset of tasks (plus suspicious submissions) is
  re-run; verdicts that do not reproduce are penalised. The miner cannot predict
  which tasks get re-audited.
- **L3: `repositories` only.** Recovered vulnerabilities are scored against the
  benchmark's known vulnerabilities by recall.

## Dual-plane evidence

Detonation tracks separate two planes:

- **Action plane**: the canonical capabilities the artifact actually exercised
  at runtime (filesystem, network, secrets, process, …), mapped to the shared
  capability taxonomy.
- **Context plane**: instructions/text the artifact injects into the agent's
  reasoning (prompt injection, hidden overrides, unicode anomalies).

A skill can be malicious on either plane; both are captured and scored.

## Module map

**phylax-subnet** (this repo, the neurons):

| Path | Role |
|---|---|
| `neurons/miner.py` | active loop: request task, run own agent, sign SSSA, submit |
| `neurons/validator.py` | audit loop: rerun sampled tasks, report reproduction, set weights |
| `phylax/harness/runner.py` | shared agent runner (used by miner runs and validator reruns) |
| `phylax/harness/agent_sandbox.py` | runs an agent (`agent_main`) in-process with a timeout |
| `phylax/harness/executor.py` | runs an agent in the registered image, network-jailed |
| `phylax/harness/inference_proxy.py` | metered LLM egress for the jailed sandbox |
| `phylax/harness/skills_reference_agent.py` | reference skills agent (probe + dual-plane) |
| `phylax/server_client.py` | signed client for the phylax-server |
| `docker/Dockerfile.agent` | reference agent base image miners extend |

**phylax-server** (separate repo, the control plane):

| Path | Role |
|---|---|
| `routers/specialization.py` | track registration + agent submission + runnable fetch |
| `routers/tasks.py` | task dispatch, attestation intake, rerun-sample, rerun report, `/track/weights` |
| `analysis/proof.py` | probe derivation + proof-of-execution verification |
| `analysis/capability.py` | canonical capability taxonomy (shared-core + per-track) |
| `analysis/tracks.py` | per-track evaluator dispatcher |
| `analysis/{skills,mcp,packages,repositories}.py` | per-track evaluators |
| `analysis/scoring.py` | scoring spine + emission weighting |
| `schemas.py` | canonical SSSA envelope + per-track evidence schemas |

## Eligibility (validators)

Validator eligibility is on-chain and permissionless: a node needs a validator
**permit** (granted by stake weight) and positive **vtrust** (proves it is
actively setting weights). No manual approval. This is the deliberate divergence
from team-gated designs.

## Anti-gaming invariants

- Server-issued nonce: the probe cannot be pre-computed, so the agent must
  actually run to produce matching traces.
- Evidence gate: no verifiable execution means score 0, with no partial credit.
- Sampled rerun: a claimed result must reproduce in the miner's registered image.
- Registered image by digest: reruns reproduce the exact environment.
- Top-3 per track: only the best few earn each round, so copying the median
  earns nothing.
