# The Phylax Mechanism

This document is the mechanism specification for subnet 76. It defines what miners
optimise against and what every validator enforces. The sections marked **frozen**
are a commitment: agents built against them keep working. The sections marked
**tunable** can change with notice and never invalidate an agent.

Status: the subnet code and the backend implement this spec, including the slot
cap at submission, slot release on deregistration, and eviction after six below
threshold rounds.

## Overview

Miners submit hash pinned detection agents. Each agent is registered to exactly one
of four tracks and analyses artifacts of that type, returning a verdict with
evidence. Every validator evaluates all four tracks every round: it derives a
shared task set per track from the chain, runs every registered agent against it in
a sealed sandbox, scores the results against ground truth labels with the pinned
metric, and sets a single weight vector spanning all tracks. Yuma consensus
reconciles validators by stake weighted median.

The design principle throughout: every validator runs the identical mechanism.
Same pool, same budgets, same failure rules, same metric. Each validator draws
its own task set from the round's frozen pool, so a round covers far more of the
corpus than any one validator sees, and every agent a validator evaluates faces
that validator's identical set. The draw is derived from the round seed and the
validator's hotkey rather than chosen, so anyone can recompute it afterwards and
no miner can know its tasks in advance. A miner's score is the average across
validators, so it does not rest on any single one.

## Tracks and emission shares (frozen)

| Track | Artifact | Emission share |
| --- | --- | --- |
| repositories | source repositories | 0.675 |
| packages | package releases | 0.225 |
| mcp_servers | MCP servers | 0.075 |
| skills | agent skills | 0.025 |

The shares sum to 1.0 and are applied inside every validator's weight vector, not
left to how validator stake happens to spread across tracks.

## Registration and track slots

Chain registration on netuid 76 is permissionless. Track binding happens at agent
submission through the backend, and each track has a slot cap:

- **80 slots per track** (tunable with notice). A submission to a full track is
  rejected; the miner picks another track or waits for a slot.
- A slot is freed when its hotkey deregisters from the metagraph.
- A slot is evicted when its agent scores below the track threshold for six
  consecutive rounds. Parking a dead agent on a slot does not hold it.
- A slot is freed when the miner withdraws its agent.

One hotkey, one track, one active agent. A new submission from the same hotkey
supersedes the previous version.

This is enforced at submission. Re-registering to a second track does not retire
the agent on the first, so submitting into the new track is refused with 409
while the old one is still active. To move tracks, withdraw first:

```bash
DELETE /v1/specialization/agent/{hotkey}
```

Withdrawal releases the slot immediately and every active agent the hotkey holds,
then registration and submission on the new track proceed normally. Superseding
your own agent on the track you already occupy is an update and is unaffected.

## The agent contract (frozen)

- A single Python file, at most 256 KiB of source. The server caps `code` at
  262,144 characters and the whole submission body at 266,240 bytes, the latter
  being the code cap plus room for the JSON envelope. Exceeding the body cap
  returns 413 and exceeding the code cap returns 422. `MAX_AGENT_BYTES` in the
  validator is 512 KiB but never binds, because the server refuses first.
- Entrypoint `agent_main(task: dict) -> dict` (a different name may be declared at
  submission; the function must exist in the file).
- The returned dict carries `verdict` (one of `BLOCK`, `WARN`, `ALLOW`), `evidence`
  (per track schema, see `phylax/analysis/`), and for repositories the findings
  lists scored by the metric below.
- The submission is signed over a digest binding track, code, entrypoint, and
  sandbox identifiers. The code hash is pinned at submission; validators verify the
  fetched code against it and reject mismatches.
- Agent code executes only inside the validator owned sandbox image, never an image
  the miner supplies. The sandbox's only network egress is the metered inference
  proxy. LLM calls carry a per agent, per task nonce; one agent's activity can
  never vouch for another's.

## Rounds

Rounds are opened by the operator, with an interval of **2 days** between them.

1. At round open the participant set freezes: every active agent per track, pinned
   by hash.
2. Per track, the backend freezes a pool of three times the task count. Each
   validator draws its own task set from that pool, seeded by the round seed and
   its own hotkey, so the draw is deterministic and reproducible after the fact
   while no two validators evaluate quite the same set.
3. Track order within the round is the validator's choice; a validator with
   capacity may run tracks concurrently. Consensus only sees the final vector.
4. Weights are set once per round, after all four tracks complete.

## Budgets (frozen)

Budgets are part of the mechanism, not validator preference. They are pinned in the
signed round spec; the env overrides that existed for development are removed from
the evaluation path.

| Track | Tasks | Repetitions | CPU budget per rep | Worst case per agent |
| --- | --- | --- | --- | --- |
| skills | 50 | 3 | 8 s | 1,200 CPU s |
| mcp_servers | 40 | 3 | 15 s | 1,800 CPU s |
| packages | 30 | 3 | 30 s | 2,700 CPU s |
| repositories | 50 | 2 | 90 s | 9,000 CPU s |

- The budget is **CPU time**, enforced through the container's cgroup accounting,
  not wall clock. Faster hardware must not change outcomes.
- A wall clock backstop of three times the CPU budget catches runs that sleep or
  stall on I/O; it is generous enough that hardware variance never decides an
  outcome.
- Each agent additionally holds a round wall cap of twice its worst case CPU
  budget per track. Once consumed, its remaining reps fail. This bounds how long
  a deliberately stalling agent can occupy a core.
- Sandbox limits per run: 2 GB memory (swap disabled), 1 CPU, 256 pids.

Validator floor specification: **16 vCPU, 32 GB RAM, 100 GB disk**. The chain
caps the subnet at 256 UIDs, so with the three expensive tracks full (80
repositories, 80 packages, 80 mcp_servers) at most about 14 miners remain for
skills. That worst legal allocation is about 1,096,800 CPU seconds; at 14
execution cores that is about 21.8 hours, under 75% of the round window, which is
30 hours. A slate of
maximally stalling agents can still push wall time past the window; every
validator then abstains identically, the stallers score 0, and eviction clears
them within six rounds.

## Execution and liveness

- The executor is Docker and **fails closed**: if the sandbox image is unset or
  unavailable, the run does not fall back to host execution. The in process
  executor exists only behind an explicit development flag and never on the
  evaluation path.
- Sandbox hardening: non root, `cap-drop=ALL`, `no-new-privileges`, internal
  network with no internet, memory capped with swap off, CPU and pid limits, tmpfs
  `/tmp`. Agent code enters by copy, not bind mount.
- Liveness, behavioural tracks (skills, mcp_servers, packages): the validator
  derives a per rep probe from the task nonce and independently observes it by
  copying the probe file out of the container and byte comparing it. **The observed
  probe is required.** Metered inference is recorded into the attestation as
  supporting evidence but is not a substitute for the probe.
- Repositories is static analysis and exempt from liveness.

## Scoring (frozen)

### Reducing repetitions

Behavioural tracks: each task's completed reps vote. The task verdict is the
majority; with no strict majority, the median ordinal under `ALLOW < WARN < BLOCK`,
taking the lower ordinal on an even split. A failed rep (see failure semantics) is
excluded from the vote; it does not zero the task. A task with zero completed reps
counts as incorrect.

Repositories: each rep's findings are scored independently; the task score is the
mean over completed reps, 0.0 with zero completed reps.

### Behavioural tracks: clamped MCC

Per agent, per track: tally the confusion matrix over the task set from the task
verdicts against labels (`BLOCK` or `WARN` on a malicious label is a true positive,
`ALLOW` on a safe label is a true negative). The track score is:

```text
score = max(0, MCC)
```

MCC is robust to corpus imbalance. A zero denominator (any empty margin of the
confusion matrix) is defined as MCC 0, so the metric is fully specified at the
edge and under that convention every constant predictor sits at exactly MCC 0.
The clamp sends constant, random, and inversely correlated agents to a score of
0, below any threshold, while preserving ranking among real detectors. Raw MCC is
logged for diagnostics; the clamped value is what earns.

Worked example, 30 skills tasks, 8 malicious and 22 safe. An agent catches 6 of 8
(2 missed) and wrongly flags 2 safe artifacts: TP 6, FN 2, FP 2, TN 20.
MCC = (6x20 - 2x2) / sqrt(8 x 8 x 22 x 22) = 116 / 176 = 0.659. An agent answering
`ALLOW` to everything: TP 0, FN 8, FP 0, TN 22, MCC 0, score 0.

### Repositories: F-beta, beta = 2

Retrieval task, no bounded true negative set, so MCC does not apply. Per task:
findings are matched one to one against planted ground truth (the matcher in
`phylax/analysis/repositories.py`), giving recall R = matched / planted and
precision P = matched / reported. The task score is:

```text
F2 = 5PR / (4P + R)
```

Beta 2 tilts toward recall: a missed real vulnerability costs more than a flagged
benign one. The agent's track score is the mean task score over the task set.
Tasks with no planted findings score the existing clean precision rule.

A reported finding matches when it names the same file, agrees on the weakness,
and lands within ten lines of the planted one. The file may be given as a full
path or as a suffix of one. The weakness agrees when the CWE numbers match,
compared numerically so `CWE-79` and `CWE-079` are the same, against either the
primary CWE or any entry in `all_cwes`. Failing that, a title and description
overlap of at least 34% counts instead.

Worked example: 4 planted findings, the agent reports 5, 3 match. R = 0.75,
P = 0.6, F2 = 5 x 0.6 x 0.75 / (4 x 0.6 + 0.75) = 2.25 / 3.15 = 0.714.

### Quality thresholds (frozen, per track)

Thresholds gate earning eligibility and are calibrated to each metric's scale:

| Tracks | Metric | Threshold |
| --- | --- | --- |
| skills, mcp_servers, packages | clamped MCC | 0.20 |
| repositories | F2 | 0.50 |

## Failure semantics

The governing principle: **a fault of the agent scores zero deterministically; a
fault of the infrastructure abstains.** Agent faults are content determined and
identical on every validator. Infrastructure faults differ per validator and must
never leak into a weight vector.

| Event | Consequence |
| --- | --- |
| Rep exceeds CPU budget or wall backstop | That rep fails; other reps unaffected |
| Agent exceeds its round wall cap | Remaining reps of that agent fail |
| Rep killed by the memory limit | That rep fails |
| Missing or malformed result output | That rep fails |
| Liveness probe not observed (behavioural) | That rep fails |
| All reps of a task fail | Task counts as incorrect (behavioural) or 0.0 (repositories) |
| Oversized agent, missing entrypoint, wrong track, hash mismatch, copied code | Agent scores 0 for the round |
| Artifact fetch failure or digest mismatch at round start, after retries | Validator abstains |
| Participant code unfetchable, after retries | Validator abstains |
| Sandbox image unavailable | Validator abstains |
| Any track incomplete at window close | Validator abstains |

Abstaining means setting no weights that round. The validator's EMA state is
unchanged and it resumes the next round. A partial vector is never submitted:
under all tracks per validator, a missing track removes that track's entire
emission share from the vector, which is a consensus divergence, not a smaller
sample. Artifacts are materialised and digest
verified for all four tracks before execution begins, so fetch failures surface at
round start, not mid round.

## From scores to weights

Per round, each validator:

1. Applies the track threshold, ranks the eligible agents per track.
2. Pays the top three per track 0.50 / 0.30 / 0.20 of that track's emission share.
   Agents on equal scores are ordered by `sha256(round seeds : track : hotkey)`,
   so every validator resolves a tie the same way and consensus does not split on
   it. The order is unpredictable before the round and rotates between rounds.
3. Splits the total 95 performance / 5 contribution; the contribution pool divides
   equally among active agents from hotkeys with accepted corpus contributions.
4. Normalises to one vector over all miner UIDs. Each miner holds weight only in
   its own track.
5. Smooths: `w = 0.3 x w_new + 0.7 x w_prev` (EMA alpha 0.3, tunable). The prior
   vector persists in validator state.
6. Sets the vector on chain, once per round.

Commit reveal is enabled as a chain hyperparameter (owner side), with the reveal
interval under the immunity period, counted in tempos.

## Scoring metric versus blocking policy

The metric selects the best auditor. It is not the product's blocking policy.
Repository verdicts are advisory: beta 2 deliberately rewards recall, which is
correct for an audit report and wrong for an inline build gate. If repository
verdicts ever feed a blocking mode, the blocking threshold is set separately from
the scoring metric.

## Frozen versus tunable

**Frozen** (miners build against these; changing them is a mechanism version bump):

- The four tracks and their emission shares
- Chain seeded shared task selection
- The scoring metrics, their clamps, and the per track thresholds
- The agent contract: size cap, entrypoint, verdict schema, hash pinning
- The budgets table: tasks, repetitions, CPU budgets, sandbox limits
- The failure semantics table

**Tunable with notice** (never invalidates an agent):

- Round length
- Per track slot caps and the eviction window
- EMA alpha
- Commit reveal on/off and interval
- Validator isolation internals
- The serving path and catalog
