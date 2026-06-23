# Phylax Scoring

Scoring is server-side and per track. The miner runs its agent and submits the
signed SSSA; the server verifies the proof-of-execution, scores the result, and
updates the agent's running score. The validator reruns a sample to audit
reproduction, and the server exposes top-3 per-track weights the validators set
on chain. The canonical implementation is
`phylax-server/phylax_server/analysis/scoring.py` and the per-track evaluators
(e.g. `analysis/skills.py`).

## The spine: four components + a gate

Every track scores on the same spine:

| Component | Weight | Meaning |
|---|---|---|
| `verdict_correctness` | `W_VERDICT = 0.40` | did the verdict match ground truth (or rerun-confirmed reality) |
| `solution_quality`    | `W_SOLUTION = 0.35` | depth of capabilities + context findings |
| `benchmark_agreement` | `W_BENCHMARK = 0.25` | agreement with labelled benchmark |
| `evidence_integrity`  | gate + multiplier | how trustworthy the evidence is |

`evidence_integrity` is **both a hard gate and a multiplier**:

```
EVIDENCE_GATE = 0.10

if evidence_integrity < EVIDENCE_GATE:
    score = 0.0                      # hard gate, no partial credit
else:
    base  = W_VERDICT*verdict_correctness
          + W_SOLUTION*solution_quality
          + W_BENCHMARK*benchmark_agreement
    score = clip01(base * evidence_integrity)
```

An agent that cannot prove it executed (probe absent from traces, missing dual
plane) fails the gate and scores 0 regardless of how good its verdict looks.

## How the components are computed (skills track)

- **`verdict_correctness`**: `1.0` if the verdict matches the label
  (malicious means BLOCK or WARN, safe means ALLOW), else `0.0`; `0.5` when no label.
- **`evidence_integrity`**: proof-of-execution must pass first (else the whole
  evaluation returns 0). Then integrity reflects how many reported capabilities
  are canonical: `0.4 + 0.6 * canonical_fraction` (or `0.7` when no capabilities
  were claimed).
- **`solution_quality`**: `0.6 * capability_depth + 0.4 * context_depth`, where
  depth saturates with the number of canonical capabilities and injected-context
  findings observed.
- **`benchmark_agreement`**: verdict agreement on labelled benchmark tasks.

Other tracks reuse the spine with their own evaluator: `repositories` derives
`verdict_correctness`/`benchmark_agreement` from vulnerability recall against the
benchmark and has no probe gate (it is replaced by benchmark comparison).

## Capability taxonomy

Capabilities reported in the action plane are scored against a canonical
taxonomy (`analysis/capability.py`): a shared core (filesystem, process,
network, secrets, database, crypto, host, context/reasoning) plus per-track
extensions (e.g. `SUPPLY_CHAIN` for packages, `MCP_PROTOCOL` for mcp_servers).
Each capability has a protection level (`normal`/`dangerous`/`system`/`redact`)
mapping to a severity. Two agents observing the same behaviour map to the same
canonical names, so they are scored comparably. Non-canonical or
wrong-for-the-track names do not count toward integrity.

## Running agent score

Each accepted attestation updates the agent's score with an EMA:

```
score = 0.2 * new_task_score + 0.8 * previous_score
```

stored per agent in `AgentScore` along with attestation count and rerun pass rate.

## Emissions: per-track weighting + top-3

On-chain weights are computed by the server (`compute_emission_weights`) and
fetched by validators via `GET /v1/tasks/track/weights`.

**Per-track emission weight**: tracks are not equal; harder, higher-value tracks
get a larger share of emissions:

| Track | Emission weight |
|---|---|
| `repositories` | 0.30 |
| `packages`     | 0.30 |
| `mcp_servers`  | 0.22 |
| `skills`       | 0.18 |

**Top-3 per track, graduated**: within each track only the top three agents by
score earn, split `0.60 / 0.30 / 0.10` (re-normalised when fewer than three
qualify). Agents with a zero score never earn.

```
for each track:
    take the top 3 agents with score > 0
    give them track_emission_weight × (0.60, 0.30, 0.10)
normalise all assigned weights to sum to 1.0
```

The result is `{hotkey: weight}`. Each validator fetches it, maps hotkeys to UIDs
on its metagraph, and calls `set_weights`. Multiple validators converging on the
same server ranking is what produces consensus; validators that score
unfaithfully lose stake-weighted influence over time.

## Why this resists gaming

- **Gate before credit**: no verifiable execution, no score.
- **Server-issued nonce and probe**: the probe can't be pre-computed; only a real run
  produces matching traces.
- **Sampled rerun (L2)**: claimed results must reproduce in the registered image.
- **Canonical taxonomy**: fabricated or off-track capability names don't raise
  integrity.
- **Top-3 only**: copying the median earns nothing; you must be among the best
  in your track.
