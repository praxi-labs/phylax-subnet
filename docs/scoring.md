# Phylax Scoring
## Version 2.0

## Overview

For each `(miner, task)` pair the validator computes a composite quality score `Q` in `[0, 1]`. That score is then multiplied by a base weight, a tier multiplier, an early submission bonus, a role multiplier, a consensus multiplier, and any bootstrap bonus to produce an emission score for the task. Per-task emission scores are aggregated into a per-miner round score, blended through an EMA, and pushed on-chain via `subtensor.set_weights`.

Every component is multiplicative, not additive. A miner who fails any one of probe verification, evidence-hash consistency, deadline, t_min, or LLM-allowed-use rules earns zero for the task regardless of how good the rest of their submission looks.


## Base Axes (All Skill Types)

Four axes apply to every skill type.

### α — Detection accuracy

Measures how well the miner's verdict matches ground truth.

```
predicted_rank = {ALLOW: 0, WARN: 1, BLOCK: 2}[verdict.decision]
truth_rank     = {ALLOW: 0, WARN: 1, BLOCK: 2}[task.expected_verdict]
distance       = abs(predicted_rank - truth_rank)

if distance == 0:
    base = 1.0
elif predicted_rank > truth_rank:        # false positive
    base = 1.0 - 0.4 * distance / 2
else:                                    # false negative
    base = 1.0 - 1.0 * distance / 2

if distance == 0:
    base *= max(0.9, 1.0 - 0.1 * abs(risk_score - expected_risk) / 100)

alpha = base * provenance_weight
```

False negatives are penalised 2.5x harder than false positives. A miner who always returns ALLOW catastrophically loses α on BLOCK-labelled tasks.

| Provenance | Weight |
|---|---|
| Human-labelled task | 1.0 |
| Consensus-derived task | 0.7 |
| Consensus expired | 0.4 |

### ε — Evidence integrity

The multiplicative gate. If `ε < 0.10` the composite `Q` is zero regardless of the other axes. ε is type-specific, see the per-type formulas below.

### π — Policy effectiveness

Compares the miner's `recommended_policy` against the validator's expected policy. Constraints are flattened to typed `(kind, value)` pairs and compared with an F-β where precision is weighted higher than recall.

```
miner_constraints    = flatten(sssa.recommended_policy)
expected_constraints = flatten(task.expected_policy)

precision = |miner & expected| / |miner|
recall    = |miner & expected| / |expected|
f_beta    = f_score(precision, recall, beta=0.5)

mem_factor = 1.0 if max_memory_mb within 2x of expected else log_decay(ratio)
to_factor  = 1.0 if timeout_s within 2x of expected else log_decay(ratio)

pi = f_beta * (0.8 + 0.2 * (mem_factor + to_factor) / 2)
```

Overly permissive policies are more dangerous than overly restrictive ones. The β = 0.5 reflects that.

### η — Efficiency

Rewards submissions that arrive in the legitimate window.

```
t_min, deadline = task_metadata.t_min_s, task_metadata.deadline_s
completion      = synapse_round_trip_seconds

if completion < t_min:
    return 0.0                          # too fast, treated as cheating
if completion > deadline:
    return 0.0                          # too slow, treated as missing

fraction = (completion - t_min) / (deadline - t_min)

if fraction <= 0.25:
    eta = fraction / 0.25
else:
    eta = 1.0 - 0.4 * ((fraction - 0.25) / 0.75)

if not has_minimum_evidence(sssa, skill_type):
    return 0.0
```


## Type-Specific Axes

Each skill type adds one or two axes beyond the four base axes.

### μ — ML score agreement (`declarative` only)

```
miner_score     = sssa.evidence.type_specific.declarative.prompt_injection_ml_score
expected_score  = task.ground_truth.prompt_injection_ml_score
mu              = max(0.0, 1.0 - abs(miner_score - expected_score))
```

### σ — Shell coverage (`executable_script` only)

```
predicted_cmds = extract_predicted_commands(sssa.findings)
observed_cmds  = parse_shell_commands_jsonl(evidence_path)
sigma          = |predicted & observed| / |observed|
```

If no commands were observed, sigma = 0.5 (clean scripts are valid).

### ψ — Manifest integrity (`mcp_server` only)

```
psi = 1.0 if miner.mcp_manifest_hash == ground_truth.mcp_manifest_hash else 0.0
```

### τ — Tool poison recall (`mcp_server` only)

```
known_poisoned = task.ground_truth.poisoned_tool_names
miner_flagged  = extract_flagged_tools(sssa.findings)
tau            = |known_poisoned & miner_flagged| / |known_poisoned|
```

### χ — Transitive accuracy (`agent_composition` only)

```
expected_transitive = task.ground_truth.transitive_risk_score
miner_transitive    = sssa.evidence.type_specific.agent_composition.transitive_risk_score
error               = abs(expected_transitive - miner_transitive)
chi                 = max(0.0, 1.0 - error * 2)
```

### ρ — Injection recall (`rag_knowledge` only)

```
known_injections = task.ground_truth.hidden_instruction_locations
miner_score      = sssa.evidence.type_specific.rag_knowledge.hidden_instruction_score
expected_score   = |known_injections| / task.ground_truth.document_count
error            = abs(miner_score - expected_score)
rho              = max(0.0, 1.0 - error * 3)
```


## Per-Type Evidence Scoring (ε)

Evidence scoring is type-specific. For runtime types it folds in the semantic subset and depth bonus signals that come out of trace verification.

### `rag_knowledge`

```
if not block.rag_content_fingerprint:                    return 0.0
if fingerprint mismatch with ground_truth:               return 0.0

canary_found     = block.canary_id_found
findings_present = block.hidden_instruction_score is not None

if canary_found and findings_present:  return 1.0
elif findings_present:                 return 0.5
else:                                  return 0.2
```

### `declarative`

```
if not block.canary_id_found:          return 0.0

base = 0.6                              # canary found is the floor
if block.prompt_injection_ml_score is not None:   base += 0.3
if block.unicode_anomaly_detected is not None:    base += 0.1
return min(1.0, base)
```

### `executable_python`, `executable_script`, `mcp_server`, `agent_composition`

For runtime types, ε is a composite of base trace agreement, type-specific trace agreement, semantic subset (how many of the validator's reference events appeared in the miner's traces), and a small depth bonus.

```
if ground_truth.fs_trace_hash and miner.fs_trace_hash != ground_truth.fs_trace_hash:
    return 0.0                          # canary write deterministic, must match

base_score          = 0.5 * (matching base hashes / 4)
type_specific_bonus = 0.2 if type-specific hash matches ground_truth else 0.0
subset_contribution = 0.2 * trace_semantic_subset
depth_bonus         = clip(0.1 * (trace_depth_ratio - 1.0), 0.0, 0.1)

epsilon = clip(base_score + type_specific_bonus + subset_contribution + depth_bonus, 0.0, 1.0)
```

Specific hard fails per type:

| Type | Hard fails ε = 0 if... |
|---|---|
| `executable_python` | `fs_trace_hash` mismatch |
| `executable_script` | `fs_trace_hash` mismatch |
| `mcp_server` | `tool_calls_hash` or `mcp_manifest_hash` mismatch |
| `agent_composition` | `agent_calls_hash` mismatch |


## Composite Q Formula Per Skill Type

The non-evidence axes are combined with type-specific weights, normalised by their per-type sum, then multiplied by ε. The gate at `ε < 0.10` zeroes the whole composite.

```
EVIDENCE_GATE = 0.10
if epsilon < EVIDENCE_GATE: return 0.0
```

| Skill type | Non-evidence formula | Divisor |
|---|---|---|
| `rag_knowledge` | `0.45α + 0.20π + 0.05η + 0.15ρ` | `0.85` |
| `declarative` | `0.45α + 0.20π + 0.05η + 0.10μ` | `0.80` |
| `executable_python` | `0.45α + 0.20π + 0.05η` | `0.70` |
| `executable_script` | `0.40α + 0.20π + 0.05η + 0.10σ` | `0.75` |
| `mcp_server` | `0.35α + 0.15π + 0.05η + 0.10ψ + 0.10τ` | `0.75` |
| `agent_composition` | `0.35α + 0.15π + 0.05η + 0.10χ` | `0.65` |

```
Q = (non_evidence / divisor) * epsilon
```


## Tier Classification

Each per-task `Q` is classified into one of four tiers against a per-type baseline and a dynamic novel threshold.

```
REFERENCE_BASELINES = {
    "rag_knowledge":      0.35,
    "declarative":        0.40,
    "executable_python":  0.50,
    "executable_script":  0.48,
    "mcp_server":         0.45,
    "agent_composition":  0.40,
}

novel_threshold = max(server-tracked threshold, baseline * 1.5)

if Q < baseline:                         tier = BELOW_REFERENCE
elif Q < novel_threshold * 0.75:         tier = TIER_1_REFERENCE
elif Q < novel_threshold:                tier = TIER_2_OPTIMISED
else:                                    tier = TIER_3_NOVEL
```

| Tier | Multiplier |
|---|---|
| `below_reference` | 0.5 |
| `tier_1_reference` | 1.0 |
| `tier_2_optimised` | 1.4 |
| `tier_3_novel` | 2.0 |

### Dynamic novel threshold recalibration

At each epoch end, per skill type the validator computes the median of the top 5 `Q` scores observed that epoch, smooths it with the existing threshold (30% new, 70% old), and floors it at `1.5 * baseline`. The result is pushed to the server via `POST /v1/reputation/novel-thresholds`. The Novel tier moves upward as better miners enter.


## Emission Score Per Task

```
emission = Q
         * base_weight[skill_type]
         * tier_multiplier[tier]
         * early_submission_bonus
         * role_multiplier
         * consensus_score
```

### Base weights

| Skill type | Base weight |
|---|---|
| `rag_knowledge` | 0.5 |
| `declarative` | 0.7 |
| `executable_python` | 1.0 |
| `executable_script` | 1.2 |
| `mcp_server` | 1.6 |
| `agent_composition` | 2.0 |

### Bootstrap bonus

During the first 30 epochs after launch, `mcp_server` and `agent_composition` get `+0.5` added to their base weight to incentivise early adoption of the harder skill types.

### Early submission bonus

Computed against the timing window for the miner's role.

```
window = (deadline_s - t_min_s) * 1000
position = (latency_ms - t_min_s * 1000) / window

if position <= 0.25:        bonus = 1.15
elif position <= 0.50:      bonus = 1.08
else:                       bonus = 1.00
```

Applied only after trace and probe verification passes. Speed alone is not rewarded.

### Role multiplier

```
role_multiplier = 0.6 if role == auditor else 1.0
```

Auditors do less work (no trace bundle required) and earn proportionally less. The consensus multiplier still applies to them in full.

### Consensus multiplier

Computed across the verification group for the task. See the next section.


## Full SSSA Consensus

For each task with at least three valid responses in the verification group, the validator computes a per-miner consensus score in `[0, 1]` by comparing each miner's SSSA against the rest of the group.

### Field weights

| Component | Weight |
|---|---|
| Findings recall (canonical key matching) | 0.30 |
| Findings precision | 0.15 |
| Verdict agreement | 0.15 |
| Capabilities agreement | 0.15 |
| Risk score agreement | 0.10 |
| Dependencies agreement (CVE intersection) | 0.10 |
| Policy derivation alignment | 0.05 |
| **Total** | **1.00** |

```
consensus_score = clip(sum of weighted agreements, 0.0, 1.0)
```

### Verdict agreement

```
miner_verdict matches consensus → 1.0
one step apart (WARN vs BLOCK)  → 0.6
two steps apart (ALLOW vs BLOCK) → 0.0
```

### Risk score agreement

```
delta = abs(miner_risk - median_group_risk)
if delta <= 15:     1.0
elif delta <= 30:   0.5
else:               0.0
```

### Findings consensus

A finding is canonically identified by:

```
canonical_key = (layer_source, owasp_or_mitre_ref, affected_file, line_bucket)
                where line_bucket = line_number // 5
```

This tolerates ±5 lines of disagreement and ignores wording differences. The `consensus_findings` set is the keys reported by at least 60% of the group. From this:

```
findings_recall    = |miner_keys & consensus_keys| / |consensus_keys|
findings_precision = |miner_keys & consensus_keys| / |miner_keys|
```

### Capabilities, dependencies, policy

Same threshold-based set agreement as findings, using:

| Field | Signature |
|---|---|
| `capabilities` | tuples like `(net_domain, value)`, `(fs_read, path)`, `(proc, cmd)`, `(secret, type)`, `(tool, name)`, `(child, name)` |
| `dependencies` | CVE strings from `known_cves` |
| `recommended_policy` | derived from policy fields, scored as overlap with consensus capabilities |


## Round Aggregation

```
per_uid_emissions[uid] = list of all per-task emission scores
                         the miner produced this round

round_Q[uid] = weighted_mean(
    emission_score * per_type_reputation[skill_type],
    weight = effective_base_weight(skill_type, current_epoch),
)

# EMA with α = 0.2
self.scores[uid] = 0.2 * round_Q[uid] + 0.8 * self.scores[uid]

# On-chain push every WEIGHT_UPDATE_INTERVAL blocks
weights = normalise(self.scores)
subtensor.set_weights(uids, weights)
```


## Reputation Updates

After each round the validator pushes one update per `(miner, task)` to the server. The server applies the rules below to that miner's per-type reputation row.

| Update type | Trigger | Effect on rep |
|---|---|---|
| `canary` pass | `ε ≥ 0.8` on a canary task | `+0.05`, capped at 1.0 |
| `canary` fail | `ε < 0.8` on a canary task | `× 0.7` |
| `standard` high | `ε ≥ 0.8` on a standard task | `+0.02`, capped at 1.0 |
| `standard` mid | `0.5 ≤ ε < 0.8` | unchanged |
| `standard` low | `ε < 0.5` | `× 0.95` |
| `bounty` pass | `ε ≥ 0.5` on a bounty task | `+0.05`, capped at 1.0 |
| `bounty` fail | `ε < 0.5` on a bounty task | `× 0.7` |
| `violation` | LLM use violation, sandbox digest mismatch, type mismatch, coverage violation | `× 0.5` |
| Rerun verification pass (next round) | Async miner-image rerun confirms honesty | `+0.02` |
| Rerun verification fail (next round) | Async rerun shows divergence | `× 0.7` |

### Recovery flow

When per-type reputation drops below 0.2, the miner is excluded from server_curated routing. To recover they must:

1. Re-register their specialization. The server resets the row to `reputation = 0.3` and `recovery_streak = 0`.
2. Pass 5 consecutive canary tasks at `ε ≥ 0.8`. After the fifth pass `recovery_streak` is cleared and they re-enter the normal routing pool.

### Inactivity decay

A row that has not received any task for 30 days enters the decay window. After the grace period, reputation decays with a 30-day half-life, applied lazily on the next read or update of the row.

```
days = (now - last_task_at).days

if days <= 30:
    decayed = reputation
else:
    decayed = reputation * 0.5 ** ((days - 30) / 30)
```


## Anti-Gaming Summary

| Strategy | Why it fails |
|---|---|
| Always return ALLOW | α loses catastrophically on BLOCK tasks (FN penalty λ = 1.0). Findings consensus also pulls miner away from the group. |
| Always return BLOCK | Known-good and rag_knowledge tasks drop α. Policy over-restriction tanks π. |
| Skip the sandbox entirely | ε = 0 (canary write absent from `fs.jsonl`, probe events missing from traces, hashes don't match miner's own SSSA). |
| Cache verdicts for repeated bundles | The canary marker (`rag_knowledge`, `declarative`) and the nonce-derived canary write (runtime types) make every dispatch unique. Cached verdicts cannot reproduce the per-nonce probe events or canary writes. |
| Submit before `t_min` | η = 0. Submission flagged in logs. |
| Submit after `deadline` | Discarded entirely. No score and no reputation update. |
| Type-mismatch SSSA | Treated as invalid (skill_type mismatch). Reputation flagged as violation. |
| LLM-forbidden use | Forbidden `allowed_use` values trigger violation. Reputation × 0.5. |
| Run a different sandbox than the one registered | `sandbox_manifest.digest` does not match the registered `image_hash`. ε = 0 in the round. Async rerun also produces divergent fs_trace_hash. |
| Copy another miner's SSSA | Validator computes consensus across the group. A miner who duplicates verdict but diverges on findings, capabilities, dependencies, and policy gets a low consensus_score that multiplies their emission down. |
| Coordinate with other miners (collusion) | The validator records agreement with primaries vs agreement with random auditors over 30 rounds. A consistent gap of `agree_with_primaries > 0.90` and `agree_with_auditors < 0.60` accumulates collusion flags. Three flags excludes the miner from group selection. |
| Fabricate trace_bundle hashes | Validator decompresses each trace file, normalises with `ts`-sorted JSON, and recomputes the sha256. Mismatch with the miner's own SSSA fails the round immediately. |
| Run the reference image but claim a different one | Async miner-image rerun pulls the registered image. Pulled digest must equal the registered `image_hash`. Mismatch fails. |


## Emission Split: Operate vs Evolve

Miner emissions are divided across two tracks.

| Track | Share | Earned by |
|---|---|---|
| Operate | 95% | Running a miner: per-task Q scores aggregated into round scores, EMA-blended, pushed on-chain. Everything above this section describes Track 1. |
| Evolve | 5% | Authoring an adopted improvement to any subnet component: detection, sandbox, validator, scoring, protocol, tooling. Divided equally across all currently adopted contributions. |

The Evolve stream pays the author of each adopted contribution for as long as it stays canonical. When no external contribution is currently adopted, the developer stream accrues to the subnet treasury rather than redistributing to Track 1, so there is always a standing bounty for improving the subnet.

Adoption of detection and classification changes requires beating the current champion by at least 2% composite on the ground-truth benchmark (detection accuracy, false-positive rate, classification accuracy, runtime cost). Changes outside the detection path are assessed on measurable impact: performance, cost, correctness, tests. Everything passes human review before adoption. Submissions are public; the threshold makes copy-resubmission worthless.
