# Scoring Algorithm

How a validator turns an SSSA into a Bittensor weight. Mirrors whitepaper §5.3 exactly.

## Composite

For each (miner, task) pair the validator computes an **evidence-gated**
composite. Evidence is treated as a multiplicative gate rather than an
additive term — a miner that didn't actually run the sandbox earns zero
regardless of how well their other axes look.

```
Q(m_i, S) = 0                                              if ε < ε_gate
Q(m_i, S) = (w_α·α + w_π·π + w_η·η) / (w_α + w_π + w_η) · ε   otherwise
```

| Axis | Symbol | Weight | What it measures |
|---|---|---|---|
| Detection accuracy   | α | 0.45 | Correct ALLOW / WARN / BLOCK with asymmetric FN penalty |
| Evidence integrity   | ε | 0.30 (gate) | Hash equality of N/F/P/K traces vs validator replay |
| Policy effectiveness | π | 0.20 | Precision-weighted F0.5 over the policy constraint set |
| Efficiency           | η | 0.05 | Validator-measured submission latency vs τ_min / τ_max |

The gate threshold is `ε_gate = 0.10`. Above the gate, the non-evidence
axes are renormalised by their weight-sum (0.70) so a perfect miner still
tops out at 1.0; the result is then scaled by the evidence score. A miner
with 80% trace agreement and perfect other axes scores ≈ 0.80.

This diverges from the original whitepaper §5.3 pure linear sum and is a
deliberate change. Under the old formula a "lazy honest" miner with
`detection = policy = efficiency = 1.0` and `evidence = 0` scored the
weighted sum `0.70` — paying full reward to non-participants. The gated
form ensures that no proof of execution means no reward.

A harmonic-mean variant is available as `compute_harmonic_score` for
diagnostic dashboards but does not drive emissions.

## Axis 1 — Detection accuracy (α)

```
α(m_i, S) = 1 − λ · |V(verdict_i) − V(verdict*)| / 2
```

`V` maps ALLOW→0, WARN→1, BLOCK→2.

- **False negatives** (predicting weaker than truth, e.g. ALLOW for a BLOCK task) — λ = 1.0.
- **False positives** (predicting stronger than truth) — λ = 0.4.

Risk-score calibration further scales α by up to 10% when the verdict is correct, rewarding well-tuned `risk_score` values without ever rescuing a wrong verdict.

## Axis 2 — Evidence integrity (ε)

```
ε_j(m_i, S) = 𝟙[ H_j(m_i) = H_j*(S, η_i) ]    for j ∈ {N, F, P, K}
ε(m_i, S)   = (1/4) · Σ_j ε_j
```

`H_j*` is produced by the validator running the same pipeline under the per-miner nonce `η_i`. Hash equality is byte-exact. When the validator cannot replay (offline / corpus-only mode) the axis is capped at 0.5 so it never preferred over real replay.

## Axis 3 — Policy effectiveness (π)

Policies are flattened into a set of typed constraints `(kind, value)` and compared via F-β:

```
Precision_π = |C_i ∩ C*| / |C_i|
Recall_π    = |C_i ∩ C*| / |C*|
π = (1+β²) · P·R / (β²·P + R)              β = 0.5
```

Precision is weighted higher than recall — overly permissive policies are more dangerous than overly restrictive ones. A mild envelope penalty (±20% max) tolerates memory/timeout values within 2× of the expected range.

## Axis 4 — Efficiency (η)

```
η = 0                                          if τ_i < τ_min
η = 1 − (τ_i − μ_τ) / (τ_max − μ_τ)             if τ_i ≥ τ_min
```

- `τ_i` is the **validator-measured** submission latency. The miner's self-reported `analysis_duration_ms` is only used as a fallback (capped at 0.7).
- `τ_min` per profile: fast 200 ms, standard 2 s, deep 10 s.
- `τ_max` per profile: fast 30 s, standard 180 s, deep 900 s.
- `μ_τ` is the round-median latency across all miners.

A submission faster than `τ_min` scores zero and is logged for pipeline-integrity review.

## Epoch aggregation (§5.4)

```
Q̄(m_i) = (1/n) · Σ_j Q(m_i, S_j)
```

The per-round vector is blended into the running `self.scores` via EMA with α = 0.2 (default; tune via `EMA_ALPHA`). The smoothed vector is normalised to sum=1 and pushed on-chain every `WEIGHT_UPDATE_INTERVAL` blocks (default 100).

## Anti-gaming summary

| Strategy | Why it fails |
|---|---|
| Block-all  | Known-Good / Near-Miss tasks drop α; over-deny policies tank π. |
| Allow-all  | Known-Bad tasks drop α catastrophically (FN λ = 1.0). |
| Copy another miner's SSSA | Nonce η_i differs per miner ⇒ evidence hashes differ ⇒ ε = 0. Validator also rejects on hotkey mismatch in the signature check. |
| Skip sandbox / fake hashes | ε = 0 (no replay match); η = 0 if submitted under τ_min. |
| Overfit public corpus | Synthetic + canary families inject novel tasks per round. |

See `tests/test_whitepaper_conformance.py` for the executable form of these guarantees.
