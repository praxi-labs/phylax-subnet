# Scoring Algorithm

How validators turn an SSSA into a Bittensor weight.

## Overview

Each miner response is scored on four independent axes. Each axis returns
a value in `[0.0, 1.0]`. The axes are combined via a **weighted harmonic
mean** to produce a single score.

```
TS = sum(w_i) / sum(w_i / (s_i + ε))
```

The harmonic mean is chosen deliberately: it **collapses toward the
weakest axis**. A miner with 100% detection accuracy but 0% evidence
integrity scores near zero — gaming one axis cannot mask negligence in
another.

## The four axes

| Axis | Weight | What it rewards | Anti-gaming target |
|---|---|---|---|
| Detection accuracy   | 45% | Correct verdict + correct risk score | Blanket ALLOW or blanket BLOCK |
| Evidence integrity   | 25% | Verifiable, hashable evidence trail | Claims without proof |
| Policy effectiveness | 20% | Least-privilege policy that still works | "Deny everything" policies |
| Efficiency           | 10% | Latency and resource economy | Slow, wasteful scans |

### Axis 1 — Detection accuracy (45%)

Penalises the miner on two sub-axes:

- **Verdict distance** (70% of axis) — the categorical gap between
  predicted and ground-truth verdict.
  - ALLOW↔WARN, WARN↔BLOCK: 40% penalty
  - ALLOW↔BLOCK: 100% penalty (catastrophic)
- **Risk-score MSE** (30% of axis) — normalised squared error.

### Axis 2 — Evidence integrity (25%)

The validator checks:

- Are all expected evidence hashes present? (`network_trace_hash`,
  `fs_trace_hash`, `process_trace_hash`, `secrets_trace_hash`,
  `sandbox_log_hash`)
- Do per-finding `evidence.trace_hash` references exist?
- Are hash strings well-formed (`sha256:<64 hex>`)?

A future iteration will fully replay the sandbox on the validator side
and require byte-equal hashes; for now we score format + presence.

### Axis 3 — Policy effectiveness (20%)

Compares the miner's `recommended_policy` to the task's
`expected_policy`:

- Jaccard similarity on egress allowlist
- Exact match on `shell_access`
- Envelope match on memory + timeout (within 2× is fine)

### Axis 4 — Efficiency (10%)

Target durations per profile:

| Profile | Target |
|---|---|
| fast | 5s |
| standard | 60s |
| deep | 5min |

Within target → 1.0. Beyond target → exponential decay.

## EMA smoothing

Per-round scores are blended into the running score via exponential
moving average with `alpha=0.1`. A single bad round won't tank a miner;
a sustained pattern will.

## Weight push

Every `WEIGHT_UPDATE_INTERVAL` blocks (default 100, ~20 minutes), the
running score vector is normalised and pushed on-chain via
`subtensor.set_weights`. The chain's Yuma Consensus then determines TAO
emissions.

## Why no per-axis hard floors

We considered adding hard floors (e.g. axis_score < 0.2 ⇒ total = 0)
but the harmonic mean already produces this behaviour smoothly without a
discontinuity that miners could probe.
