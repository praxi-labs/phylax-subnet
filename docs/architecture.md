# Phylax Architecture

End-to-end picture of how a skill bundle becomes a Signed Skill Safety Attestation, mapped to whitepaper sections.

## High-level flow

```
                            ┌────────────────────────────────────────┐
                            │            Skill ingest                │
                            │  (registry crawler / API submit /      │
                            │   runtime trigger / synthetic gen)     │
                            └──────────────┬─────────────────────────┘
                                           │  S, metadata
                                           ▼
            ┌────────────────────────────────────────────────────────┐
            │              Validator (§5)                            │
            │  - generate per-miner nonce η_i (§5.1)                 │
            │  - run BaselineRunner under each η_i (§5.2)            │
            │  - broadcast (S, η_i, deadline) to each miner          │
            │  - measure submission latency τ_i                      │
            │  - verify signatures + miner-hotkey identity           │
            │  - score α, ε, π, η ⇒ Q (§5.3)                         │
            │  - consensus argmax over Σ Q (§6.2)                    │
            │  - countersign + publish to registry (§6.3)            │
            │  - aggregate Q̄, EMA, set_weights (§5.4)                │
            └─────────────┬───────────────────────┬──────────────────┘
                          │  PhylaxSynapse        │  consensus SSSA
                          ▼                       ▼
            ┌────────────────────┐    ┌────────────────────────┐
            │      Miners        │    │  Attestation Registry  │
            │  3-layer pipeline  │    │  (SQLite, §6.3)        │
            │  static + SBOM     │    └──────────┬─────────────┘
            │  + sandbox(η_i)    │               │  GET /v1/attestation/{H}
            │  Sign SSSA         │               ▼
            └─────────┬──────────┘    ┌────────────────────────┐
                      │ SSSA          │   Runtime / Marketplace│
                      └──────────────►│   PhylaxClient + 5-step│
                                      │   verifier (§9.1)      │
                                      └────────────────────────┘
```

## Module map

| Module | Whitepaper § | Role |
|---|---|---|
| `phylax.protocol`              | §3, §5.1 | Pydantic schema for the SSSA + `PhylaxSynapse` wire object with `nonce`. |
| `phylax.pipeline.static`       | §4.1 L1 | AST + regex scan, prompt-injection, network-persistence rules. |
| `phylax.pipeline.sbom`         | §4.1 L2 | SBOM, typosquat, install-hook, **osv.dev CVE lookup**. |
| `phylax.pipeline.sandbox`      | §4.1 L3 | Locked Docker detonation. Seed always supplied by caller. |
| `docker/harness/run.py`        | §4.1 L3 | In-container hooks: fs / network / DNS / env (all three idioms) / processes. Writes completion marker. |
| `phylax.policy.generator`      | §3.3 | Least-privilege RecommendedPolicy from observed capabilities. |
| `phylax.attestation.signer`    | §3, §6.2, §9.1 | Miner signing, validator countersigning, 5-step verifier. |
| `phylax.scoring.metrics`       | §5.3 | α (asymmetric λ), ε (hash equality), π (F0.5), η (τ_min floor). |
| `phylax.scoring.rewards`       | §5.3 | Weighted linear sum primary; harmonic diagnostic only. |
| `phylax.validator.baseline`    | §5.2 | Validator-side pipeline → GroundTruth. |
| `phylax.validator.consensus`   | §6.2 | Quality-weighted argmax verdict. |
| `phylax.validator.registry`    | §6.3 | SQLite content-addressed attestation store with invalidation. |
| `phylax.validator.corpus`      | §7.4 | Loads all seven families with schema validation. |
| `phylax.validator.synth`       | §7.3 | Per-round adversarial / canary / near-miss / prompt-conditioned generator. |
| `neurons.validator`            | §5 + §6 | End-to-end orchestrator using the above. |
| `neurons.miner`                | §4 + §5.1 | Three-layer pipeline driver, signs SSSA. |
| `phylax.api.server`            | §6.1, §6.3, Appendix A | FastAPI: POST /scan, GET /attestation, invalidate, health. |
| `phylax.client.runtime`        | §9.1, §9.2 | Runtime SDK: fetch + verify + PolicyEnforcer. |
| `phylax.cli`                   | §9.2 | `phylax check` / `verify` / `export-schema`. |

## Anti-gaming invariants

1. **Nonce-salted detonation**: validator hands a fresh `η_i` to each miner; same skill produces miner-specific evidence hashes. Copy attacks fail the ε axis.
2. **Validator replay**: `BaselineRunner` runs the same pipeline under `η_i` to compute `H_j*`; ε is hash equality, not presence.
3. **Validator-measured latency**: η axis uses τ measured at the dendrite, not the miner-self-reported `analysis_duration_ms`.
4. **Asymmetric verdict penalty**: FN λ = 1.0, FP λ = 0.4 — miss-a-threat is more expensive than over-block.
5. **Signature + identity**: validator rejects SSSAs whose ed25519 signature or `miner_hotkey` doesn't match the responding UID.
6. **Synthetic + canary**: unbounded corpus; benchmark memorisation cannot carry across rounds.

These are exercised by `tests/test_whitepaper_conformance.py` and `tests/test_nonce_anticopy.py`.

## Harness evolution

The components every miner must run identically (the classifier, the reference harness, the sandbox probes) are not frozen. They evolve through a competitive submission track open to any registered hotkey.

```
SUBMIT          miner uploads a component version, hotkey-signed
   │
BENCHMARK       validator replays it against the ground-truth corpus
   │            (canaries + known-good + known-bad)
   │            axes: detection accuracy, false-positive rate,
   │            classification accuracy, runtime cost
   │
THRESHOLD       composite must beat the current champion by >= 2%
   │
REVIEW          human gate (Praxi Labs during testnet)
   │
ADOPT           version becomes canonical, pinned by hash,
   │            announced to the network on the next round
   │
REWARD          author earns the developer stream (5% of miner
                emissions) while their version stays canonical
```

Version pinning is what keeps this compatible with the anti-gaming invariants above: every classification and every probe result carries the component version that produced it, so auditors reproduce results against the same pinned code, and rounds stay replayable after an upgrade.

Execution stays distributed. Evolution changes which shared code the network runs, never who runs it: scan and audit work continues to flow through independent miners exactly as described in the high-level flow.
