# Phylax: Decentralized Trust Layer for AI Agent Skills

> *φύλαξ — Ancient Greek for guardian, sentinel, watchman.*

[![Bittensor](https://img.shields.io/badge/Bittensor-Subnet-blue)](https://bittensor.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Status: Pre-launch](https://img.shields.io/badge/Status-Pre--launch-orange)]()

Phylax is a Bittensor subnet that turns untrusted AI agent skill bundles into Signed Skill Safety Attestations (SSSAs) — portable, verifiable, cryptographically-signed artifacts with enforceable execution policies.

## The Problem

Agent ecosystems scale through composable skills. The same extensibility creates a large attack surface: a malicious skill can steal API keys, exfiltrate data, establish persistence, or hijack agent behaviour through prompt injection.

Existing approaches use an LLM as the scanner. They are fast to build but fundamentally limited: the model itself is prompt-injectable, evasion via obfuscation is trivial without real execution, and the output is plain text rather than an enforceable contract.

## The Phylax Approach

Phylax runs a decentralized competition in which miners perform real behavioural sandbox detonation, produce cryptographically-signed evidence packs, and emit machine-readable policies that runtimes can enforce automatically. Validators independently replay the same pipeline under a per-miner nonce and score on hash equality — claims without matching evidence earn zero.

| | Traditional Scanners | Phylax |
|---|---|---|
| Analysis method | LLM text analysis | Real sandbox detonation |
| Evasion resistance | Low (prompt-injectable) | High (behavioural observation) |
| Output | Text report | Signed, enforceable contract |
| Verification | None | Validator-replayed evidence hashes |
| Scale | Centralized | Decentralized competition |
| Incentive | None | Bittensor TAO emissions |

## How it works

Each skill bundle submitted to Phylax passes through a three-layer miner pipeline (whitepaper §4.1) before producing a signed attestation.

**Layer 1 — Static Analysis.** Scans code structure, dangerous API patterns, permission discrepancies, and **prompt-injection / network-persistence** patterns.

**Layer 2 — Supply-Chain + SBOM.** Generates a full dependency graph, cross-references the [osv.dev](https://osv.dev) CVE database, detects typosquatting, flags malicious install hooks.

**Layer 3 — Behavioural Sandbox.** Executes the skill in a locked container seeded by the validator's per-miner nonce. Records network egress (with DNS), filesystem access, process spawning, and secrets access (all three Python idioms: `os.environ.get`, `os.environ[K]`, `os.getenv`).

The validator runs the **same three layers** to produce ground truth and scores miners on byte-equal hash equality (whitepaper §5.2).

## The Signed Skill Safety Attestation (SSSA)

```text
verdict:              ALLOW | WARN | BLOCK
risk_score:           0 - 100
capabilities:         { network, fs, process, secrets }
findings:             [ { severity, evidence, fix } ]
recommended_policy:   { enforceable JSON }
evidence:             { sha256 hashes of N, F, P, K traces }
attestation:          ed25519:miner_hotkey
countersignature:     ed25519:validator_hotkey (consensus rounds, §6.2)
```

Full reference: [docs/sssa_schema.md](docs/sssa_schema.md).

## Scoring

Each (miner, task) submission is scored on four axes combined via an **evidence-gated composite**: evidence is a multiplicative gate (no proof of execution = no reward), not an additive term.

| Axis | Weight | Measures |
|---|---|---|
| Detection accuracy α | 0.45 | Correct verdict with asymmetric FN penalty (λ_FN = 1.0, λ_FP = 0.4) |
| Evidence integrity ε | 0.30 (gate) | Hash equality of N/F/P/K traces vs validator replay |
| Policy effectiveness π | 0.20 | Precision-weighted F0.5 over the policy constraint set |
| Efficiency η | 0.05 | Validator-measured submission latency with τ_min floor |

```text
Q(m, S) = 0                                              if ε < 0.10
Q(m, S) = (0.45·α + 0.20·π + 0.05·η) / 0.70 · ε          otherwise
```

A miner who skips the sandbox earns zero, regardless of how good the other axes look. A miner with 80% trace agreement and perfect other axes scores ≈ 0.80. A harmonic-mean variant is available as a diagnostic. Epoch aggregation, EMA smoothing, and on-chain weight pushes are documented in [docs/scoring.md](docs/scoring.md).

## Anti-Gaming

| Strategy | Failure mode |
|---|---|
| Block-all | Known-Good / Near-Miss tasks crater α; π collapses on deny-all policies |
| Allow-all | Known-Bad tasks crater α via the asymmetric FN penalty |
| Copy another miner's SSSA | Per-miner nonce η_i ⇒ unique evidence hashes ⇒ ε = 0; signature/hotkey check also fails |
| Fabricate hashes / skip detonation | Validator replay produces different H_j*; ε = 0; η = 0 if under τ_min |
| Overfit public corpus | Synthetic + canary tasks injected per round; corpus is unbounded |

Conformance tests live in `tests/test_whitepaper_conformance.py` and `tests/test_nonce_anticopy.py`.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full module map. Key new packages:

- `phylax.validator.baseline` — runs the same pipeline as miners to produce ground truth (§5.2)
- `phylax.validator.consensus` — quality-weighted argmax verdict (§6.2)
- `phylax.validator.registry` — SQLite content-addressed attestation store (§6.3)
- `phylax.validator.corpus` — loads all seven corpus families
- `phylax.validator.synth` — per-round synthetic challenge generator (§7.3)
- `phylax.api.server` — POST /scan, GET /attestation, /verify, /invalidate, /health (Appendix A)
- `phylax.client` + `phylax.cli` — runtime SDK and CI gate (§9)

## Getting started

```bash
git clone https://github.com/praxi-labs/phylax-subnet.git
cd phylax-subnet
pip install -e .
docker build -f docker/Dockerfile.sandbox -t phylax-sandbox:latest .
```

- [Miner setup](docs/miner_setup.md)
- [Validator setup](docs/validator_setup.md) — **note: validators now require Docker**
- [REST API](docs/api.md)
- [Runtime integration](docs/integration.md)
