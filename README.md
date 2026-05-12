# Phylax: Decentralized Trust Layer for AI Agent Skills

> *φύλαξ — Ancient Greek for guardian, sentinel, watchman.*

[![Bittensor](https://img.shields.io/badge/Bittensor-Subnet-blue)](https://bittensor.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Status: Pre-launch](https://img.shields.io/badge/Status-Pre--launch-orange)]()

Phylax is a Bittensor subnet that transforms untrusted AI agent skill bundles into Signed Skill Safety Attestations (SSSAs): portable, verifiable, cryptographically-signed artifacts with enforceable execution policies.

## The Problem

Agent ecosystems scale through composable skills. That same extensibility creates a significant attack surface. A malicious skill can steal API keys, exfiltrate data, establish persistence, or hijack agent behavior through prompt injection.

Existing approaches rely on language models as the scanner, producing plain text reports. They are fast to build, but fundamentally limited. The model itself is a vulnerability surface that can be prompt-injected. Without real execution, evasion is trivial through obfuscated or delayed payloads. The output is a text report rather than an enforceable contract, and the whole system is centralized and unscalable.

## The Phylax Approach

Phylax runs a decentralized competition where miners perform real behavioral sandbox detonation, produce cryptographically-signed evidence packs, and emit machine-readable policies that runtimes can enforce automatically. Claims without evidence earn zero emissions.

| | Traditional Scanners | Phylax |
|---|---|---|
| **Analysis method** | LLM text analysis | Real sandbox detonation |
| **Evasion resistance** | Low (prompt-injectable) | High (behavioral observation) |
| **Output** | Text report | Signed, enforceable contract |
| **Verification** | None | Content-addressed evidence hashes |
| **Scale** | Centralized | Decentralized competition |
| **Incentive** | None | Bittensor TAO emissions |

## How It Works

Each skill bundle submitted to Phylax passes through a three-layer miner pipeline before producing a signed attestation.

**Layer 1: Static Analysis**
Scans code structure, dangerous API patterns, and permission surface without executing anything.

**Layer 2: Supply-Chain and SBOM**
Generates a full dependency graph, cross-references CVE databases, detects typosquatting, and flags malicious install hooks.

**Layer 3: Behavioral Sandbox Detonation**
Executes the skill in a locked container with full observability, including network egress monitoring, filesystem access tracing, process spawning observation, and secrets/environment access detection.

## The Signed Skill Safety Attestation (SSSA)

The SSSA is the primary output of the Phylax subnet: a machine-readable, cryptographically signed artifact. See [docs/sssa_schema.md](docs/sssa_schema.md) for the full field reference.

```
verdict:              ALLOW | WARN | BLOCK
risk_score:           0 - 100
capabilities:         { network, fs, process, secrets }
findings:             [ { severity, evidence, fix } ]
recommended_policy:   { enforceable JSON }
evidence:             { hashed logs, traces, pcap }
signature:            ed25519:miner_hotkey
```

## Scoring

Miners are evaluated on four axes per epoch. Scoring uses a harmonic mean, so a weak axis cannot be offset by strength elsewhere. A miner with perfect detection but no evidence integrity scores near zero.

| Axis | Weight | What It Measures |
|---|---|---|
| Detection Accuracy | 45% | Correct ALLOW / WARN / BLOCK decision and risk score calibration |
| Evidence Integrity | 25% | Findings backed by verifiable, replayable traces |
| Policy Effectiveness | 20% | Policy reduces risk without overreach or blanket denial |
| Efficiency | 10% | Latency and resource cost per scan |

```
Total Score = harmonic_mean(
    0.45 * S_detection,
    0.25 * S_evidence,
    0.20 * S_policy,
    0.10 * S_efficiency
)
```

See [docs/scoring.md](docs/scoring.md) for full details.

## Anti-Gaming Design

Phylax is built on the assumption that miners will attempt to game benchmarks. Several mechanisms are in place to prevent this.

**Canary skills** are hidden tasks with behaviors that only trigger under specific conditions and are not included in any public corpus.

**Near-miss benign samples** are safe code that superficially resembles dangerous patterns. Miners who over-block are penalized, not rewarded.

**Adversarial variants** include obfuscated malware, delayed triggers, and prompt-activated branches designed to defeat naive detectors.

**Consensus cross-checking** compares miner outputs on identical inputs. Outliers are reviewed and penalized.

**Evidence-gated scoring** means a miner cannot earn evidence score through claims alone. Submitted hashes must match replayed detonation results.

## Getting Started

```bash
git clone https://github.com/praxi-labs/phylax-subnet.git
cd phylax-subnet
pip install -e .
```

- [Miner Setup Guide](docs/miner_setup.md)
- [Validator Setup Guide](docs/validator_setup.md)

## Integration

Phylax SSSAs are designed to be consumed directly by agent runtimes and skill marketplaces. See [docs/integration.md](docs/integration.md) for the full runtime integration guide.
