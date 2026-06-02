# Phylax: Decentralized Trust Layer for AI Agent Skills

> *φύλαξ, Ancient Greek for guardian, sentinel, watchman.*

[![Bittensor](https://img.shields.io/badge/Bittensor-Subnet-blue)](https://bittensor.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Status: Pre-launch](https://img.shields.io/badge/Status-Pre--launch-orange)]()

Phylax is a Bittensor subnet that turns untrusted AI agent skill bundles into Signed Skill Safety Attestations (SSSAs): portable, verifiable, cryptographically-signed artifacts with enforceable execution policies.

## The Problem

Agent ecosystems scale through composable skills. The same extensibility creates a large attack surface: a malicious skill can steal API keys, exfiltrate data, establish persistence, or hijack agent behaviour through prompt injection.

Existing approaches use an LLM as the scanner. They are fast to build but fundamentally limited: the model itself is prompt-injectable, evasion via obfuscation is trivial without real execution, and the output is plain text rather than an enforceable contract.

## The Phylax Approach

Phylax runs a decentralized competition in which miners perform real behavioural sandbox detonation, produce cryptographically-signed evidence packs, and emit machine-readable policies that runtimes can enforce automatically. Validators independently verify submissions through multi-miner consensus and async sandbox reruns. Claims without matching evidence earn zero.

| | Traditional Scanners | Phylax |
|---|---|---|
| Analysis method | LLM text analysis | Real sandbox detonation |
| Evasion resistance | Low (prompt-injectable) | High (behavioural observation) |
| Output | Text report | Signed, enforceable contract |
| Verification | None | Multi-miner consensus + validator sandbox rerun |
| Scale | Centralized | Decentralized competition |
| Incentive | None | Bittensor TAO emissions |

## Skill Types

Phylax supports six skill types, each with its own analysis pipeline and scoring. Miners choose which types to specialise in.

| Skill type | What it covers |
|---|---|
| `rag_knowledge` | Document collections and knowledge-base content |
| `declarative` | Natural-language instruction files (SKILL.md) |
| `executable_python` | Python source code and dependency manifests |
| `executable_script` | Shell scripts and bash files |
| `mcp_server` | Model Context Protocol server implementations |
| `agent_composition` | Skills that orchestrate other skills or spawn sub-agents |

Harder skill types carry higher base weights and earn proportionally more emissions. Miners who invest in deeper analysis pipelines reach higher tiers and earn more than those running the reference implementation.

## How it Works

Each skill bundle passes through a miner analysis pipeline before producing a signed attestation.

**Layer 1: Static Analysis.** Scans code structure, dangerous API patterns, permission discrepancies, and prompt-injection patterns using AST analysis, regex banks, and taint flow tracking.

**Layer 2: Supply Chain and SBOM.** Generates a full dependency graph, cross-references the [osv.dev](https://osv.dev) CVE database, detects typosquatting, and flags malicious install hooks.

**Layer 3: Behavioural Sandbox.** Executes the skill in a locked container seeded by a per-task nonce. Records network egress, filesystem access, process spawning, and secrets access. For MCP server skills a dedicated test client exercises all declared tools. For composition skills a cascading multi-container detonation traces inter-skill communication.

Validators verify submissions by checking trace hashes for self-consistency and canary presence, computing full SSSA consensus across a five-miner verification group, and asynchronously rerunning each primary miner's declared sandbox image to confirm their traces are honest.

## The Signed Skill Safety Attestation (SSSA)

```text
skill:                { name, bundle_hash, skill_type, profile }
verdict:              ALLOW | WARN | BLOCK
risk_score:           0 - 100
capabilities:         { network, filesystem, process, secrets,
                        tool_calls, child_skills }
findings:             [ { severity, evidence_snippet, owasp_ref,
                          mitre_ref, layer_source } ]
dependencies:         { sbom_hash, known_cves, install_hooks }
recommended_policy:   { enforceable JSON }
evidence:             { sha256 hashes of sandbox traces,
                        type-specific evidence fields }
attestation:          ed25519:miner_hotkey
```

Full schema reference: [docs/sssa_schema.md](docs/sssa_schema.md).

## Scoring

Each submission is scored across multiple axes that vary by skill type. Detection accuracy is the dominant signal. Evidence is a multiplicative gate. A miner who cannot prove they ran real analysis earns zero regardless of how good their verdict looks.

On top of per-task scoring, submissions are evaluated against a five-miner verification group. Each miner's score is multiplied by their consensus alignment across verdict, findings, capabilities, dependencies, and recommended policy. A miner who diverges from the group on findings earns less even if their individual axes score well.

Full scoring specification: [docs/scoring.md](docs/scoring.md).

## Anti-Gaming

Phylax layers multiple mechanisms to make gaming more expensive than honest mining.

Submitting without running the sandbox fails the evidence gate immediately. Fabricating trace hashes fails against the canary written by the validator's nonce before execution. Copying another miner's submission fails because every miner receives a unique nonce that produces unique trace hashes. Colluding with a fixed group of miners fails because each task also includes randomly selected auditor miners whose verdicts the colluding group cannot predict.

## Architecture

Key packages:

- `phylax.validator.consensus` full SSSA consensus across the verification group
- `phylax.validator.rerun` async miner sandbox image rerun worker
- `phylax.validator.collusion` per-miner consensus agreement history and collusion detection
- `phylax.validator.corpus` corpus task fetching and canary injection
- `phylax.api.server` POST /scan, GET /attestation, /verify, /health
- `phylax.client` and `phylax.cli` runtime SDK and CI gate

Full module map: [docs/architecture.md](docs/architecture.md).

## Getting Started

```bash
git clone https://github.com/praxi-labs/phylax-subnet.git
cd phylax-subnet
pip install -e .
docker build -f docker/Dockerfile.sandbox -t phylax-sandbox:latest .
```

- [Miner setup](docs/miner_setup.md)
- [Validator setup](docs/validator_setup.md)
- [REST API](docs/api.md)
- [Runtime integration](docs/integration.md)
