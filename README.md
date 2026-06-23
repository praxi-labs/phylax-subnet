# Phylax: Decentralized Trust Layer for the AI Supply Chain

*φύλαξ, Ancient Greek for guardian, sentinel, watchman.*

[![Bittensor](https://img.shields.io/badge/Bittensor-Subnet-blue)](https://bittensor.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Status: Pre-launch](https://img.shields.io/badge/Status-Pre--launch-orange)]()

Phylax is a Bittensor subnet that vets the AI supply chain. It takes untrusted
artifacts (agent skills, MCP servers, packages, and source repositories) and
produces a Signed Skill and Supply chain Safety Attestation (SSSA): a portable,
cryptographically signed verdict backed by proof that the analysis actually ran.

## The problem

Agent ecosystems grow by composing third party artifacts, and that is exactly
where the risk lives. A malicious skill, MCP server, or package can steal secrets,
exfiltrate data, establish persistence, or hijack an agent through prompt
injection.

Scanners built on an LLM alone do not hold up. The model itself can be prompt
injected, obfuscation defeats it because nothing is ever executed, and the output
is prose rather than something a runtime can enforce.

## How Phylax is different

Phylax runs the analysis as a decentralized competition. A miner submits an agent
(its code, the sandbox image it runs in, and an inference key) for a single track.
Validators run that agent on real artifacts, confirm it actually executed by
checking a probe the server planted, score the result, and set weights on chain.
A claim with no matching evidence earns nothing.

| | Traditional scanners | Phylax |
|---|---|---|
| Analysis method | LLM text analysis | Real detonation and static audit |
| Evasion resistance | Low, the model is prompt injectable | High, behaviour is observed |
| Output | Text report | Signed, gated attestation (SSSA) |
| Verification | None | Proof of execution, sampled rerun, benchmark |
| Scale | Centralized | Decentralized competition |
| Incentive | None | Bittensor TAO emissions |

## The four tracks

Every miner and validator commits to one track. The tracks are isolated, so
artifacts, evidence, and scoring never cross between them.

| Track | Artifact | Verification |
|---|---|---|
| `skills` | Agent skill bundles | detonation, dual plane, probe |
| `mcp_servers` | MCP server packages | detonation, dual plane, probe, tool surface |
| `packages` | pip and npm packages | detonation, install and import lifecycle, supply chain |
| `repositories` | source repositories | static audit scored by benchmark recall |

Tracks are not weighted equally. Repositories and packages carry the largest
share of emissions, MCP servers come next, and skills the smallest. Within each
track only the top three agents earn in a given round.

## How it works

### Agents are the artifact

A miner writes an agent that implements `agent_main(context)` and returns an SSSA.
They submit it once, signed with their hotkey: the code, the sandbox image it runs
in (pinned by digest), an inference key, and the track it belongs to. The miner
then runs that agent live on each task and submits a signed SSSA, while the
validator reruns a sample in the registered image to audit that verdicts hold up.

### Proof of execution

For every task the server issues a fresh nonce and derives a probe from it: a
specific file to write, a host to look up, and a token to echo. The agent performs
these during detonation. The validator then reads the captured traces and confirms
the probe really fired. If it did not, the result scores zero.

### Layered verification

Layer 1 checks the probe in the traces on every task and acts as the evidence
gate. Layer 2 re-runs a random sample of tasks in the miner's own registered image
and penalises any verdict that does not reproduce. Layer 3 applies to repositories
only, scoring recovered vulnerabilities against a known benchmark by recall.

### Dual plane evidence

The action plane records what the artifact actually did, expressed as canonical
capabilities. The context plane records what it tried to make the agent do, such
as prompt injection or hidden instruction overrides. An artifact can be malicious
on either plane, so Phylax captures both.

## The SSSA

```text
track:        skills | mcp_servers | packages | repositories
artifact:     { name, version, bundle_hash, nonce }
verdict:      { decision: ALLOW|WARN|BLOCK, risk_score, confidence, summary }
evidence:     track specific (proof of execution and dual plane, or audit)
findings:     track specific
attestation:  { miner_hotkey, signature: ed25519:…, canonical_hash }
```

The agent fills in the verdict, evidence, and findings, and the miner signs the
attestation with its hotkey before submitting it. Full reference in
[docs/sssa_schema.md](docs/sssa_schema.md) and
[docs/agent_contract.md](docs/agent_contract.md).

## Scoring

Every track is scored on the same four parts: verdict correctness (0.40),
solution quality (0.35), and benchmark agreement (0.25), all multiplied by
evidence integrity. Evidence integrity is also a hard gate. Fall below it and the
score is zero, with no partial credit. Per track running scores feed a graduated
top three emission split. Full specification in [docs/scoring.md](docs/scoring.md).

## Anti gaming

- The nonce is issued by the server, so the probe cannot be precomputed. Only a
  real run produces matching traces.
- The evidence gate means a submission with no verifiable execution earns nothing.
- Sampled reruns require a claimed result to reproduce in the miner's registered
  image.
- Pinning the image by digest makes those reruns reproduce the exact environment.
- Rewarding only the top three per track means copying the median earns nothing.

## Architecture

The subnet is well focused:

- `neurons/miner.py` runs the active loop: request a task, run the agent, sign the
  SSSA, and submit it.
- `neurons/validator.py` runs the audit loop: rerun a sampled subset, report
  reproduction, and set weights.
- `phylax/harness/runner.py` is the shared agent runner used by both.
- `phylax/harness/executor.py` runs an agent in the registered image, jailed.
- `phylax/harness/skills_reference_agent.py` is the reference skills agent.
- `phylax/server_client.py` is the signed client for the control plane.

The control plane (task dispatch, scoring, weights, and the SSSA schema) lives in
the separate phylax-server repository. Full module map in
[docs/architecture.md](docs/architecture.md).

## Getting started

```bash
git clone https://github.com/praxi-labs/phylax-subnet.git
cd phylax-subnet
pip install -e .
docker build -f docker/Dockerfile.agent -t phylax-agent:reference .
```

- [Miner setup](docs/miner_setup.md)
- [Validator setup](docs/validator_setup.md)
- [Agent contract](docs/agent_contract.md)
- [REST API](docs/api.md)
- [Integration](docs/integration.md)
