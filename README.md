# Phylax — Decentralized Trust Layer for AI Agent Skills

> *Phylax (φύλαξ): Ancient Greek for guardian, sentinel, watchman.*

[![Bittensor](https://img.shields.io/badge/Bittensor-Subnet-blue)](https://bittensor.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Status: Pre-launch](https://img.shields.io/badge/Status-Pre--launch-orange)]()

**Phylax is a Bittensor subnet that transforms untrusted AI agent skill bundles into Signed Skill Safety Attestations (SSSAs) — portable, verifiable, cryptographically-signed artifacts with enforceable execution policies.**

Think: VirusTotal × supply-chain scanner × Bittensor incentives — but purpose-built for agent skills.

---

## Why Phylax?

Agent ecosystems scale through composable skills. That same extensibility creates a massive attack surface. A malicious skill can steal API keys, exfiltrate data, establish persistence, or hijack agent behavior via prompt injection.

**The existing approach** (e.g. LLMSecurity/skillguard): use an LLM as the scanner, produce a text report. Fast to build. But:
- The LLM IS the vulnerability surface — it can be prompt-injected itself
- No actual execution, so evasion is trivial (obfuscated code, delayed triggers)
- Output is a text report, not an enforceable contract
- Centralized and unscalable

**The Phylax approach**: decentralized competition where miners run real behavioral sandbox detonation, produce cryptographically-signed evidence packs, and output machine-readable policies that runtimes can enforce automatically. Claims without evidence earn zero emissions.

| Feature | LLM-based scanners | Phylax |
|---|---|---|
| Analysis method | LLM text analysis | Real sandbox detonation |
| Evasion resistance | Low (prompt-injectable) | High (behavioral observation) |
| Output | Text report | Signed, enforceable contract |
| Verification | None | Content-addressed evidence hashes |
| Scale | Centralized | Decentralized competition |
| Incentive | None | Bittensor TAO emissions |

---

## Architecture

```
Skill Bundle (code + deps + metadata)
         │
         ▼
┌─────────────────────────────────────────────────┐
│              PHYLAX MINER PIPELINE              │
│                                                 │
│  Layer 1: Static Analysis                       │
│  ├── Dangerous API patterns                     │
│  ├── Permission surface scan                    │
│  └── Code structure analysis                    │
│                                                 │
│  Layer 2: Supply-Chain / SBOM                   │
│  ├── Dependency graph generation                │
│  ├── CVE database lookup                        │
│  ├── Typosquatting detection                    │
│  └── Malicious install hook detection           │
│                                                 │
│  Layer 3: Behavioral Sandbox Detonation         │
│  ├── Locked container execution                 │
│  ├── Network egress monitoring                  │
│  ├── Filesystem access tracing                  │
│  ├── Process spawning observation               │
│  └── Secrets/env access detection               │
└─────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│       SIGNED SKILL SAFETY ATTESTATION (SSSA)    │
│                                                 │
│  verdict:  ALLOW | WARN | BLOCK                 │
│  risk_score: 0–100                              │
│  capabilities: { network, fs, process, secrets }│
│  findings: [ { severity, evidence, fix } ]      │
│  recommended_policy: { enforceable JSON }       │
│  evidence: { hashed logs, traces, pcap }        │
│  signature: ed25519:miner_hotkey                │
└─────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│            VALIDATOR SCORING ENGINE             │
│                                                 │
│  Detection Accuracy   45% weight                │
│  Evidence Integrity   25% weight                │
│  Policy Effectiveness 20% weight                │
│  Efficiency           10% weight                │
│                                                 │
│  Score = weighted harmonic mean                 │
│  → set_weights() on Bittensor chain             │
└─────────────────────────────────────────────────┘
```

---

## Quickstart

### Prerequisites

- Python 3.10+
- Docker 24+
- `btcli` installed ([install guide](https://docs.bittensor.com/getting-started/install-btcli))
- Git

```bash
git clone https://github.com/your-org/phylax-subnet.git
cd phylax-subnet
pip install -e .
```

---

## Running a Miner

### Step 1: Create your wallet

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
```

### Step 2: Register on testnet

```bash
# Get testnet TAO from Bittensor Discord (#faucet channel)
btcli subnet register \
  --netuid <PHYLAX_NETUID> \
  --subtensor.network test \
  --wallet.name miner \
  --wallet.hotkey default
```

### Step 3: Configure

```bash
cp .env.example .env
# Edit .env: set your wallet paths, netuid, subtensor endpoint
```

### Step 4: Build the sandbox container

```bash
docker build -f docker/Dockerfile.sandbox -t phylax-sandbox:latest .
```

### Step 5: Run

```bash
python neurons/miner.py \
  --netuid <PHYLAX_NETUID> \
  --subtensor.network test \
  --wallet.name miner \
  --wallet.hotkey default \
  --axon.port 8091 \
  --logging.debug
```

See [docs/miner_setup.md](docs/miner_setup.md) for the full guide.

---

## Running a Validator

### Step 1: Create your wallet

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
```

### Step 2: Register and stake

```bash
btcli subnet register \
  --netuid <PHYLAX_NETUID> \
  --subtensor.network test \
  --wallet.name validator \
  --wallet.hotkey default

# Stake TAO to get validator permit (top 64 by stake)
btcli stake add \
  --wallet.name validator \
  --wallet.hotkey default \
  --amount 1000
```

### Step 3: Run

```bash
python neurons/validator.py \
  --netuid <PHYLAX_NETUID> \
  --subtensor.network test \
  --wallet.name validator \
  --wallet.hotkey default \
  --logging.debug
```

See [docs/validator_setup.md](docs/validator_setup.md) for the full guide.

---

## The Signed Skill Safety Attestation (SSSA)

The SSSA is the commodity produced by this subnet. See
[docs/sssa_schema.md](docs/sssa_schema.md) for the full field reference.

---

## Scoring

Miners are evaluated on four axes per epoch. See [docs/scoring.md](docs/scoring.md) for full details.

| Axis | Weight | What it measures | Gaming failure mode punished |
|---|---|---|---|
| Detection accuracy | 45% | Correct ALLOW/WARN/BLOCK decision + risk score | Over-blocking or blanket allow-all |
| Evidence integrity | 25% | Findings backed by verifiable traces | Missing hashes, fabricated evidence |
| Policy effectiveness | 20% | Policy reduces risk without overreach | Useless or "deny everything" policy |
| Efficiency | 10% | Latency + resource cost | Extremely slow or heavy scans |

**Score formula:**
```
TS = harmonic_mean(
    0.45 * S_detection,
    0.25 * S_evidence,
    0.20 * S_policy,
    0.10 * S_efficiency
)
```

The harmonic mean **punishes weak axes severely** — a miner with 100% detection but 0% evidence integrity scores near zero.

---

## Anti-Gaming Design

Phylax is designed assuming miners will attempt to game benchmarks.

- **Canary skills**: Hidden skills with behaviors triggered only under specific conditions. Not in the public corpora.
- **Near-miss benign samples**: Safe code that looks scary. Miners who over-block are penalized.
- **Adversarial variants**: Obfuscated malware, delayed triggers, prompt-activated branches.
- **Consensus cross-checking**: Miner outputs on the same input are compared. Outliers are reviewed.
- **Evidence-gated scoring**: A miner cannot earn evidence score by making claims. Hashes must match replayed detonation.

---

## Integration (For Runtimes & Marketplaces)

See [docs/integration.md](docs/integration.md) for the full runtime integration guide.

---

## Project Structure

```
phylax-subnet/
├── neurons/
│   ├── miner.py
│   └── validator.py
├── phylax/                       # Core package
│   ├── protocol.py               # PhylaxSynapse + SSSA schema
│   ├── pipeline/{static,sbom,sandbox}.py
│   ├── attestation/{schema,signer}.py
│   ├── scoring/{rewards,metrics}.py
│   ├── policy/generator.py
│   └── utils/{hashing,logging}.py
├── corpora/                      # Validator task datasets
│   ├── schema.json
│   ├── known_bad/  known_good/  near_miss/  adversarial/
├── docker/
│   ├── Dockerfile.miner
│   ├── Dockerfile.sandbox
│   ├── docker-compose.yml
│   └── harness/run.py
├── tests/
├── scripts/{register_testnet,run_local}.sh
└── docs/
```

---

## Roadmap

### Phase 1 — MVP (Static + SBOM)
- [x] Canonical SSSA schema
- [x] Miner/validator template
- [ ] Static analysis pipeline (bandit, semgrep)
- [ ] SBOM generation (syft, cyclonedx)
- [ ] Initial corpora (50 known-bad, 50 known-good)
- [ ] Testnet deployment

### Phase 2 — Behavioral Detonation
- [ ] Docker sandbox with eBPF instrumentation
- [ ] Network egress capture (pcap)
- [ ] Filesystem access tracing
- [ ] Evidence replay for validators
- [ ] Adversarial corpora expansion

### Phase 3 — Trust Graph
- [ ] Publisher reputation scoring
- [ ] Version drift detection
- [ ] Transparency log integration
- [ ] Mainnet launch

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE)

---

## Disclaimer

Phylax reduces risk but cannot guarantee detection of all threats, especially novel evasion techniques. Always supplement automated scanning with human review for high-stakes systems.
