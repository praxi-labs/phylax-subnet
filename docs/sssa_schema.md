# SSSA schema

The Signed Skill and Supply chain Safety Attestation records a verdict, the
evidence behind it, and the parties who produced it.

## Envelope

```json
{
  "track": "skills | mcp_servers | packages | repositories",
  "artifact": { "bundle_hash": "…", "nonce": "…" },
  "verdict":  { "decision": "ALLOW | WARN | BLOCK", "risk_score": 0, "confidence": 0.0, "summary": "" },
  "evidence": { },
  "findings": [ ],
  "policy": { },
  "attestation": {
    "agent_hash": "sha256:…",
    "miner_hotkey": "…",
    "validator_hotkey": "…",
    "signature": "ed25519:…",
    "canonical_hash": "sha256:…"
  }
}
```

## Two signatures

At submission time the miner signs the submission digest (track, code hash,
entrypoint, image pin), binding `agent_hash` to `miner_hotkey`. At evaluation
time the validator that executed the run assembles the SSSA and signs its
canonical hash. Attribution flows through the agent hash; authenticity of the run
flows through the validator's signature.

## Canonicalisation

The signed content is the SSSA minus the attestation block, including the
recommended policy: NFC normalised, key sorted, whitespace free JSON, hashed
with SHA-256
(`phylax/utils/hashing.py`). Anyone recomputes the hash and verifies the
signature against the validator's on chain hotkey, offline.

## Evidence per track

- **skills** — `proof_of_execution` (probe evidence + hashed filesystem,
  network, and process traces), `action_plane.capabilities` (canonical taxonomy),
  `context_plane.injected_instructions`.
- **mcp_servers** — the dual plane core plus `mcp_surface`: exposed tools with
  declared versus observed schema, manifest integrity, tool poisoning, cross
  component influence.
- **packages** — the proof of execution plus `lifecycle` (install time and
  import time) and `supply_chain` (SBOM, dependency CVEs, typosquat, dependency
  confusion).
- **repositories** — `audit` (files and lines analysed) plus `vulnerabilities`
  (CWE, file, line, severity, remediation). No probe, no dual plane.

## Findings

```json
{ "category": "…", "severity": "LOW | MED | HIGH | CRIT",
  "plane": "action | context | protocol", "title": "…", "evidence_ref": "…" }
```

Categories per track: skills use `instruction_injection`,
`permission_overreach`, `transitive_poisoning`, `transitive_leakage`,
`context_injection`, `rug_pull`; mcp_servers add `tool_poisoning`,
`manifest_tamper`, `tool_shadow`, `schema_mismatch`; package findings carry an
install, import, or runtime phase; repository findings are the vulnerabilities
list.
