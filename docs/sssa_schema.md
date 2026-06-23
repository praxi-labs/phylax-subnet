# SSSA Schema Reference

The **Signed Skill/Supply-chain Safety Attestation** is what an agent returns for
each task and what the miner signs and submits. It is one shared envelope with a
track-specific `evidence` block and `findings` list. The canonical models live in
`phylax-server/phylax_server/schemas.py`.

## Envelope (every track)

```json
{
  "track": "skills | mcp_servers | packages | repositories",
  "artifact": { "name": "", "version": "", "bundle_hash": "sha256:…", "nonce": "" },
  "verdict":  { "decision": "ALLOW | WARN | BLOCK", "risk_score": 0, "confidence": 0.0, "summary": "" },
  "evidence": { /* track-specific, see below */ },
  "findings": [ /* track-specific */ ],
  "attestation": { "miner_hotkey": "", "signature": "ed25519:…", "canonical_hash": "sha256:…" }
}
```

- `verdict.decision`: `ALLOW`/`WARN`/`BLOCK`. `risk_score` 0-100, `confidence` 0-1.
- `attestation.miner_hotkey` identifies whose agent ran. The **miner signs** the
  SSSA with that hotkey before returning it to the validator, so the signature binds
  the result to the miner who produced it. The validator verifies the
  proof-of-execution and reruns a sample to confirm the verdict holds.

The agent fills `verdict`, `evidence`, and `findings`, and the miner signs the
envelope with its hotkey.

## `evidence` (skills)

```json
{
  "proof_of_execution": {
    "probe_evidence": { "file_write": "/skill/.probe_…", "dns_lookup": "….probe.phylax.ai",
                        "process_echo": "…", "canary": "…" },
    "traces": {
      "filesystem": { "hash": "", "events": [ { "path": "…", "op": "write" } ] },
      "network":    { "hash": "", "events": [ { "domain": "…", "proto": "dns" } ] },
      "process":    { "hash": "", "events": [ { "cmd": "echo", "args": ["…"] } ] }
    }
  },
  "action_plane":  { "capabilities": [ { "capability": "POST_WEB", "group": "network",
                                         "protection": "dangerous", "evidence_ref": "" } ] },
  "context_plane": { "injected_instructions": [ { "type": "instruction_injection",
                                                  "excerpt": "…", "location": "skill_text" } ],
                     "loaded_context": [] },
  "capability_manifest": ["POST_WEB", "READ_ENV_SECRETS"]
}
```

`findings[]`: `{ category, severity, plane, title, evidence_ref }` where
`category ∈ {instruction_injection, permission_overreach, transitive_poisoning,
transitive_leakage, context_injection, rug_pull}` and `plane ∈ {action, context}`.

## `evidence` (mcp_servers)

Same `proof_of_execution` + `action_plane` + `context_plane` as skills, plus:

```json
{
  "mcp_surface": {
    "exposed_tools": [ { "name": "…", "declared_schema": {}, "observed_behavior": "",
                         "schema_mismatch": false } ],
    "manifest_integrity": { "tampered": false, "detail": "" },
    "tool_poisoning": [ { "tool": "…", "type": "…", "evidence_ref": "" } ]
  }
}
```

`findings[]` add `category ∈ {tool_poisoning, manifest_tamper, tool_shadow,
schema_mismatch, context_injection, overreach}`; `plane` may be `protocol`; an
optional `tool` field names the offending tool.

## `evidence` (packages)

```json
{
  "proof_of_execution": { /* as above */ },
  "lifecycle": {
    "install_time": { "hook_executed": false, "side_effects": false, "capabilities": [], "evidence_ref": "" },
    "import_time":  { "hook_executed": false, "side_effects": false, "capabilities": [], "evidence_ref": "" }
  },
  "action_plane": { "capabilities": [] },
  "supply_chain": {
    "sbom_hash": "", "dependencies": [ { "name": "…", "version": "…", "cve": [] } ],
    "typosquat": {}, "dependency_confusion": false, "maintainer_signal": ""
  },
  "capability_manifest": []
}
```

`findings[]`: `category ∈ {install_hook_exec, import_side_effect, typosquat,
dependency_confusion, dependency_cve, credential_theft, crypto_wallet_access}`,
with an optional `phase ∈ {install, import, runtime}`.

## `evidence` (repositories)

The outlier: **no probe, no detonation, no dual plane.** Static audit only.

```json
{
  "audit": { "files_analysed": 0, "lines_analysed": 0, "coverage": "", "method": "" },
  "vulnerabilities": [
    { "id": "", "title": "…", "severity": "HIGH", "cwe": "CWE-89",
      "file": "…", "line": "…", "description": "…", "remediation": "…" }
  ]
}
```

`findings` for this track are the `vulnerabilities`. Scored by recall against the
benchmark's known vulnerabilities.

## Evidence requirements per track

| Block | skills | mcp_servers | packages | repositories |
|---|---|---|---|---|
| `proof_of_execution` | required | required | required | n/a |
| `action_plane` | required | required | required | n/a |
| `context_plane` | required | required | minor | n/a |
| track-specific | n/a | `mcp_surface` | `lifecycle` + `supply_chain` | `audit` |
| `vulnerabilities` | n/a | n/a | n/a | required |
| evidence gate | dual-plane + probe | dual-plane + probe | dual-plane + probe | benchmark recall |

## Canonical hash and signing

The miner computes `canonical_hash` over the canonical JSON of
`{track, bundle_hash, nonce, verdict, evidence}` (sorted keys, no whitespace),
then sets `attestation.signature = "ed25519:" + sign(sha256(canonical_body))`
with the miner hotkey. The validator verifies the signature and the probe before
scoring it.
