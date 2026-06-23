# Label Schema

Every artifact in every track has a `label.json` file beside it. This file is the
ground truth the validator scores a miner's SSSA against. This document defines the
shared fields. Track-specific fields are described in each track's `README.md`.

## Shared fields (all tracks)

```json
{
  "artifact_id": "skills/known-bad/credential-stealer",
  "track": "skills | mcp_servers | packages | repositories",
  "ground_truth": {
    "verdict": "ALLOW | WARN | BLOCK",
    "risk_score": 0,
    "classification": "safe | warning | dangerous"
  },
  "expected_findings": [],
  "expected_capabilities": [],
  "source": {
    "origin": "synthetic | registry | github | audit-contest",
    "url": "optional source URL",
    "collected_at": "2026-06-01"
  },
  "notes": "human-readable explanation of why this is the ground truth"
}
```

### Field meanings

- **artifact_id**: the path of the artifact under `corpora/`, used as a stable identifier.
- **track**: which track this artifact belongs to. Determines how it is scored.
- **ground_truth.verdict**: the correct verdict. ALLOW for safe, BLOCK for dangerous,
  WARN for borderline.
- **ground_truth.risk_score**: the reference risk score in [0, 100].
- **ground_truth.classification**: safe, warning, or dangerous.
- **expected_findings**: the findings a correct agent should recover. The *shape* of
  each finding is track-specific (see below).
- **expected_capabilities**: the canonical capabilities a correct agent should observe.
  Used by the three detonation tracks only; omitted for repositories.
- **source**: provenance of the artifact, so the corpus is auditable.
- **notes**: a plain-language explanation of the ground truth, for human reviewers.

## Track-specific shapes

### Detonation tracks (skills, mcp_servers, packages)

`expected_capabilities` entries use the canonical capability taxonomy:

```json
{ "capability": "READ_SECRET", "group": "Secrets and Credentials", "protection": "redact" }
```

`expected_findings` entries carry a `plane` (action or context), because these tracks
use the dual-plane model:

```json
{ "category": "instruction_injection", "severity": "HIGH", "plane": "context",
  "title": "...", "evidence_ref": "SKILL.md" }
```

Each detonation track adds its own block to the label where useful:
- skills: findings span both planes.
- mcp_servers: add an `mcp_surface` block (tool poisoning, manifest integrity).
- packages: add a `lifecycle` block (install/import) and a `supply_chain` block.

### Audit track (repositories)

No `expected_capabilities`. `expected_findings` are recovered vulnerabilities, scored by
recall:

```json
{ "category": "vulnerability", "severity": "HIGH", "cwe": "CWE-89",
  "file": "src/db.py", "line": 7, "title": "...", "remediation": "..." }
```

## The invariant

The label format for a track must match that track's SSSA evidence schema, because the
label is what the SSSA is scored against. If you change a track's evidence schema, change
its label format in the same commit.
