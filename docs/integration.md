# Runtime Integration Guide

How to consume Signed Skill Safety Attestations (SSSAs) from your agent runtime, marketplace, or CI pipeline.

## Why integrate

An SSSA gives you, for any skill bundle:

1. A pass/warn/block verdict
2. A risk score 0–100
3. A capability map (what the skill *actually* accesses)
4. A machine-readable policy you can enforce
5. Cryptographic proof of the producing miner — and optionally a validator countersignature

Use it as a precondition to skill execution. Treat unsigned or expired SSSAs as untrusted.

## REST API

The validator exposes a small REST surface via `phylax.api.server` (default `http://localhost:8080`).

| Verb | Path | Purpose |
|---|---|---|
| GET  | `/v1/health` | Liveness + registry stats |
| POST | `/v1/scan` | Submit a bundle; returns cached or freshly-attested SSSA |
| GET  | `/v1/attestation/{bundle_hash}` | Look up a cached consensus attestation |
| POST | `/v1/attestation/verify` | Server-side verification of an SSSA payload |
| POST | `/v1/attestation/{bundle_hash}/invalidate` | Mark an attestation invalid (admin token required) |

The full request/response shapes are documented in [`docs/api.md`](api.md).

## Python quickstart

```python
from phylax.client import fetch_and_verify, PolicyEnforcer

with open("./dist/skill.zip", "rb") as f:
    bundle = f.read()

sssa, result = fetch_and_verify(
    bundle,
    base_url="https://api.phylax.local",
    require_countersignature=True,
    max_age_seconds=86_400,
)

if not result.ok:
    raise RuntimeError(f"Phylax verification failed: {result.reason}")

enforcer = PolicyEnforcer(sssa)
if enforcer.must_block():
    raise RuntimeError(f"Phylax BLOCKED: {sssa.verdict.summary}")

sandbox.configure(**enforcer.sandbox_config())
```

## CLI gate (CI pipelines)

```yaml
- name: Phylax safety gate
  run: |
    phylax check ./dist/skill.zip \
        --api https://api.phylax.local \
        --max-risk 30 \
        --require ALLOW \
        --require-countersignature
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | OK |
| 2 | Bundle path not found |
| 3 | Signature / verification failed |
| 4 | Verdict didn't match `--require` |
| 5 | Risk score above `--max-risk` |

## Verification (whitepaper §9.1)

`fetch_and_verify` performs the five checks:

1. Local bundle hash equals `sssa.skill.bundle_hash`.
2. Miner ed25519 signature is valid for `sssa.attestation.miner_hotkey`.
3. (Optional) validator countersignature is valid for the same canonical body + round_id.
4. Local SBOM hash equals `sssa.skill.sbom_hash` when both are available.
5. Timestamp is within `max_age_seconds` of now.

Use `phylax verify` for offline verification of a saved attestation JSON.

## Marketplace integration

Marketplaces should:

1. Require every uploaded skill to carry a fresh SSSA with `ALLOW` or `WARN`.
2. Display the verdict, top reasons, and capability surface next to the listing.
3. Hide skills with `BLOCK` verdicts from search.
4. Refuse to publish skills whose declared capabilities exceed those observed in the attestation.

## Cache + staleness

- Cache by `bundle_hash` indefinitely; the hash changes when the bundle changes.
- Re-attest on:
  - `schema_version` change in `run_metadata.tools`.
  - Drift events (CVE feeds, publisher compromise) — the registry will mark the entry invalid; the API returns 404 and `/scan` produces a fresh attestation.

## Reporting issues

If you find an SSSA that's clearly wrong (false positive or false negative), open an issue tagged `triage/sssa` with the `bundle_hash` and the miner hotkey. The validator corpora and ground-truth pipeline are the source of truth — bug reports against attestations get traced back to which family / heuristic produced the wrong call.
