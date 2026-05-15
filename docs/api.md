# Phylax REST API

The validator exposes `phylax.api.server` (FastAPI) on `PHYLAX_API_PORT` (default 8080).

## POST `/v1/scan`

Submit a bundle for attestation. Returns the cached consensus SSSA if one exists, or a freshly produced single-party attestation from the validator's BaselineRunner if not.

Request body:

```json
{
  "bundle_url": "https://...",
  "bundle_bytes": "<base64>",
  "metadata": { "name": "...", "version": "...", "permissions": ["..."] },
  "test_profile": "fast | standard | deep"
}
```

Either `bundle_url` or `bundle_bytes` (base64) must be present.

Response body:

```json
{
  "attestation": { ... canonical SSSA ... },
  "evidence_refs": { "N": "sha256:...", "F": "...", "P": "...", "K": "..." },
  "from_cache": true
}
```

## GET `/v1/attestation/{bundle_hash}`

Lookup by content address. Returns the cached consensus SSSA, or 404 if none exists / it was invalidated.

## POST `/v1/attestation/verify`

Server-side verification of any SSSA payload. Useful for runtimes that don't want to ship the verifier code.

Response:

```json
{
  "ok": true,
  "reason": null,
  "miner_signature_ok": true,
  "validator_signature_ok": true,
  "bundle_hash_ok": true,
  "sbom_hash_ok": true,
  "fresh": true
}
```

## POST `/v1/attestation/{bundle_hash}/invalidate`

Drift-detection hook (whitepaper §6.4). Marks the attestation as invalid; subsequent GETs will return 404 until a fresh consensus is produced.

Request body:

```json
{ "reason": "CVE-2026-1234 affects bundled dependency X", "token": "<admin_token>" }
```

The token must match `PHYLAX_API_ADMIN_TOKEN`.

## GET `/v1/health`

Liveness + registry stats:

```json
{
  "ok": true,
  "schema_version": "1.1.0",
  "registry": { "total": 1234, "active": 1190, "block": 220, "warn": 180, "allow": 790 }
}
```

## Running standalone

```bash
PHYLAX_REGISTRY_PATH=/var/lib/phylax/registry.sqlite3 \
PHYLAX_API_HOST=0.0.0.0 \
PHYLAX_API_PORT=8080 \
python -m phylax.api.server
```

When deployed alongside a Phylax validator, point both processes at the same `PHYLAX_REGISTRY_PATH` so the API serves the consensus attestations the validator publishes.
