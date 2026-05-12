# SSSA Schema Reference

Field-by-field reference for the Signed Skill Safety Attestation.

The canonical schema is defined in [`phylax/protocol.py`](../phylax/protocol.py).
This document is the human-readable counterpart.

## Top-level

| Field | Type | Required | Notes |
|---|---|---|---|
| `skill` | object | yes | Identifies the bundle |
| `verdict` | object | yes | The miner's decision |
| `capabilities` | object | yes | Observed runtime capabilities |
| `findings` | array | no | Individual issues detected |
| `dependencies` | object | no | SBOM + supply-chain results |
| `recommended_policy` | object | no | Enforceable runtime policy |
| `evidence` | object | no | Content-addressed evidence hashes |
| `run_metadata` | object | no | Tooling versions + timing |
| `attestation` | object | yes (signed) | Hotkey + signature |

## `skill`

| Field | Type | Notes |
|---|---|---|
| `name` | string | From manifest, or `"unknown"` |
| `version` | string | From manifest, or `"unknown"` |
| `bundle_hash` | string | `sha256:<64 hex>` — primary identifier |
| `sbom_hash` | string? | `sha256:<hex>` of generated SBOM |
| `entrypoints` | string[] | Discovered entry points |
| `declared_permissions` | string[] | Permissions claimed by author |

## `verdict`

| Field | Type | Notes |
|---|---|---|
| `decision` | enum | `ALLOW` \| `WARN` \| `BLOCK` |
| `risk_score` | int 0–100 | Higher = riskier |
| `confidence` | float 0–1 | Miner's self-reported confidence |
| `summary` | string | One-paragraph human summary |
| `top_reasons` | string[] | Up to 3 short bullets |

## `capabilities`

Four nested groups. Empty groups indicate "no observed capability of
this kind".

### `capabilities.filesystem`
`reads[]`, `writes[]`, `deletes[]` — absolute or repo-relative paths.

### `capabilities.network`
- `egress: bool` — did the skill open any outbound connection?
- `observed_domains[]` — domains contacted
- `observed_ips[]` — IPs contacted (for direct-IP traffic)
- `allowlist_suggestion[]` / `denylist_suggestion[]` — miner's curated picks

### `capabilities.process`
- `spawns: bool` — did the skill spawn child processes?
- `shell_exec: bool` — did it invoke a shell?
- `observed_commands[]` — command lines observed

### `capabilities.secrets`
- `env_access: bool`
- `observed_vars[]`
- `keychain_access: bool`

## `findings`

Each finding has:

| Field | Type | Notes |
|---|---|---|
| `severity` | enum | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `title` | string | Short, human title |
| `description` | string | Detailed explanation |
| `evidence` | object | `trace_hash`, `line_ref`, `snippet` |
| `recommendation` | string | What the author should do |
| `owasp_ref` | string? | OWASP AI Guardrails ID |
| `mitre_ref` | string? | MITRE ATLAS technique ID |

## `dependencies`

| Field | Type | Notes |
|---|---|---|
| `sbom_hash` | string? | `sha256:<hex>` of the SBOM |
| `high_risk_packages` | string[] | Typosquats, malware names |
| `known_vulns` | string[] | CVE IDs |
| `install_hooks` | string[] | Paths to detected install-time code |

## `recommended_policy`

| Field | Type | Notes |
|---|---|---|
| `sandbox_runtime_image` | string? | `sha256:<hex>` of suggested image |
| `egress_allowlist` | string[] | Domains the skill is permitted to call |
| `egress_denylist` | string[] | Domains to actively block |
| `filesystem` | object | `read_only[]`, `restricted_write[]` |
| `shell_access` | bool | `false` unless shell observed |
| `env_allowlist` | string[] | Env vars the skill is permitted to read |
| `max_memory_mb` | int | Hard memory cap |
| `timeout_seconds` | int | Execution timeout |
| `rate_limit_rps` | int? | Optional outbound rate limit |

## `evidence`

Each value is `sha256:<hex>` of an analysis artifact:

| Field | Of what |
|---|---|
| `network_trace_hash` | pcap or summarised network log |
| `fs_trace_hash` | filesystem-access journal |
| `process_trace_hash` | process spawning log |
| `secrets_trace_hash` | env/keychain probe log |
| `sandbox_log_hash` | full sandbox stdout+stderr |

## `run_metadata`

| Field | Type | Notes |
|---|---|---|
| `tools` | object | `{tool_name: version}` map |
| `runtime_image` | string? | sha256 of sandbox image |
| `determinism_seed` | int | Seed used for any randomness |
| `analysis_duration_ms` | int | Wall time for the full pipeline |
| `schema_version` | string | Schema version (currently `"1.0.0"`) |

## `attestation`

| Field | Type | Notes |
|---|---|---|
| `miner_hotkey` | string | ss58-encoded |
| `signature` | string | `ed25519:<hex>` of `signing_hash()` |
| `timestamp` | string | ISO 8601 UTC |
| `schema_version` | string | Should match `run_metadata.schema_version` |

## Canonical JSON for signing

The signature is computed over the SHA-256 of the canonical JSON form of
the SSSA **with the `attestation` field omitted**. Use
[`SSSA.canonical_json()`](../phylax/protocol.py) to produce the exact
bytes; the canonical form sorts keys and uses `(",", ":")` separators.

## Versioning policy

The schema follows semver:

- **patch** (`1.0.x`): documentation-only or backward-compatible field
  additions
- **minor** (`1.x.0`): new optional fields
- **major** (`x.0.0`): renamed or removed fields — breaks compatibility

Miners and validators must agree on at least the major version. The
validator rejects SSSAs whose `schema_version` isn't in
`SUPPORTED_SCHEMA_VERSIONS`.
