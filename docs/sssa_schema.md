# SSSA Schema Reference

Field-by-field reference for the Signed Skill Safety Attestation (schema version 1.1.0).

Canonical schema source: [`phylax/protocol.py`](../phylax/protocol.py).

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
| `run_metadata` | object | no | Tooling versions + timing + determinism seed (validator nonce) |
| `attestation` | object | required for signed SSSA | Miner ed25519 signature |
| `countersignature` | object | optional | Validator countersignature on consensus SSSAs (§6.2) |

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

### `capabilities.filesystem`

`reads[]`, `writes[]`, `deletes[]` — absolute or repo-relative paths.

### `capabilities.network`

- `egress: bool`
- `observed_domains[]`
- `observed_ips[]`
- `observed_ports[]`
- `persistent_connections: int` — count of long-lived flows (new in 1.1.0)
- `allowlist_suggestion[]` / `denylist_suggestion[]`

### `capabilities.process`

- `spawns: bool`
- `shell_exec: bool`
- `observed_commands[]`

### `capabilities.secrets`

- `env_access: bool`
- `observed_vars[]`
- `keychain_access: bool`

## `findings`

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
| `known_vulns` | string[] | CVE / GHSA IDs from osv.dev |
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
| `network_trace_hash` | `H(N(S))` — network egress log |
| `fs_trace_hash` | `H(F(S))` — filesystem-access journal |
| `process_trace_hash` | `H(P(S))` — process tree log |
| `secrets_trace_hash` | `H(K(S))` — env/keychain probe log |
| `sandbox_log_hash` | full sandbox stdout+stderr |
| `pcap_hash` | optional PCAP capture (Appendix A) |

## `run_metadata`

| Field | Type | Notes |
|---|---|---|
| `tools` | object | `{tool_name: version}` map |
| `runtime_image` | string? | sha256 of sandbox image |
| `determinism_seed` | int | The per-task nonce η_i the validator supplied (§5.1) |
| `analysis_duration_ms` | int | Wall time for the full pipeline (not authoritative — validator measures latency itself) |
| `schema_version` | string | `1.1.0` |

## `attestation`

| Field | Type | Notes |
|---|---|---|
| `miner_hotkey` | string | ss58-encoded |
| `signature` | string | `ed25519:<hex>` over `SSSA.signing_hash()` |
| `timestamp` | string | ISO 8601 UTC |
| `schema_version` | string | Must match `run_metadata.schema_version` |

## `countersignature` (new in 1.1.0)

| Field | Type | Notes |
|---|---|---|
| `validator_hotkey` | string | ss58-encoded |
| `signature` | string | `ed25519:<hex>` over `SSSA.consensus_signing_bytes(round_id)` |
| `timestamp` | string | ISO 8601 UTC |
| `round_id` | string | Bound to the consensus round; prevents replay onto a different round |
| `quality_score` | float 0–1 | Winning miner's composite Q at the time of consensus |

## Canonical JSON for signing

`SSSA.canonical_json()` returns sorted-key, compact-separator JSON with both `attestation` and `countersignature` stripped. The miner signs this. For the validator countersignature, `SSSA.consensus_signing_bytes(round_id)` binds in the miner signature, the miner hotkey and the round_id.

## Versioning policy

- patch: docs / additive optional fields
- minor: new optional fields
- major: renamed or removed fields (incompatible)

Validators reject SSSAs whose `schema_version` is not in `SUPPORTED_SCHEMA_VERSIONS`. The 1.0.0 → 1.1.0 bump added `nonce` to the synapse, `countersignature` to the SSSA, and `persistent_connections` to network capabilities.
