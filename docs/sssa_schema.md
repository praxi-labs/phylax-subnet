# SSSA Schema Reference
## Version 1.0 (Phylax v2.0)

The Signed Skill Safety Attestation (SSSA) is the canonical JSON artifact a miner returns inside the `synapse.attestation` field of every `PhylaxSynapse` response. It is signed in its entirety with the miner's ed25519 hotkey.

Canonical schema source: [`phylax/protocol.py`](../phylax/protocol.py).

The full miner response also carries three companion fields next to the SSSA. These are described in section 12 at the end of this document.


## 1. Top-Level Structure

```json
{
  "skill":               { ... },
  "verdict":             { ... },
  "capabilities":        { ... },
  "findings":            [ ... ],
  "dependencies":        { ... },
  "recommended_policy":  { ... },
  "evidence":            { ... },
  "attestation":         { ... }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `skill` | object | yes | Identifies the bundle and skill type. |
| `verdict` | object | yes | The miner's analysis conclusion. |
| `capabilities` | object | yes | Observed runtime capabilities. |
| `findings` | array | yes | Issues detected. May be empty. |
| `dependencies` | object | yes | Supply-chain results. |
| `recommended_policy` | object | yes | Enforceable runtime policy. |
| `evidence` | object | yes | Content-addressed evidence + type-specific block + optional LLM block. |
| `attestation` | object | yes | Miner ed25519 signature. |


## 2. `skill`

Identifies which bundle was analysed and under which skill type.

| Field | Type | Notes |
|---|---|---|
| `name` | string | From bundle metadata. Use `"unknown"` if missing. |
| `bundle_hash` | string | `sha256:<64 hex>`. Primary identifier. Must match the bundle the validator sent. |
| `skill_type` | enum | One of `rag_knowledge`, `declarative`, `executable_python`, `executable_script`, `mcp_server`, `agent_composition`. Must match the task's skill type. |
| `profile` | enum | `fast`, `standard`, or `deep`. From bundle metadata. |
| `schema_version` | string | Always `"1.0"` in this schema. |


## 3. `verdict`

The miner's analysis conclusion.

| Field | Type | Notes |
|---|---|---|
| `decision` | enum | `ALLOW`, `WARN`, or `BLOCK`. |
| `risk_score` | int | `0` to `100`. Higher = riskier. |
| `confidence` | float | `0.0` to `1.0`. The miner's self-reported confidence. |
| `verdict_sources` | string[] | Layer strings that contributed to the verdict. Examples: `L0_content`, `L0_declarative`, `L1_taint`, `L2_sbom`, `L3_runtime`, `L3_mcp_manifest`, `L3_tool_calls`, `L3_composition`, `L3_transitive_risk`. |


## 4. `capabilities`

Flat lists of everything the skill was observed to do.

### `capabilities.filesystem`

| Field | Type | Notes |
|---|---|---|
| `reads` | string[] | Path patterns the skill read from. |
| `writes` | string[] | Path patterns the skill wrote to. |

### `capabilities.network`

| Field | Type | Notes |
|---|---|---|
| `domains` | string[] | Observed outbound domains. |
| `ips` | string[] | Observed outbound IP addresses. |
| `ports` | int[] | Observed outbound ports. |

### Top-level capability lists

| Field | Type | Notes |
|---|---|---|
| `process_spawns` | string[] | Commands the skill spawned. |
| `secrets_access` | string[] | Types of secrets accessed (e.g. `api_key`, `ssh_key`). |
| `shell_commands` | string[] | Shell command lines observed. |
| `tool_calls` | string[] | MCP tool invocations observed. |
| `child_skills` | string[] | Child skill names invoked in a composition. |


## 5. `findings`

A list of issues detected by the miner. Each entry has the same structure regardless of skill type.

| Field | Type | Notes |
|---|---|---|
| `finding_id` | string | UUID assigned by the miner. |
| `severity` | enum | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `title` | string | Short, machine-stable title. The validator uses parts of this for finding canonicalisation. |
| `description` | string | Human-readable detail. |
| `owasp_ref` | string \| null | OWASP reference (e.g. `A03`). |
| `mitre_ref` | string \| null | MITRE ATT&CK reference (e.g. `T1059.004`). |
| `evidence_snippet` | string | Short string showing where the finding was observed. Often `<file>:<line>` or `<command>:<args>`. |
| `layer_source` | enum | `L0`, `L1`, `L2`, or `L3`. Which layer of analysis produced the finding. |
| `finding_type` | enum | `static`, `sbom`, `runtime`, `manifest`, or `content`. |

The validator uses `(layer_source, owasp_ref or mitre_ref, affected_file, line_bucket)` as the canonical finding key when computing consensus. Findings with the same key across multiple miners are treated as the same finding.


## 6. `dependencies`

Supply-chain analysis results.

| Field | Type | Notes |
|---|---|---|
| `sbom_hash` | string \| null | `sha256:<hex>` of the generated SBOM. |
| `high_risk_packages` | string[] | Typosquats, abandoned packages, etc. |
| `known_cves` | string[] | CVE / GHSA IDs found via vulnerability lookup. |
| `install_hooks` | string[] | Paths to detected install-time code. |
| `mcp_manifest_hash` | string \| null | `sha512:<hex>` of the MCP manifest as served at runtime. Required for `mcp_server` type. |
| `child_skill_verdicts` | object[] | Per-child results in `agent_composition` analysis. |

### `child_skill_verdicts[]` entry

| Field | Type | Notes |
|---|---|---|
| `skill_name` | string | Name of the child skill. |
| `bundle_hash` | string | `sha256:<hex>` of the child bundle. |
| `verdict` | enum | `ALLOW`, `WARN`, `BLOCK`, or `UNKNOWN`. |


## 7. `recommended_policy`

A machine-enforceable runtime policy a consuming runtime should apply before invoking the skill.

| Field | Type | Notes |
|---|---|---|
| `egress_allow` | string[] | Domains or IPs the skill is permitted to call. |
| `egress_deny` | string[] | Domains or IPs to actively block. |
| `fs_read` | string[] | Path patterns the skill is permitted to read. |
| `fs_write` | string[] | Path patterns the skill is permitted to write. |
| `shell_access` | bool | `false` unless shell execution was observed and is required. |
| `max_memory_mb` | int | Hard memory cap. |
| `timeout_s` | int | Execution timeout. |
| `env_allowlist` | string[] | Env vars the skill is permitted to read. |
| `tool_allowlist` | string[] | MCP tool names the skill is permitted to call. |
| `child_skill_allowlist` | string[] | Names of child skills the composition may invoke. |

The policy should be derivable from the observed `capabilities`. The validator's policy axis π scores how well your `recommended_policy` matches what was observed and what was expected.


## 8. `evidence`

The proof-of-work block. It has three subsections.

### 8.1. `evidence.base`

Base trace hashes for all runtime skill types. For `rag_knowledge` and `declarative` these are typically `null`.

| Field | Type | Notes |
|---|---|---|
| `network_trace_hash` | string \| null | `sha256:<hex>` of normalised `network.jsonl`. |
| `fs_trace_hash` | string \| null | `sha256:<hex>` of normalised `fs.jsonl`. Must include the canary write at `/skill/.canary`. |
| `process_trace_hash` | string \| null | `sha256:<hex>` of normalised `process.jsonl`. |
| `secrets_trace_hash` | string \| null | `sha256:<hex>` of normalised `secrets.jsonl`. |

Trace normalisation rule: parse each JSONL line, sort by `ts` ascending, re-serialise with sorted keys and no whitespace, then sha256.

### 8.2. `evidence.type_specific`

Exactly one of the following six blocks is populated per response. Which one depends on `skill.skill_type`.

#### 8.2.1. `rag_knowledge`

| Field | Type | Notes |
|---|---|---|
| `rag_content_fingerprint` | string | `sha256:<hex>` of concatenated sorted document hashes (over the documents as the validator delivered them, including any embedded canary marker). |
| `hidden_instruction_score` | float | `0.0` to `1.0`. |
| `embedded_urls` | string[] | All URLs found across documents. |
| `document_count` | int | Number of documents analysed. |
| `canary_id_found` | bool | `true` if the validator's canary marker was located. |

#### 8.2.2. `declarative`

| Field | Type | Notes |
|---|---|---|
| `canary_id_found` | bool | `true` if `<!-- CANARY: {id} -->` was found in `SKILL.md`. Required for non-zero ε. |
| `findings_count` | int | Number of findings reported. |
| `skill_md_fingerprint` | string | `sha256:<hex>` of `SKILL.md` as delivered. |
| `prompt_injection_ml_score` | float | `0.0` to `1.0`. Offline classifier output, not from a live LLM. |
| `unicode_anomaly_detected` | bool | Whether unicode steganography signals were detected. |
| `layer0_sync_hash` | string | `sha256:<hex>` of analysis state for cross-miner verification. |

#### 8.2.3. `executable_python`

| Field | Type | Notes |
|---|---|---|
| `imports_trace_hash` | string | `sha256:<hex>` of normalised `imports.jsonl`. |

#### 8.2.4. `executable_script`

| Field | Type | Notes |
|---|---|---|
| `shell_commands_hash` | string | `sha256:<hex>` of normalised `shell_commands.jsonl`. |

#### 8.2.5. `mcp_server`

| Field | Type | Notes |
|---|---|---|
| `tool_calls_hash` | string | `sha256:<hex>` of normalised `tool_calls.jsonl`. |
| `mcp_manifest_hash` | string | `sha512:<hex>` of the canonical tool manifest as served by the MCP server at runtime. |
| `tool_poisoning_score` | float | `0.0` to `1.0`. |
| `tool_shadowing_detected` | bool | |
| `rug_pull_risk` | bool | |

#### 8.2.6. `agent_composition`

| Field | Type | Notes |
|---|---|---|
| `agent_calls_hash` | string | `sha256:<hex>` of normalised `agent_calls.jsonl`. |
| `dependency_graph_hash` | string | `sha256:<hex>` of the serialised dependency graph. |
| `transitive_risk_score` | float | `0.0` to `1.0`. Computed from child verdicts. |
| `composition_depth_observed` | int | Nesting depth observed at runtime. Should equal the synapse's `composition_depth`. |

### 8.3. `evidence.llm_evidence`

Optional. Populate only if your pipeline made any LLM API call.

| Field | Type | Notes |
|---|---|---|
| `model_id` | string \| null | Model name (e.g. `claude-3-5-sonnet`). |
| `prompt_hash` | string \| null | `sha256:<hex>` of the prompt sent. |
| `response_hash` | string \| null | `sha256:<hex>` of the model response. |
| `api_request_id` | string \| null | Provider-supplied request identifier. |
| `token_count` | int \| null | Total tokens used. |
| `timestamp` | string \| null | ISO-8601 UTC of the request. |
| `allowed_use` | enum \| null | Must be `finding_enrichment`, `mitre_owasp_mapping`, or `cve_explanation`. Any other value triggers a violation and the SSSA scores zero. |

LLMs may only be used post-analysis for enrichment, labelling, or CVE explanation. They may not be used to decide the verdict, score prompt injection, classify tool poisoning, detect behaviour mismatches, or analyse skill content. See the miner setup guide section 11 (Hard Rules).


## 9. `attestation`

The signature block. Required.

| Field | Type | Notes |
|---|---|---|
| `miner_hotkey` | string | ss58 address of the miner's hotkey. |
| `supported_types_declared` | string[] | The list of skill types the miner registered with phylax-server. |
| `ed25519_signature` | string | `<hex>` of the ed25519 signature. See section 10 for the signing rule. |
| `timestamp` | string | ISO-8601 UTC of when the SSSA was signed. |
| `schema_version` | string | Always `"1.0"`. |
| `skill_type_version` | string | Always `"1.0"`. |


## 10. Canonical JSON and Signing

The ed25519 signature is computed as follows.

```
canonical = json.dumps(sssa_body_with_signature_field_removed,
                       sort_keys=True,
                       separators=(",", ":"))
message   = sha256(canonical.encode("utf-8"))
signature = wallet.hotkey.sign(message).hex()
sssa.attestation.ed25519_signature = signature
```

Rules:

- The signing input excludes `attestation.ed25519_signature` itself.
- All other `attestation` fields (`miner_hotkey`, `supported_types_declared`, `timestamp`, `schema_version`, `skill_type_version`) are included in the signing input.
- JSON is UTF-8.
- Keys are sorted alphabetically at every nesting level.
- No whitespace between tokens.

The validator verifies the signature by re-serialising the SSSA in the same canonical form (with the signature field removed), recomputing the sha256, and verifying the ed25519 signature against `miner_hotkey`.


## 11. Versioning Policy

| Change | Bump |
|---|---|
| Documentation only | (no bump) |
| New optional field, additive | patch (`1.0.x`) |
| New required field, structural | minor (`1.x.0`) |
| Renamed or removed fields | major (`x.0.0`) |

The validator rejects SSSAs whose `attestation.schema_version` is not `"1.0"`.


## 12. Companion Fields on the Synapse

The miner returns the same `PhylaxSynapse` object with the following fields populated next to `attestation`. These are wire-level fields, not part of the signed SSSA body.

### `synapse.probe_evidence`

Required for both primaries and auditors. A dict echoing the four probe values derived from the nonce.

```json
{
  "file_path":    "/skill/.probe_<sha256(nonce)[:16]>",
  "file_content": "<sha256(nonce)[16:48]>",
  "dns_host":     "<sha256(nonce)[:8]>.probe.phylax.ai",
  "process_echo": "<sha256(nonce)[8:24]>"
}
```

For runtime skill types these three events must also appear in the trace files:

- The file write at `file_path` must appear in `fs.jsonl`.
- The DNS lookup of `dns_host` must appear in `network.jsonl`.
- A process spawn of `echo <process_echo>` must appear in `process.jsonl`.

The validator verifies probe values match the nonce-derivation and (for runtime types) that the three events are present.

### `synapse.trace_bundle`

Required only for runtime primaries. A `dict[str, str]` of `{filename: base64(gzip(jsonl_bytes))}`.

| Skill type | Required files |
|---|---|
| `executable_python` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `imports.jsonl.gz` |
| `executable_script` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `shell_commands.jsonl.gz` |
| `mcp_server` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `tool_calls.jsonl.gz` |
| `agent_composition` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `agent_calls.jsonl.gz` |
| `rag_knowledge`, `declarative` | Omit. |

Size caps (compressed): `network` 5 MB, `fs` 10 MB, `process` 5 MB, `secrets` 1 MB, `imports` 2 MB, `shell_commands` 5 MB, `tool_calls` 5 MB, `agent_calls` 10 MB. Total bundle must not exceed 30 MB.

### `synapse.sandbox_manifest`

Required only for runtime primaries. Declares which sandbox image produced the traces.

```json
{
  "image":          "ghcr.io/<you>/phylax-sandbox-python:v1",
  "digest":         "sha256:abc123...",
  "tracer_version": "1.0.0",
  "tracer_hash":    "sha256:def456...",
  "kernel":         "",
  "cpu_arch":       ""
}
```

The `digest` must equal the `image_hash` the miner registered with phylax-server. Mismatch fails the round immediately.

### `synapse.error`

Optional. Set if anything failed on the miner side. When set, the validator skips the response entirely.


## 13. Quick Reference: What is Required Per Role

| Field | Primary, runtime type | Primary, content type | Auditor, any type |
|---|---|---|---|
| `synapse.attestation` (SSSA) | required | required | required |
| `synapse.probe_evidence` | required | required | required |
| `synapse.trace_bundle` | required | omit | omit |
| `synapse.sandbox_manifest` | required | omit | omit |

Runtime types: `executable_python`, `executable_script`, `mcp_server`, `agent_composition`.
Content types: `rag_knowledge`, `declarative`.
