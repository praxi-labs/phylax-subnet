# Miner Setup Guide

Run a Phylax miner on testnet (netuid 486).

A miner picks one or more of six skill types, registers that specialization with phylax-server, then runs an axon that answers `PhylaxSynapse` requests. The reference repo ships a working harness for every type; what you replace inside those harnesses is your competitive edge. The subnet team defines only the **structural contract** below — your internal pipeline is entirely your own.

## 1. Prerequisites

- Docker 24+ with the `compose` plugin (`docker compose version` must work).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, **80 GB free disk**.
- Inbound TCP **8091** open to the public internet (validators dial this port).
- Your shell user in the `docker` group: `sudo usermod -aG docker $USER && newgrp docker`.

## 2. Wallet, register on netuid 486

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
```

Fund the coldkey with testnet TAO from the Bittensor Discord `#faucet` channel.

```bash
btcli subnet register \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name miner \
  --wallet.hotkey default
```

Verify:

```bash
btcli wallet overview --wallet.name miner --subtensor.network test
```

## 3. Install + configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
```

Edit `~/phylax/miner/.env`:

| Variable | What to set |
|---|---|
| `PHYLAX_NETUID` | `486` |
| `SUBTENSOR_NETWORK` | `test` |
| `WALLET_NAME` | folder name in `~/.bittensor/wallets/` |
| `WALLET_HOTKEY` | `default` (or the hotkey you registered) |
| `PHYLAX_SERVER_URL` | `https://<phylax-server-host>` |
| `PHYLAX_SERVER_HOTKEY` | `<hex from curl $PHYLAX_SERVER_URL/v1/server-identity>` |

## 4. Choose your skill types

You decide. No one assigns them. Pick what you have the infrastructure and expertise to do well — declaring a type you cannot serve drops your standing for that type and you stop receiving its tasks.

| Skill type | What the bundle is | What your harness must do |
|---|---|---|
| `rag_knowledge` | Documents, knowledge-base content. No code. | Content-only scan. No sandbox. Compute document fingerprint, detect hidden-instruction patterns, enumerate embedded URLs, find the canary. |
| `declarative` | A `SKILL.md` (or equivalent) of natural-language instructions. No code. | Static text analysis. No sandbox. Compute `skill_md_fingerprint`, run your prompt-injection classifier (offline, not a live LLM), detect Unicode anomalies, find the canary. |
| `executable_python` | Python source + dependency manifests. | Static + SBOM + Docker sandbox detonation. Emit the four base traces + `imports.jsonl`. Touch the canary file during detonation. |
| `executable_script` | Shell scripts (`*.sh`, `*.bash`, etc.). | Static shell taint analysis + Docker sandbox detonation. Emit the four base traces + `shell_commands.jsonl`. |
| `mcp_server` | A Model Context Protocol server: handlers + manifest. | Two containers (server + your test client). Connect, enumerate tools, exercise each with synthetic params (one carrying the canary), capture interactions. Emit base traces + `tool_calls.jsonl` and compute `mcp_manifest_hash`. |
| `agent_composition` | A composition manifest orchestrating child skills. | Multi-container cascading detonation: parent + all children. Emit aggregated base traces + `agent_calls.jsonl`, plus a dependency graph hash and a transitive risk score. |

Constraints when you register:

- Declare **at least two** distinct types (the network needs broad coverage).
- At least one declared type must have a base weight `>= 1.0` (i.e. one of `executable_python`, `executable_script`, `mcp_server`, `agent_composition`). You can't earn only from RAG + declarative.

## 5. Register your specialization

phylax-server only routes tasks to miners who have a current specialization on file. **You must also register the sandbox image you will run for each runtime skill type** — validators will pull and re-execute that exact image to verify your traces are honest.

```bash
curl -X POST "$PHYLAX_SERVER_URL/v1/specialization/register" \
  -H "Content-Type: application/json" \
  -H "X-Phylax-Hotkey: <your-ss58-address>" \
  -H "X-Phylax-Timestamp: $(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  -H "X-Phylax-Signature: ed25519:<hex-sig-of-canonical-body>" \
  -d '{
    "hotkey": "<your-ss58-address>",
    "registration_version": "2.0",
    "specialization": {
      "supported_types": ["executable_python", "declarative"],
      "sandbox_images": {
        "executable_python": {
          "image_uri":  "ghcr.io/<you>/phylax-sandbox-python:v1",
          "image_hash": "sha256:abc123..."
        }
      },
      "min_profile": "standard",
      "max_concurrent_tasks": 2,
      "implementation_tier_claim": "reference"
    }
  }'
```

**Sandbox image rules** (server-enforced):

- For every runtime skill type you declare (`executable_python`, `executable_script`, `mcp_server`, `agent_composition`), you must provide a `sandbox_images[<type>] = {image_uri, image_hash}` entry. Missing entries → registration rejected.
- `image_hash` must start with `sha256:` and be the **content-addressable digest** of the image (`docker images --digests` or `docker inspect --format='{{index .RepoDigests 0}}' <image>`).
- The image must be publicly pullable from `image_uri`, or pre-authorised on validator hosts.
- Re-register any time to publish a new image. Validators pick up the new image on the next routing query.
- `rag_knowledge` and `declarative` don't need sandbox images (no container).

`implementation_tier_claim` is informational only — your actual standing is derived from your SSSAs and the validator's rerun verification.

## 6. Run

```bash
cd ~/phylax/miner
docker compose pull
docker compose up -d
docker compose logs -f
```

Within ~30 seconds:

```
Axon serving on [::]:8091
```

Once a validator dispatches a task:

```
scan: bundle=sha256:... type=executable_python profile=standard task=...
scan done: sha256:... -> ALLOW risk=12
```

## 7. The structural contract you owe

For every `PhylaxSynapse` your axon receives, you have `task_metadata.deadline_s` seconds to return a synapse with a valid SSSA. The SSSA shape is defined in [`phylax/protocol.py`](../phylax/protocol.py). What you must produce per declared skill type:

**Per-type inputs** the synapse delivers to you:

- `skill_bundle.bundle_bytes` or `skill_bundle.bundle_url` — the bundle.
- `skill_bundle.bundle_hash` — sha256 you must verify before doing anything.
- `skill_bundle.metadata.skill_type` — which harness to dispatch to.
- `skill_bundle.metadata.profile` — `fast` / `standard` / `deep`.
- `nonce` — the canary seed. Thread it into your sandbox; without it the canary mechanism fails.
- `task_metadata.task_id`, `task_metadata.deadline_s`, `task_metadata.t_min_s`.

**Per-type required output files** (under `/evidence/`, generated by your harness):

| Type | Required trace files |
|---|---|
| `rag_knowledge` | `rag_manifest.json` |
| `declarative` | none (in-memory analysis only) |
| `executable_python` | `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`, `imports.jsonl` |
| `executable_script` | `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`, `shell_commands.jsonl` |
| `mcp_server` | `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`, `tool_calls.jsonl` |
| `agent_composition` | `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`, `agent_calls.jsonl` (all aggregated across containers) |

JSONL schemas for `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`, `imports.jsonl`, `shell_commands.jsonl`, `tool_calls.jsonl`, and `agent_calls.jsonl` are defined in [new_strutcure.md §3](../new_strutcure.md). Your harness must emit exactly these schemas — the trace hashes you put in the SSSA are computed from these files.

**Per-type required SSSA evidence fields** (under `evidence.type_specific.<skill_type>`):

| Type | Required fields |
|---|---|
| `rag_knowledge` | `rag_content_fingerprint`, `hidden_instruction_score`, `embedded_urls`, `document_count`, `canary_id_found` |
| `declarative` | `canary_id_found`, `findings_count`, `skill_md_fingerprint`, `prompt_injection_ml_score`, `unicode_anomaly_detected`, `layer0_sync_hash` |
| `executable_python` | `imports_trace_hash` (plus the four base trace hashes under `evidence.base`) |
| `executable_script` | `shell_commands_hash` (plus four base trace hashes) |
| `mcp_server` | `tool_calls_hash`, `mcp_manifest_hash`, `tool_poisoning_score`, `tool_shadowing_detected`, `rug_pull_risk` (plus four base trace hashes) |
| `agent_composition` | `agent_calls_hash`, `dependency_graph_hash`, `transitive_risk_score`, `composition_depth_observed` (plus four base trace hashes) |

**Canary handling** — every type carries a `canary_id` and `canary_val` your harness receives. What you do with them per type:

- `rag_knowledge`: compute `rag_content_fingerprint` deterministically over the documents in the bundle exactly as delivered (don't strip, normalise, or reorder bytes). Scan content for a canary marker matching `CANARY_<canary_id>` and set `canary_id_found` accordingly.
- `declarative`: scan SKILL.md for `<!-- CANARY: {canary_id} -->`; set `canary_id_found = true` when found. Compute `skill_md_fingerprint` over SKILL.md exactly as delivered.
- `executable_python` / `executable_script`: thread `canary_val` into the sandbox as the `CANARY_VAL` env var, and have your harness write it to `/skill/.canary` before launching the skill. Your tracer must record the resulting filesystem op into `fs.jsonl` so the hash includes it.
- `mcp_server`: include `canary_val` as a parameter value in at least one synthetic tool invocation your test client makes; the resulting record must appear in `tool_calls.jsonl`.
- `agent_composition`: inject `canary_val` into the parent skill's input context before detonation so it propagates through the composition; the propagation must appear in `agent_calls.jsonl`.

**Signing** — every SSSA you return must carry an `attestation` block:

- `miner_hotkey` = your axon's ss58 address.
- `supported_types_declared` = the list you registered with phylax-server.
- `ed25519_signature` = hex signature, signed with your hotkey, over `sha256(canonical_json(SSSA without the signature field))`. Keys sorted alphabetically, no whitespace, UTF-8.
- `timestamp` = ISO-8601 UTC.

## 8. Where to build your own pipeline

The reference harnesses in this repo satisfy the structural contract above. Replacing the internals of any of them is where you compete.

| Skill type | Harness file (replace internals here) | Sandbox container (replace here for runtime types) |
|---|---|---|
| `rag_knowledge` | [phylax/harness/rag_knowledge/runner.py](../phylax/harness/rag_knowledge/runner.py) | — (no container) |
| `declarative` | [phylax/harness/declarative/runner.py](../phylax/harness/declarative/runner.py) | — (no container) |
| `executable_python` | [phylax/harness/executable_python/runner.py](../phylax/harness/executable_python/runner.py) | [phylax/harness/executable_python/container/](../phylax/harness/executable_python/container/) (`Dockerfile`, `run.sh`, `tracer.py`) |
| `executable_script` | [phylax/harness/executable_script/runner.py](../phylax/harness/executable_script/runner.py) | [phylax/harness/executable_script/container/](../phylax/harness/executable_script/container/) (`shell_tracer.py`) |
| `mcp_server` | [phylax/harness/mcp_server/runner.py](../phylax/harness/mcp_server/runner.py) | [phylax/harness/mcp_server/container/](../phylax/harness/mcp_server/container/) (`mcp_client.py`) |
| `agent_composition` | [phylax/harness/agent_composition/runner.py](../phylax/harness/agent_composition/runner.py) | [phylax/harness/agent_composition/container/](../phylax/harness/agent_composition/container/) (`orchestrator.py`) |

Each runner exposes a `run(bundle_dir, ..., nonce, canary_id, canary_val)` method called by [neurons/miner.py](../neurons/miner.py) `_dispatch`. The runner returns a result object with `evidence`, `findings`, and (for runtime types) `base_evidence`. As long as your replacement returns the same dataclass shape and emits the required trace files into the evidence dir, the miner glue code doesn't care what's inside.

### Building your own sandbox

For `executable_python` / `executable_script` / `mcp_server` / `agent_composition`, the harness invokes a Docker container that you control. The container contract:

- **Entrypoint:** `/harness/run.sh <bundle_path> <nonce>`
- **Env vars injected by your harness:** `CANARY_ID`, `CANARY_VAL`, `AGENT_TIMEOUT` (seconds).
- **Output dir:** `/evidence/` — bind-mounted into the container by `_dispatch`. Write all required JSONL files here.

To run your own image, build it and point the miner at it:

```bash
docker build -t my-sandbox:custom -f phylax/harness/executable_python/container/Dockerfile .
export PHYLAX_SANDBOX_IMAGE=my-sandbox:custom
docker compose up -d --force-recreate
```

The miner runs the container; the container does the analysis. Add audit hooks, kernel-level tracing, your own classifier, proprietary CVE feeds, etc., inside the container. As long as it emits the required JSONL schemas, validators will accept the resulting SSSA.

### Primary vs auditor role

Every task carries a `task_metadata.role` field which is either `"primary"` or `"auditor"`. The validator chooses your role per task per round — you don't know in advance.

- **Primary** (3 per task, picked from highest reputation for that skill type): full pipeline. Sandbox detonation, full SSSA, trace_bundle, sandbox_manifest, probe_evidence. Longer deadline (the matrix in §4). Full emission.
- **Auditor** (2 per task, picked randomly from remaining declared miners): full SSSA (verdict, findings, capabilities, dependencies, policy) but no trace_bundle and no sandbox_manifest required. Tighter deadline (rag 2/15, decl 3/30, exec 10/90, mcp 20/150, comp 30/240 seconds). Earns `0.6 × primary_emission × consensus_score`.

Auditors are rotated: if you've been an auditor 3 rounds in a row for a skill type, you're promoted into the primary slot regardless of reputation rank.

### What you must submit per task

For every task the validator sends, your axon must return the synapse with these pieces populated:

1. **`attestation`** — the signed SSSA (canonical JSON, ed25519 signature with your hotkey). Always required.
2. **`probe_evidence`** — a dict `{file_path, file_content, dns_host, process_echo}` derived from the nonce. Always required (primary and auditor). For runtime skill types, your harness must **also** perform those three events inside the sandbox so they appear in fs.jsonl, network.jsonl, and process.jsonl respectively.
3. **`trace_bundle`** — required for runtime primaries only. A `dict[str, str]` of `{filename: base64(gzip(jsonl_bytes))}`. Required filenames per type:
   - `executable_python`: `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `imports.jsonl.gz`
   - `executable_script`: same four base + `shell_commands.jsonl.gz`
   - `mcp_server`: same four base + `tool_calls.jsonl.gz`
   - `agent_composition`: same four base + `agent_calls.jsonl.gz`
   - `rag_knowledge` and `declarative`: omit `trace_bundle` entirely (no sandbox).
3. **`sandbox_manifest`** — a `dict` for runtime types declaring what you ran:
   ```json
   {
     "image": "ghcr.io/<you>/phylax-sandbox-python:v1",
     "digest": "sha256:abc123...",
     "tracer_version": "1.0.0",
     "tracer_hash": "sha256:def456...",
     "kernel": "",
     "cpu_arch": ""
   }
   ```
   The `image` + `digest` here **must match what you registered** at `/v1/specialization/register`. Validators will pull and rerun this exact image to verify your traces.

Trace bundle size limits (compressed, per file): `network` 5MB, `fs` 10MB, `process` 5MB, `secrets` 1MB, `imports` 2MB, `shell_commands` 5MB, `tool_calls` 5MB, `agent_calls` 10MB. Total bundle ≤ 30MB. Exceeding any → response treated as missing.

### How the validator verifies your submission

In the same round (immediate scoring):
- **Hash consistency**: validator decompresses each trace file, normalises (sort by `ts`, sorted keys, no whitespace), sha256-hashes it. Computed hash must equal the hash you declared in the SSSA. Mismatch → ε = 0.
- **Canary presence**: validator scans your decompressed `fs.jsonl` for a write to `/skill/.canary`. Your tracer must observe and record that filesystem op. Missing → ε = 0.
- **Semantic subset**: every event (network tuple, fs op+path, process cmd, secret pattern) the validator's own reference run observed must appear in your traces. Missing events lower ε, extras raise the depth bonus.

Asynchronously (next round's reputation):
- Validator pulls your registered sandbox image, verifies its content-addressable digest matches what you declared at registration, then **reruns it on the same bundle with the same nonce**.
- Validator checks the rerun's `fs_trace_hash` against the hash you submitted. The canary write is deterministic, so an honest sandbox run produces a matching hash.
- Validator checks semantic agreement (≥ 0.7) between rerun events and your submitted events on the four base traces.
- Outcome → `/v1/reputation/rerun-verification` → pass adds +0.02 to your per-type reputation, fail multiplies by ×0.7. Reputation directly affects routing and emission weighting.

### Hard rules — break any of these and the SSSA scores zero

- **No LLM for reasoning.** Using a live LLM to decide the verdict, score prompt injection, classify tool poisoning, detect behaviour mismatches, or do any form of skill content analysis is forbidden and produces a zero score for the task. Reputation for the skill type decays accordingly. The only permitted LLM uses are post-hoc finding enrichment, MITRE/OWASP labelling, and CVE explanation — and only if the deterministic analysis is already complete. Your SSSA's `llm_evidence.allowed_use` (when present) must be one of `finding_enrichment`, `mitre_owasp_mapping`, or `cve_explanation`. Anything else gets flagged. The detection, the verdict, and every score in your SSSA must come from deterministic analysis your harness performs itself.
- **No skill_type mismatch.** Return an SSSA whose `skill.skill_type` differs from the synapse bundle's `skill_type` and the response is treated as invalid (zero score).
- **No suspiciously fast responses.** Return before `task_metadata.t_min_s` seconds elapse and the response is treated as not having actually run the sandbox (zero score).
- **No missing required evidence.** Any required SSSA evidence field for the declared skill type (see §7) that is missing or empty zeroes out the evidence gate, which zeroes the composite score regardless of verdict correctness.

## 9. Updating

Auto-update (Watchtower):

```bash
cd ~/phylax/miner
docker compose --profile auto-update up -d
```

Manual:

```bash
cd ~/phylax/miner
docker compose pull && docker compose up -d
```

## 10. Tuning

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_TIMEOUT` | `60` | Per-detonation timeout (seconds). |
| `PHYLAX_LOG_LEVEL` | `INFO` | Stdlib logger level. |
| `PHYLAX_EVIDENCE_DIR` | `/opt/phylax/evidence` | In-container evidence path (do not change). |
| `PHYLAX_EVIDENCE_HOST_DIR` | set by `install.sh` | Host-side absolute path of the bind mount. Required for docker-in-docker. |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Image launched by runtime harnesses. **Must equal the `image_uri` you registered at `/v1/specialization/register`.** |
| `PHYLAX_SANDBOX_DIGEST` | _empty_ | The `sha256:...` digest of `PHYLAX_SANDBOX_IMAGE`. **Must equal the `image_hash` you registered.** Used in the `sandbox_manifest` sent on each response. |
| `PHYLAX_TRACER_VERSION` | `1.0.0` | Version string of your tracer (informational). |
| `PHYLAX_KERNEL` | _empty_ | Optional kernel identifier for the `sandbox_manifest`. |
| `PHYLAX_CPU_ARCH` | _empty_ | Optional CPU arch (e.g. `x86_64`) for the `sandbox_manifest`. |
| `DOCKER_GID` | set by `install.sh` | Host docker group GID. |
| `HOST_UID` / `HOST_GID` | set by `install.sh` | Your shell user's UID/GID. |
| `AXON_PORT` | `8091` | Host port mapped to the miner axon. |
| `PHYLAX_IMAGE_TAG` | `latest` | Pin to `sha-<short>` for reproducible deploys. |

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Container exits immediately | Hotkey not found | `ls ~/.bittensor/wallets/<WALLET_NAME>/hotkeys/<WALLET_HOTKEY>` |
| Registered on netuid 1 not 486 | `PHYLAX_NETUID` left at default | Set to `486`, `docker compose up -d --force-recreate`. |
| No `scan:` lines after 5 minutes | Not registered with phylax-server, or axon unreachable | Re-do step 5; check inbound 8091. |
| Validator dials `0.0.0.0:8091` | Miner + validator on same host | Run on different hosts. |
| Specialization registration rejected: "at least two skill types" | Declared only one | Add another type. |
| Specialization registration rejected: "needs at least one type with base_weight >= 1.0" | All declared types are RAG / declarative | Add one of `executable_python`, `executable_script`, `mcp_server`, `agent_composition`. |
| Sandbox produces only `log.txt` | Bind mount misconfigured | Re-run `scripts/install.sh` or set `PHYLAX_EVIDENCE_HOST_DIR` to the absolute host path. |
| `permission denied while trying to connect to the docker API` | Container UID not in host docker group | Confirm `DOCKER_GID` matches `getent group docker`. |
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` reachability from inside the container. |
| Sandbox timeouts | Heavy bundle | Bump `SANDBOX_TIMEOUT`. |
