# Phylax Miner Guide
## netuid 486 (testnet)

## Overview

A Phylax miner registers a Bittensor axon on netuid 486 and responds to `PhylaxSynapse` requests from validators. Each request contains a skill bundle to analyse. You run your analysis pipeline on that bundle and return a signed SSSA (Signed Skill Safety Attestation).

The subnet team defines the structural contract: what inputs you receive, what outputs you must produce, and how your submission is scored. Your internal analysis pipeline is entirely your own. That is where you compete.


## Requirements

- Docker 24+ with the compose plugin (`docker compose version` must work)
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli))
- 16 GB RAM, 4+ CPU cores, 80 GB free disk
- Inbound TCP port **8091** open to the public internet
- Your shell user in the docker group: `sudo usermod -aG docker $USER && newgrp docker`


## 1. Create Wallet and Register

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


## 2. Install and Configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s miner
```

This drops the install layout at `~/phylax/miner/`:

```
~/phylax/miner/
├── docker-compose.yml
├── .env                ← edit this
├── evidence/           ← bind mount for sandbox traces
└── src/                ← full source clone
    └── scripts/        ← helper scripts (build-sandbox.sh, register.sh, register_miner.py)
```

Edit `~/phylax/miner/.env` and set every key in the table below. **Add any key that is not already in the file.** The shipped `.env.example` leaves the miner-specific keys blank on purpose so the registration script can flag them by name. The miner will not start, register, or score without all of these:

| Variable | What to set | Where it comes from |
|---|---|---|
| `PHYLAX_NETUID` | `486` | testnet |
| `SUBTENSOR_NETWORK` | `test` | testnet |
| `WALLET_NAME` | folder name in `~/.bittensor/wallets/` | `btcli wallet create` step |
| `WALLET_HOTKEY` | `default` (or the hotkey you registered) | `btcli wallet create` step |
| `PHYLAX_SERVER_URL` | `https://api.phyi.dev` | testnet coordinator |
| `PHYLAX_SERVER_HOTKEY` | `a53f8e390446e31cd077517e44e585c0e0474bbd5b1db5864c52fb07bcbe541c` | pinned anti-impersonation key |
| `PHYLAX_SUPPORTED_TYPES` | comma list, e.g. `executable_python,declarative` | which types you'll serve (see step 3) |
| `PHYLAX_SANDBOX_IMAGE` | e.g. `docker.io/<you>/phylax-sandbox-python:v1` | set after step 5 |
| `PHYLAX_SANDBOX_DIGEST` | `sha256:...` of the image above | set after step 5 |

Optional but useful:

| Variable | Default | Description |
|---|---|---|
| `PHYLAX_MIN_PROFILE` | `standard` | Lowest task profile you'll accept |
| `PHYLAX_MAX_CONCURRENT_TASKS` | `2` | Throttle concurrent dispatches |
| `PHYLAX_TIER_CLAIM` | `reference` | Informational. Real tier is set by your scores. |


## 3. Choose Your Skill Types

You decide which skill types to support. No one assigns them. Pick what you have the infrastructure and expertise to do well. Declaring a type you cannot serve drops your reputation for that type and you stop receiving its tasks.

| Skill type | What the bundle contains | What your harness must do |
|---|---|---|
| `rag_knowledge` | Documents, knowledge-base content. No code. | Content-only scan. No sandbox. Compute document fingerprint, detect hidden instructions, enumerate embedded URLs, find the canary. |
| `declarative` | A `SKILL.md` of natural-language instructions. No code. | Static text analysis. No sandbox. Compute `skill_md_fingerprint`, run your prompt-injection classifier (offline only, not a live LLM), detect Unicode anomalies, find the canary. |
| `executable_python` | Python source + dependency manifests. | Static analysis + SBOM + Docker sandbox detonation. Emit four base traces + `imports.jsonl`. Thread the canary through the sandbox. |
| `executable_script` | Shell scripts. | Static shell taint analysis + Docker sandbox detonation. Emit four base traces + `shell_commands.jsonl`. |
| `mcp_server` | A Model Context Protocol server: handlers + manifest. | Two containers (server + your test client). Enumerate and exercise all tools, one invocation carrying the canary. Emit four base traces + `tool_calls.jsonl`. Compute `mcp_manifest_hash`. |
| `agent_composition` | A composition manifest orchestrating child skills. | Multi-container cascading detonation across parent and all children. Emit aggregated four base traces + `agent_calls.jsonl`. Compute dependency graph hash and transitive risk score. |

Two rules apply when you register your specialization:

- `declarative` is mandatory and automatic. Every miner declares it. The register helper and the server both inject it for you. You only put the EXTRA types in `PHYLAX_SUPPORTED_TYPES`.
- You must declare at least one other type, and `rag_knowledge` does not count on its own. So `PHYLAX_SUPPORTED_TYPES` must contain at least one of: `executable_python`, `executable_script`, `mcp_server`, `agent_composition` (or `rag_knowledge` plus one of those four).


## 4. Build Your Pipeline

The reference repo ships a working harness for every skill type. Each harness satisfies the structural contract out of the box and earns Tier 1 (Reference) emissions. Replacing the internals with your own analysis logic is how you reach Tier 2 (Optimised) or Tier 3 (Novel) and earn more.

All paths below are relative to `~/phylax/miner/`. For each skill type you chose, open the corresponding runner and container files and build your analysis logic inside them.

| Skill type | Runner file to edit | Sandbox container to edit |
|---|---|---|
| `rag_knowledge` | `src/phylax/harness/rag_knowledge/runner.py` | none |
| `declarative` | `src/phylax/harness/declarative/runner.py` | none |
| `executable_python` | `src/phylax/harness/executable_python/runner.py` | `src/phylax/harness/executable_python/container/` |
| `executable_script` | `src/phylax/harness/executable_script/runner.py` | `src/phylax/harness/executable_script/container/` |
| `mcp_server` | `src/phylax/harness/mcp_server/runner.py` | `src/phylax/harness/mcp_server/container/` |
| `agent_composition` | `src/phylax/harness/agent_composition/runner.py` | `src/phylax/harness/agent_composition/container/` |

Each runner exposes a `run(bundle_dir, nonce, canary_id, canary_val)` method. As long as your replacement returns the same dataclass shape and emits the required trace files into the evidence directory, the miner glue code does not care what is inside.

For runtime types (`executable_python`, `executable_script`, `mcp_server`, `agent_composition`) the runner launches a Docker container that you control. The container must follow this contract:

- Entrypoint: `/harness/run.sh <bundle_path> <nonce>`
- Env vars injected by the runner: `CANARY_ID`, `CANARY_VAL`, `AGENT_TIMEOUT`
- All required JSONL trace files written to `/evidence/` which is bind-mounted by the runner


## 5. Build and Tag Your Sandbox Image

You'll need to be logged into your container registry first. Any public registry works (Docker Hub, GHCR, Quay, ECR Public).

```bash
docker login                       # Docker Hub
# or:  docker login ghcr.io        # GitHub Container Registry
# or:  docker login quay.io
```

The namespace in your image tag must match the username you logged in with. `docker.io/alice/<repo>` can only be pushed by `alice`. Mismatched namespace produces `push access denied ... insufficient_scope`.

Then run the helper script:

```bash
cd ~/phylax/miner
./src/scripts/build-sandbox.sh executable_python docker.io/<you>/phylax-sandbox-python:v1
```

It builds the Dockerfile at `src/phylax/harness/<skill>/container/Dockerfile`, pushes it, and prints both the image URI and its `sha256:` digest. Paste both into `.env`:

```bash
PHYLAX_SANDBOX_IMAGE=docker.io/<you>/phylax-sandbox-python:v1
PHYLAX_SANDBOX_DIGEST=sha256:<digest from the helper output>
```

Repeat for each runtime skill type you plan to declare. `rag_knowledge` and `declarative` do not need sandbox images.

For GHCR specifically, after the first push you must mark the package as **Public** on the GitHub UI, otherwise validators get 403 when they try to pull. Docker Hub repos are public by default for free accounts.

Verify your image is anonymously pullable before moving on:

```bash
docker logout
docker pull docker.io/<you>/phylax-sandbox-python:v1     # should succeed with no creds
docker login                                              # log back in for next time
```


## 6. Register Your Specialization

The coordinator only routes tasks to miners with a current specialization on file. The helper script reads your `.env`, signs the request with your hotkey, and POSTs it.

First-time only, install the signing dependency:

```bash
pip3 install --user substrate-interface
```

Then register:

```bash
cd ~/phylax/miner
./src/scripts/register.sh
```

Expected output:

```
==> POST https://api.phyi.dev/v1/specialization/register
    hotkey: 5DLAsRvT...
    types:  ['executable_python', 'declarative']
    image:  docker.io/<you>/phylax-sandbox-python:v1
    digest: sha256:abc123...
==> 200 OK
{"hotkey":"...","supported_types":[...],"sandbox_images":{...},"reputation":{...}}
```

Re-run this whenever you change `PHYLAX_SUPPORTED_TYPES` or rebuild the sandbox image.

If you serve multiple runtime types and use a different image per type, edit `.env` between runs (set `PHYLAX_SUPPORTED_TYPES` to one type and update image/digest), then call `./src/scripts/register.sh` after each.

Common errors:

| Error | Cause |
|---|---|
| `PHYLAX_SUPPORTED_TYPES is not set` | Add the line to `.env`. |
| `401 invalid signature` | `.env` `WALLET_NAME`/`WALLET_HOTKEY` doesn't match the wallet you registered on chain. |
| `403 hotkey not on allowlist` | Coordinator operator hasn't added your hotkey. |
| `400 sandbox_image must be sha256:` | Your `PHYLAX_SANDBOX_DIGEST` is missing the `sha256:` prefix. |


## 7. Run

```bash
cd ~/phylax/miner
docker compose pull
docker compose up -d
docker compose logs -f
```

Within about 30 seconds you should see:

```
Axon serving on [::]:8091
```

When a validator dispatches a task:

```
scan: bundle=sha256:... type=executable_python profile=standard task=...
scan done: sha256:... -> ALLOW risk=12
```


## 8. What You Receive and What You Must Return

### What the Validator Sends You

Every `PhylaxSynapse` your axon receives contains:

| Field | Description |
|---|---|
| `skill_bundle.bundle_bytes` or `bundle_url` | The skill bundle to analyse |
| `skill_bundle.bundle_hash` | SHA256 you must verify before doing anything |
| `skill_bundle.metadata.skill_type` | Which of the six types to dispatch to |
| `skill_bundle.metadata.profile` | `fast`, `standard`, or `deep` |
| `nonce` | Canary seed. Thread this into your sandbox. |
| `task_metadata.role` | `primary` or `auditor`. The validator assigns this. |
| `task_metadata.deadline_s` | Seconds you have to respond |
| `task_metadata.t_min_s` | Minimum seconds before you may respond |

### Your Role Per Task

The validator assigns your role per task per round. You do not choose it.

**Primary** (3 per task, picked from highest reputation for that skill type): full pipeline. Sandbox detonation, full SSSA, trace_bundle, sandbox_manifest, probe_evidence. Full emission.

**Auditor** (2 per task, picked randomly from remaining declared miners): full SSSA including verdict, findings, capabilities, dependencies, and policy, but no trace_bundle or sandbox_manifest required. Tighter deadline. Earns 0.6 times primary emission multiplied by consensus score.

If you have been an auditor for the same skill type three rounds in a row, you are rotated into the primary slot regardless of reputation rank.

### What You Must Return

Return the same `PhylaxSynapse` with these fields populated:

**1. `attestation`** (always required, primary and auditor)
The signed SSSA. Full structure described in the next section.

**2. `probe_evidence`** (always required, primary and auditor)
A dict `{file_path, file_content, dns_host, process_echo}` derived from the nonce. For runtime skill types your harness must also perform these three events inside the sandbox so they appear in `fs.jsonl`, `network.jsonl`, and `process.jsonl`.

**3. `trace_bundle`** (required for runtime primaries only)
`dict[str, str]` of `{filename: base64(gzip(jsonl_bytes))}`.

| Skill type | Required files in trace_bundle |
|---|---|
| `executable_python` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `imports.jsonl.gz` |
| `executable_script` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `shell_commands.jsonl.gz` |
| `mcp_server` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `tool_calls.jsonl.gz` |
| `agent_composition` | `network.jsonl.gz`, `fs.jsonl.gz`, `process.jsonl.gz`, `secrets.jsonl.gz`, `agent_calls.jsonl.gz` |
| `rag_knowledge` | Omit trace_bundle entirely |
| `declarative` | Omit trace_bundle entirely |

Size limits per compressed file: `network` 5MB, `fs` 10MB, `process` 5MB, `secrets` 1MB, `imports` 2MB, `shell_commands` 5MB, `tool_calls` 5MB, `agent_calls` 10MB. Total bundle must not exceed 30MB. Exceeding any limit means the response is treated as missing.

**4. `sandbox_manifest`** (required for runtime primaries only)

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

`image` and `digest` must match exactly what you registered in step 6.


## 9. The SSSA Structure

Your attestation field must contain a valid SSSA with these sections.

**`skill`** identifies the bundle you analysed:
`name`, `bundle_hash`, `skill_type`, `profile`, `schema_version`

**`verdict`** is your analysis conclusion:
`decision` (ALLOW | WARN | BLOCK), `risk_score` (0-100), `confidence` (0-1), `verdict_sources` (list of layer strings)

**`capabilities`** describes what the skill does:
`filesystem.reads/writes`, `network.domains/ips/ports`, `process_spawns`, `secrets_access`, `shell_commands`, `tool_calls`, `child_skills`

**`findings`** is a list of issues found:
Each finding contains `finding_id`, `severity`, `title`, `description`, `owasp_ref`, `mitre_ref`, `evidence_snippet`, `layer_source`, `finding_type`

**`dependencies`** covers supply chain analysis:
`sbom_hash`, `high_risk_packages`, `known_cves`, `install_hooks`, `mcp_manifest_hash`, `child_skill_verdicts`

**`recommended_policy`** is the suggested runtime sandbox policy:
`egress_allow/deny`, `fs_read/write`, `shell_access`, `max_memory_mb`, `timeout_s`, `env_allowlist`, `tool_allowlist`, `child_skill_allowlist`

**`evidence`** is your proof of work.

Base hashes (all runtime types): `network_trace_hash`, `fs_trace_hash`, `process_trace_hash`, `secrets_trace_hash`

Type-specific required evidence fields:

| Skill type | Required fields |
|---|---|
| `rag_knowledge` | `rag_content_fingerprint`, `hidden_instruction_score`, `embedded_urls`, `document_count`, `canary_id_found` |
| `declarative` | `canary_id_found`, `findings_count`, `skill_md_fingerprint`, `prompt_injection_ml_score`, `unicode_anomaly_detected`, `layer0_sync_hash` |
| `executable_python` | `imports_trace_hash` plus four base hashes |
| `executable_script` | `shell_commands_hash` plus four base hashes |
| `mcp_server` | `tool_calls_hash`, `mcp_manifest_hash`, `tool_poisoning_score`, `tool_shadowing_detected`, `rug_pull_risk` plus four base hashes |
| `agent_composition` | `agent_calls_hash`, `dependency_graph_hash`, `transitive_risk_score`, `composition_depth_observed` plus four base hashes |

**`attestation`** is your signature:
`miner_hotkey` (your ss58 address), `supported_types_declared`, `ed25519_signature` (hex sig over sha256 of canonical SSSA body excluding this field, keys sorted alphabetically, no whitespace, UTF-8), `timestamp` (ISO-8601 UTC), `schema_version`, `skill_type_version`


## 10. Canary Handling

Every task carries a `canary_id` and `canary_val` derived from the nonce. You must handle them correctly or your evidence score is zero.

| Skill type | What to do with the canary |
|---|---|
| `rag_knowledge` | Compute `rag_content_fingerprint` over the documents exactly as delivered. Scan for `CANARY_<canary_id>` in content and set `canary_id_found` accordingly. |
| `declarative` | Scan SKILL.md for `<!-- CANARY: {canary_id} -->`. Set `canary_id_found = true` when found. Compute `skill_md_fingerprint` over SKILL.md exactly as delivered. |
| `executable_python` / `executable_script` | Thread `canary_val` into the sandbox as the `CANARY_VAL` env var. Have your harness write it to `/skill/.canary` before launching the skill. Your tracer must record this filesystem op in `fs.jsonl`. |
| `mcp_server` | Include `canary_val` as a parameter value in at least one synthetic tool invocation. The record must appear in `tool_calls.jsonl`. |
| `agent_composition` | Inject `canary_val` into the parent skill's input context before detonation. The propagation must appear in `agent_calls.jsonl`. |


## 11. Hard Rules

Break any of these and your SSSA scores zero for that task.

**No LLM for analysis.** Using a live LLM to decide the verdict, score prompt injection, classify tool poisoning, or analyse skill content is forbidden. The verdict and all scores must come from deterministic analysis your harness performs. LLMs are only permitted for post-analysis enrichment with one of these allowed uses: `finding_enrichment`, `mitre_owasp_mapping`, or `cve_explanation`. If your SSSA includes `llm_evidence`, its `allowed_use` must be one of these three values.

**No skill_type mismatch.** Return an SSSA whose `skill.skill_type` differs from the task's `skill_type` and the response is treated as invalid.

**No early responses.** Return before `task_metadata.t_min_s` seconds and the response is treated as not having run the sandbox.

**No late responses.** Return after `task_metadata.deadline_s` seconds and the submission is discarded entirely with no score and no reputation update.

**No missing evidence.** Any required evidence field for your declared skill type that is absent or empty zeroes the evidence gate, which zeroes the composite score regardless of verdict correctness.


## 12. How the Validator Verifies You

**In the same round:**
The validator decompresses each trace file, normalises it (sort by `ts`, sorted keys, no whitespace), and sha256-hashes it. The computed hash must equal what you declared in the SSSA. It also scans your `fs.jsonl` for a write to `/skill/.canary` and checks your probe_evidence matches the nonce-derived probe events.

**Across your verification group:**
For each task the validator selects 5 miners: 3 primaries with the highest per_type_reputation and 2 auditors chosen randomly. All 5 analyse the same bundle independently. The validator then compares verdict, risk score, findings, capabilities, dependencies, and recommended policy across all submissions. Your consensus score is weighted: findings recall 30%, findings precision 15%, capabilities agreement 15%, verdict agreement 15%, dependencies agreement 10%, risk score agreement 10%, policy derivation 5%. This score multiplies your base emission score.

**Asynchronously for the next round:**
The validator pulls your registered sandbox image, verifies its digest matches your registration, and reruns it on the same bundle with the same nonce. It checks that `fs_trace_hash` matches exactly and that semantic agreement on other traces is at least 0.7. A pass adds +0.02 to your per_type_reputation. A fail multiplies it by 0.7.


## 13. Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `SANDBOX_TIMEOUT` | `60` | Per-detonation timeout in seconds |
| `PHYLAX_LOG_LEVEL` | `INFO` | Log level |
| `PHYLAX_EVIDENCE_HOST_DIR` | set by install.sh | Host-side absolute path of the evidence bind mount. Required for docker-in-docker. |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Image launched by runtime harnesses. Must match `image_uri` at registration. |
| `PHYLAX_SANDBOX_DIGEST` | (empty) | `sha256:...` digest of the sandbox image. Must match `image_hash` at registration. |
| `PHYLAX_TRACER_VERSION` | `1.0.0` | Tracer version string included in `sandbox_manifest` |
| `AXON_PORT` | `8091` | Host port for the miner axon |


## 14. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Container exits immediately | Hotkey not found | Check `~/.bittensor/wallets/<WALLET_NAME>/hotkeys/<WALLET_HOTKEY>` exists |
| No `scan:` lines after 5 minutes | Not registered with phylax-server or axon unreachable | Re-run step 6, check inbound 8091 |
| Specialization rejected: "at least two skill types" | Only one type declared | Add a second type |
| Specialization rejected: "needs base_weight >= 1.0" | Only `rag_knowledge` and/or `declarative` declared | Add one of `executable_python`, `executable_script`, `mcp_server`, or `agent_composition` |
| Specialization rejected: "missing sandbox_image" | Runtime type declared without sandbox image entry | Add `sandbox_images[<type>]` for every runtime type you declared |
| Sandbox produces only `log.txt` | Evidence bind mount misconfigured | Re-run `scripts/install.sh` or set `PHYLAX_EVIDENCE_HOST_DIR` to the correct absolute host path |
| `permission denied` connecting to Docker API | Container UID not in host docker group | Confirm `DOCKER_GID` matches `getent group docker` |
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` is reachable from inside the container |
| Sandbox timeouts | Heavy bundle or slow analysis | Increase `SANDBOX_TIMEOUT` |
| Score zero despite valid SSSA | Missing canary in traces | Confirm `/skill/.canary` write appears in `fs.jsonl` |
