# Skill Bundle Reference
## Version 2.0

A skill bundle is the zipped artifact a developer publishes for analysis. Phylax-server stores bundles in its corpus and dispatches them to validators, who forward them to miners inside `PhylaxSynapse`. Every bundle is content-addressed by `sha256(bundle_bytes)`.

A bundle's structure depends on its `skill_type`. The validator tags each task with the skill type at dispatch, and the miner routes to the harness for that type. This document covers the expected layout per type, what canary and probe artifacts the validator embeds, and what `SKILL.md` looks like when present.


## 1. Common Bundle Conventions

| Property | Notes |
|---|---|
| Format | ZIP archive. The miner extracts to a working directory. |
| Identifier | `sha256:<64 hex>` of the bundle bytes. Always declared on the synapse as `skill_bundle.bundle_hash`. The miner must verify the bytes match the hash before doing anything. |
| Maximum size | The miner enforces 256 MB total uncompressed, 64 MB per member. Symlinks and zip-slip paths are rejected. |
| Skill type | Declared on the synapse in `skill_bundle.metadata.skill_type`. Always one of the six values listed below. |
| Profile | `fast`, `standard`, or `deep`. Determines the timing window for the miner's response. |

The skill type tells the miner which harness to dispatch to. Bundle members the harness ignores are simply not analysed.


## 2. Bundle Layouts Per Skill Type

### 2.1. `rag_knowledge`

A document set used to ground an agent's responses through retrieval. No executable code.

Typical contents:

```
my-rag-bundle/
├── doc1.md
├── doc2.txt
├── docs/
│   ├── policy.md
│   └── manual.pdf
└── SKILL.md           (optional, metadata only)
```

What the miner analyses:

- All files with `.md`, `.markdown`, `.txt`, `.rst`, `.html`, `.htm`, `.pdf` extensions.
- Patterns: HTML comment injection, fake system prompts, hidden CJK characters, embedded URLs, embedded code fences.

What the validator embeds:

- A canary marker of the form `CANARY_<canary_id>` appended to one randomly chosen document. The miner reports `canary_id_found = true` if it observes this marker.
- The probe events (file write, DNS lookup, process spawn) are emitted by the miner's harness as part of analysis; they appear in the trace files for runtime types only, not for `rag_knowledge`.

The miner's `rag_content_fingerprint` must be computed over all documents in the bundle as delivered, including the canary-injected document.


### 2.2. `declarative`

Natural-language instructions for an agent. No executable code. `SKILL.md` is effectively the entire bundle.

Typical contents:

```
my-declarative-bundle/
└── SKILL.md
```

A `SKILL.md` for a declarative bundle is a markdown document declaring what the agent should do, how it should behave, and what it should refuse. See section 3 for the conventional structure.

What the miner analyses:

- Pattern matches against prompt-injection regex banks (e.g. `ignore previous instructions`, `you are now`, `system:`, `DAN`, etc.).
- Unicode anomaly detection: zero-width characters, bidi overrides, Cyrillic homoglyphs.
- Embedded HTML comment instructions.
- Base64 blobs.

What the validator embeds:

- A canary comment of the form `<!-- CANARY: {canary_id} -->` injected into the SKILL.md at a position that does not affect the document's apparent meaning (typically after the second section heading).
- The miner reports `canary_id_found = true` if it finds the comment.
- The miner reports `skill_md_fingerprint` as `sha256` of the SKILL.md content as delivered (with the canary present).


### 2.3. `executable_python`

A Python skill that runs against an interpreter at runtime.

Typical contents:

```
my-python-skill/
├── main.py              (entry point)
├── requirements.txt     (or pyproject.toml)
├── setup.py             (optional)
├── lib/
│   └── helpers.py
└── SKILL.md             (optional)
```

What the miner analyses:

- Static: AST walking, dangerous API patterns, prompt-injection signatures, permission discrepancies.
- SBOM: dependency graph, typosquat detection, install-hook scan, CVE lookup.
- Dynamic: Docker sandbox detonation, `sys.audit`-traced fs / network / process / secrets / imports events.

What the validator embeds:

- The canary value `CANARY_VAL` and the probe values are passed as environment variables (`CANARY_ID`, `CANARY_VAL`, plus probe-derived values).
- The miner's harness writes the canary value to `/skill/.canary` before launching the skill. The miner's tracer records this filesystem op in `fs.jsonl`.
- The miner's harness also performs the three probe events (probe file write, DNS lookup, `echo` of the probe token) and records them in `fs.jsonl`, `network.jsonl`, and `process.jsonl`.

Bundle bytes are not modified for runtime types. The canary and probe arrive via environment variables, not by editing the bundle itself.


### 2.4. `executable_script`

A shell script skill (`.sh`, `.bash`, `.zsh`).

Typical contents:

```
my-script-skill/
├── main.sh
├── helpers/
│   └── lib.sh
└── SKILL.md             (optional)
```

What the miner analyses:

- Static taint: line-by-line classification of dangerous patterns (`pipe_to_shell`, `remote_fetch`, `eval`, `chmod_exec`, `cron_persistence`, `destructive_rm`, `netcat_shell`, `ssh_key_touch`).
- Syntax check via `bash -n`.
- Dynamic: Docker sandbox detonation with shell-command tracing.

Validator embeds: same as `executable_python` (env vars + canary file + probe events in trace files).


### 2.5. `mcp_server`

A Model Context Protocol server. Exposes tools an agent can invoke.

Typical contents:

```
my-mcp-skill/
├── manifest.json        (MCP tool manifest)
├── server.py            (or whatever language)
├── handlers/
│   ├── tool1.py
│   └── tool2.py
└── SKILL.md             (optional)
```

What the miner analyses:

- Static: tool description scan for tool-poisoning signatures, shadowing detection, rug-pull detection (mutable remote tools).
- Manifest integrity: `sha512` of the canonical manifest as served at runtime.
- Dynamic: start the MCP server in one container, connect a test MCP client in another, enumerate all declared tools, invoke each with synthetic parameters, capture the tool calls.

Validator embeds:

- Env vars `CANARY_ID`, `CANARY_VAL`.
- The miner's MCP client includes `CANARY_VAL` as a parameter value in at least one synthetic tool invocation. That record must appear in `tool_calls.jsonl`.
- The three probe events appear in the base trace files (`fs.jsonl`, `network.jsonl`, `process.jsonl`).


### 2.6. `agent_composition`

A composition manifest orchestrating multiple child skills.

Typical contents:

```
my-composition/
├── composition.yaml     (or composition.json)
├── children/
│   ├── child1/
│   │   └── ...
│   └── child2/
│       └── ...
└── SKILL.md             (optional)
```

The `composition.yaml` declares a graph of child skills and how they invoke each other.

```yaml
name: research_assistant
version: 1.0.0
parent:
  name: orchestrator_agent
  invokes:
    - skill: web_search
    - skill: summarizer
children:
  - skill: web_search
    bundle_hash: sha256:abc...
  - skill: summarizer
    bundle_hash: sha256:def...
```

What the miner analyses:

- Parses the composition manifest.
- Resolves all declared child skill dependencies.
- Builds a dependency graph and detects cycles.
- Spins up containers for parent plus all children, observes inter-skill communication.
- Captures cascading traces across all containers (aggregated into the same four base trace files plus `agent_calls.jsonl`).
- Computes a transitive risk score from child verdicts propagated upward.

Validator embeds:

- Env vars `CANARY_ID`, `CANARY_VAL`, plus `COMPOSITION_DEPTH`.
- `CANARY_VAL` is injected into the parent skill's input context. If composition is honest, the canary should propagate through child agents and appear in `agent_calls.jsonl`.
- Probe events appear in the aggregated base trace files.


## 3. SKILL.md (Optional Metadata)

`SKILL.md` is the conventional documentation file inside a bundle. For `declarative` bundles it is the entire bundle. For all other types it is optional but recommended. Phylax does not require its presence.

### Conventional structure

A `SKILL.md` is a markdown file at the bundle root. Frontmatter (YAML) is optional. The document body is free-form developer documentation.

```markdown
---
name: weather-api
version: 1.2.3
description: Fetches current weather from Weather.com
---

# Weather Skill

Free-form description, usage examples, how the skill is expected to behave.
```

### What miners may extract from SKILL.md

Per-type harnesses may parse SKILL.md for additional signals:

| Type | What SKILL.md is used for |
|---|---|
| `rag_knowledge` | Included in the document set scanned for hidden instructions. |
| `declarative` | The primary input. Analysed for prompt injection, unicode anomalies, canary marker. |
| `executable_python` / `executable_script` | Documentation only. No effect on scoring. |
| `mcp_server` | Documentation only. Tool definitions come from `manifest.json` served at runtime. |
| `agent_composition` | Documentation only. Composition definition comes from `composition.yaml`. |

### Why SKILL.md is no longer a capability declaration

In Phylax v0.3, `SKILL.md` was a capability contract: it declared what network egress, filesystem reads, env vars, etc., the skill would do at runtime. The validator compared the declaration against observed behaviour and scored the discrepancy.

That model is replaced in v2.0. The miner's per-type harness directly analyses observed behaviour and reports it in the SSSA. The validator's expected-behaviour ground truth comes from the corpus row (server-curated `expected_capabilities`, `expected_policy`, `expected_findings`), not from a developer-supplied manifest. SKILL.md remains useful as documentation but no longer drives the verdict.


## 4. Bundle Integrity

| Check | When |
|---|---|
| `sha256(bundle_bytes) == skill_bundle.bundle_hash` | Miner verifies on receipt. Mismatch is an immediate failure. The miner returns `synapse.error` populated. |
| ZIP structure | Miner rejects symlinks, members larger than 64 MB, total uncompressed over 256 MB, and any path that escapes the extraction root (zip-slip). |
| Canary verification | After analysis, the miner's evidence block reports `canary_id_found` (rag, declarative) or includes the canary path in `fs.jsonl` (runtime types). |
| Probe verification | All miners (primary and auditor) populate `synapse.probe_evidence` with the nonce-derived values. Runtime primaries must also have the probe events present in their trace files. |


## 5. Tooling Status

The v0.3 `phylax manifest init` and `phylax manifest check` CLI tools are no longer shipped. The capability-declaration model they targeted is no longer the scoring mechanism. If you publish skills for Phylax analysis:

- For `declarative` bundles: ship a clean `SKILL.md` describing the agent's intended behaviour. The validator will inject canaries into it at dispatch time.
- For runtime bundles (`executable_python`, `executable_script`, `mcp_server`, `agent_composition`): focus on writing reproducible, deterministic skill code. Behaviour is observed by sandbox detonation, not declared. Document anything else in a freeform `SKILL.md` if you want.
- For `rag_knowledge` bundles: include the documents you intend to surface through retrieval. The miner fingerprints them as a set.

Tooling for bundle authoring may return in a later release. For now, bundles are constructed manually or by your build pipeline.
