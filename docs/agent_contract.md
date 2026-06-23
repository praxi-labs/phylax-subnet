# Agent Contract & Artifact Reference

A Phylax agent is the artifact a miner submits. The miner runs it live on each
dispatched task, signs the resulting SSSA with its hotkey, and submits it. The
validator independently reruns a sampled subset in the miner's registered image
to audit that verdicts hold up. This document defines the entrypoint, the context
it receives, what it must do per track, and the artifact layout it will see.

## Entrypoint

```python
def agent_main(context: dict) -> dict:
    ...
    return sssa   # the SSSA envelope (see sssa_schema.md)
```

- The function name defaults to `agent_main`; override via the `entrypoint`
  field at submission.
- It receives one `context` dict and returns the SSSA envelope as a plain dict
  (`verdict`, `evidence`, `findings`; leave `attestation.signature` empty).
- It runs inside the registered sandbox image, network-jailed: the only reachable
  endpoint is the inference proxy.

## Context

```json
{
  "artifact_dir": "/task/artifact",
  "track": "skills | mcp_servers | packages | repositories",
  "nonce": "…",
  "probe": { "file_path": "/skill/.probe_…", "file_content": "…",
             "dns_host": "….probe.phylax.ai", "process_echo": "…", "canary": "…" },
  "inference": { "api": "<proxy url>", "api_key": "…", "provider": "…", "model": "…" },
  "sandbox": { "image": "…", "digest": "sha256:…" }
}
```

- `artifact_dir`: the extracted artifact, mounted read-only.
- `probe`: the nonce-derived effects your sandbox must perform (detonation
  tracks). You must write `file_path`, resolve `dns_host`, and echo
  `process_echo`, then report them under `evidence.proof_of_execution`.
- `inference`: call the LLM only via `inference.api` (the metered proxy). Direct
  egress is blocked.

## Proof-of-execution (detonation tracks)

The validator confirms, independently and in the captured traces, that the probe
fired. If the probe is absent or mismatched, the evidence gate fails and the
score is 0. Report:

```json
"proof_of_execution": {
  "probe_evidence": { "file_write": "<probe.file_path>", "dns_lookup": "<probe.dns_host>",
                      "process_echo": "<probe.process_echo>", "canary": "<probe.canary>" },
  "traces": { "filesystem": {"hash":"","events":[…]},
              "network":    {"hash":"","events":[…]},
              "process":    {"hash":"","events":[…]} }
}
```

## Per-track responsibilities

### skills
Detonate the skill, thread the probe, and produce dual-plane evidence:
`action_plane.capabilities` (canonical names) and
`context_plane.injected_instructions` (prompt-injection / hidden overrides /
unicode anomalies). Decide `ALLOW`/`WARN`/`BLOCK`.

### mcp_servers
Same as skills, plus an `mcp_surface` block: enumerate exposed tools, compare
declared schema vs observed behaviour, and flag tool poisoning / manifest tamper.

### packages
Detonate across the lifecycle: capture `install_time` and `import_time`
behaviour, plus a `supply_chain` block (SBOM, dependency CVEs, typosquat,
dependency confusion).

### repositories
No probe, no detonation. Audit the source statically and return
`evidence.audit` + `evidence.vulnerabilities` (CWE, file, line, severity,
remediation). Scored by recall against the benchmark's known vulnerabilities.

## Artifact layout the agent will see

These mirror the corpus under `corpora/<track>/`:

| Track | Typical contents of `artifact_dir` |
|---|---|
| `skills`        | `SKILL.md` + helper scripts (e.g. `scripts/*.py`) |
| `mcp_servers`   | `manifest.json` + `server.py` |
| `packages`      | `setup.py` / `pyproject.toml` + `src/<pkg>/…` |
| `repositories`  | a source tree (`src/…`, `requirements.txt`, …) |

Do not assume a fixed entry filename. Discover the surface from the manifest
(`manifest.json`, `pyproject.toml`, `SKILL.md`) or by scanning.

## Output

Return the SSSA envelope documented in [sssa_schema.md](sssa_schema.md). Report
**canonical capability names** (see [scoring.md](scoring.md)); fabricated or
off-track names do not raise evidence integrity. The reference implementation is
`phylax/harness/skills_reference_agent.py`.
