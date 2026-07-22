# Agent contract

An agent is the code a miner builds and submits. Validators execute it inside
their own hardened sandbox image (`PHYLAX_SANDBOX_IMAGE`), so untrusted code runs
in a trusted runtime and every run is reproducible everywhere.

## Entrypoint

```python
def agent_main(context: dict) -> dict:
    return {
        "verdict": {"decision": "ALLOW | WARN | BLOCK", "risk_score": 0, "confidence": 0.0},
        "evidence": {},
        "findings": [],
        "policy": {},
    }
```

- The function name defaults to `agent_main`; override via the `entrypoint`
  field of the submission.
- It runs network jailed. The only reachable endpoint is the inference proxy in
  `context["inference"]["api"]`.
- A crash, timeout, or malformed return is a failed run and scores zero for that
  task.

## The context

```json
{
  "artifact_dir": "/task/artifact",
  "track": "skills | mcp_servers | packages | repositories",
  "nonce": "…",
  "probe": { "file_path": "/task/workspace/.probe_…", "file_content": "…",
             "dns_host": "….probe.phylax.ai", "process_echo": "…", "canary": "…" },
  "inference": { "api": "<proxy url>", "api_key": "…", "provider": "…", "model": "…" },
  "sandbox": { "image": "…", "digest": "sha256:…" }
}
```

The nonce and probe are derived from the round seed, so they are unknowable
before the round starts. On the detonation tracks the agent must thread the probe
(write the file, resolve the host, echo the token); the probe file is checked by
the validator's executor after the run, from outside the container, so skipping
it zeroes the run. The `repositories` track has no probe.

## Scoring interface

The verdict's `risk_score` (0 to 100) is what correctness is measured on: the
validator scores `1 - |risk/100 - label|` against ground truth. Evidence must
follow the track's schema ([sssa_schema.md](sssa_schema.md)); capabilities must
use canonical taxonomy names or they are dropped. Each task is run several times
and must be correct consistently, so keep the agent deterministic.

## Limits

| Limit | Value |
|---|---|
| Wall clock | the per track timeout: 8 s skills, 15 s mcp_servers, 30 s packages, 120 s repositories |
| Size | 512 KB of agent code by default |
| Network | none, except the metered inference proxy |
| Resources | memory, CPU, and PID caps in the jail |

## Reference agent

`phylax/harness/reference_agent.py` (unified across all four tracks) threads the
probe, scans both evidence planes, and returns a valid attestation body. Copy it
and improve on detonation depth and context plane precision.
