# Phylax REST API

The control plane is the **phylax-server** (separate repo). Miners and validators
talk to it over HTTP; the subnet ships a signed client (`phylax/server_client.py`).
All mutating calls are authenticated by a hotkey signature over
`METHOD \n PATH \n TIMESTAMP \n BODY`, sent as `X-Phylax-Hotkey`,
`X-Phylax-Timestamp`, `X-Phylax-Signature` (`ed25519:<hex>`).

## Identity

### `GET /v1/server-identity`
Returns the server's pinned hotkey. Validators pin this (`PHYLAX_SERVER_HOTKEY`)
so a hijacked URL cannot impersonate the control plane.

## Miner endpoints (signed by the miner hotkey)

### `POST /v1/specialization/register`
Register a hotkey into one track.
```json
{ "hotkey": "5…", "registration_version": "2.0", "track": "skills", "label": "" }
```

### `POST /v1/specialization/agent`
Submit (or re-version) the agent. Requires the hotkey to be registered into a
track first.
```json
{
  "hotkey": "5…", "name": "",
  "code": "def agent_main(context): ...",
  "entrypoint": "agent_main",
  "execution_api_key": "cpk_… | sk-or-…",
  "inference_model": "",
  "sandbox": { "image_uri": "ghcr.io/you/agent:v1", "image_hash": "sha256:…" },
  "dependency_manifest": ""
}
```
Returns `{ agent_id, track, version, status, code_sha256, inference_provider,
inference_model, sandbox_image, sandbox_digest, created_at }`. Re-submitting
supersedes the previous active version.

### `DELETE /v1/specialization/agent/{hotkey}`
Withdraw the agent (stops dispatch).

## Validator endpoints (signed by the validator hotkey)

### `POST /v1/tasks/track/next`
Dispatch a task for a track.
```json
{ "track": "skills" }
```
Returns (or `null` when no work):
```json
{
  "task_id": "…", "track": "skills", "agent_hotkey": "5…",
  "artifact_ref": "sha256:…", "artifact_url": "https://…", "nonce": "…",
  "probe": { "file_path": "…", "file_content": "…", "dns_host": "…",
             "process_echo": "…", "canary": "…" },
  "is_benchmark": false, "deadline_at": "…"
}
```

### `GET /v1/specialization/agent/{hotkey}/runnable`
Fetch a miner's active agent to run.
```json
{
  "agent_id": "…", "track": "skills", "version": 3, "entrypoint": "agent_main",
  "code": "…", "execution_api_key": "…", "inference_provider": "chutes",
  "inference_model": "", "sandbox_image": "…", "sandbox_digest": "sha256:…",
  "dependency_manifest": ""
}
```

### `POST /v1/tasks/track/{task_id}/attestation`
Submit the verified SSSA for a dispatched task.
```json
{ "verdict": "BLOCK", "risk_score": 90, "evidence": { /* track evidence */ },
  "miner_signature": "ed25519:…" }
```
The server verifies the probe is present in the traces, scores the result, and
updates the agent's score. Returns `{ task_id, track, agent_hotkey, score,
evidence_gate_passed, capability_count, reason }`.

### `GET /v1/tasks/track/weights`
Top-3 per-track emission weights (no signature required).
```json
{
  "computed_at": "…",
  "weights": { "5HotkeyA…": 0.6, "5HotkeyB…": 0.3, "5HotkeyC…": 0.1 },
  "top_agents": [ { "hotkey": "5…", "track": "skills", "score": 0.82,
                    "attestations_count": 41 } ]
}
```
Validators fetch this, map hotkeys to UIDs, and call `set_weights`.

## Client

`phylax/server_client.py` wraps these: `register`, `register_track`,
`submit_agent`, `get_runnable_agent`, `dispatch_track_task`,
`submit_track_attestation`, `fetch_track_weights`.
