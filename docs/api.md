# Protocol & API

There are three surfaces. The **synapse protocol** is the decentralized core:
validator to miner over Bittensor. The **chain** carries registration and weights.
The **server API** is product work only and is not part of the protocol.

## Synapse protocol (validator to miner)

The validator and miner exchange Bittensor synapses, authenticated between their
hotkeys. The validator derives the nonce and probe itself, so every audit is
independent. The synapses are defined in `phylax/protocol.py`.

### `TaskSynapse` (validator to miner)

The validator sends the task; the miner fills in the signed SSSA and returns it.

```json
// sent by the validator
{ "track": "packages", "artifact_ref": "…", "artifact_b64": "…",
  "nonce": "…",
  "probe": { "file_path": "…", "file_content": "…", "dns_host": "…",
             "process_echo": "…", "canary": "…" } }
// returned by the miner (same synapse, response fields filled)
{ "sssa": { "track": "…", "artifact": {…}, "verdict": {…}, "evidence": {…},
            "findings": [], "attestation": { "miner_hotkey": "…", "signature": "ed25519:…", "canonical_hash": "sha256:…" } } }
```

For `repositories` the probe is omitted.

### `AgentSynapse` (validator to miner)

Used during the rerun audit. The validator asks the miner for its agent so it can
rerun it. The sandbox image is pulled by digest from the miner's public registry,
not served here.

```json
// returned by the miner
{ "code": "…", "entrypoint": "agent_main",
  "sandbox": { "image_uri": "…", "image_hash": "sha256:…" }, "inference_model": "…" }
```

The miner signs the SSSA over its canonical hash (see [sssa_schema.md](sssa_schema.md));
the validator verifies the signature against the answering hotkey before scoring.

## Chain surface

| Action | Who | Purpose |
|---|---|---|
| `subnet register` | miner, validator | claim a UID on netuid 486 |
| `stake add` | validator | hold a validator permit |
| `set_weights` | validator | publish per-track rankings; Yuma aggregates by stake |
| contributor-set commitment | subnet owner | publish the recognized-contributor set validators read for the 5% pool |

The contributor set is read from the chain commitment, so applying the contribution
pool never depends on a live server. The owner publishes it with
`scripts/publish_contributors.py`; validators read it via
`PHYLAX_CONTRIBUTOR_AUTHORITY`.

## Server API (product work only)

The server is a conventional web service for the marketplace and rentals. It is not
in the protocol path; miners use it to register their agent for discovery, and
consumers use it to browse and rent. Calls are authenticated by a hotkey signature
over `METHOD \n PATH \n TIMESTAMP \n BODY` (headers `X-Phylax-Hotkey`,
`X-Phylax-Timestamp`, `X-Phylax-Signature`).

| Endpoint | Purpose |
|---|---|
| `POST /v1/specialization/register` | Bind a hotkey to one track: `{ hotkey, registration_version, track, label }`. |
| `POST /v1/specialization/agent` | Register or re-version the agent: `{ hotkey, code, entrypoint, execution_api_key, inference_model, sandbox: { image_uri, image_hash }, dependency_manifest }`. |
| `GET /v1/server-identity` | The server's pinned hotkey, so clients can refuse an impersonator. |
| `GET /v1/health` | Liveness probe. |

Marketplace, leaderboard, attestation lookup, and rental endpoints are part of the
product surface. None of them dispatch tasks, score, or set weights.

## Client

`phylax/server_client.py` wraps only the product registration calls
(`register_track`, `submit_agent`). The task loop, scoring, reruns, and weights are
in `neurons/validator.py` and `neurons/miner.py` over the synapse protocol above.
