# Protocol surfaces

## Agent submission and fetch

The backend is the source of truth for agent code. There is no task dispatch:
validators execute agents themselves.

**Miner submits** — `POST /v1/specialization/agent`, signed by the hotkey:

| Field | Meaning |
|---|---|
| `track` | The miner's registered track |
| `code` | The agent source |
| `entrypoint` | The entry function, default `agent_main` |
| `execution_api_key` | The metered inference key validators spend |
| `inference_model` | Optional preferred model |

The submission is code only — the validator owns the sandbox image, so it carries
no image or digest. The backend stores it keyed by `sha256:` of the code. No neuron
runs on the miner side.

**Validator fetches** — at round start, for each frozen participant,
`GET /v1/specialization/agent/{hotkey}/runnable` returns the code, entrypoint, and
key. The validator verifies the fetched code hash matches the frozen pin, then
screens for size, entrypoint, and copied code before admitting the agent.

The old peer-to-peer `AgentSynapse` (validator to miner, same fields plus the
miner's signature over the submission digest) remains only as a local-dev fallback
when no backend is configured.

## The chain

| Value | Role |
|---|---|
| Block hash | Fallback round seed for task selection and probes when no server schedules the round |
| Weight submissions | Each validator's graduated vector |
| Yuma consensus | Stake weighted median with clipping |
| Commitments | The recognized contributor set |

## The server (product only)

The server schedules rounds (`GET /v1/rounds/next` hands every validator the same
round id and seed) and records the signed results validators post back
(`POST /v1/rounds/results`) for the marketplace and leaderboard. The miner also
registers its agent with it (`register_track`, `submit_agent`) so it appears in the
marketplace. The server never derives tasks, executes agents, scores, or picks the
winner — that is on-chain consensus. Without a server, validators fall back to a
block-derived round seed.
