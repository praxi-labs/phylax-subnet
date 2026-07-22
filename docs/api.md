# Protocol surfaces

## The synapse

The subnet has one synapse. There is no task dispatch: validators execute agents
themselves.

### `AgentSynapse` (validator to miner)

The miner fills in its submission:

| Field | Meaning |
|---|---|
| `track` | The miner's registered track |
| `code` | The agent source |
| `entrypoint` | The entry function, default `agent_main` |
| `execution_api_key` | The metered inference key validators spend |
| `inference_model` | Optional preferred model |
| `agent_hash` | `sha256:` of the code |
| `signature` | ed25519 over the submission digest, by the miner's hotkey |

The submission is code only — the validator owns the sandbox image, so it carries
no image or digest. Miners blacklist callers without a validator permit (and below
`PHYLAX_MIN_VALIDATOR_STAKE` when set). The validator verifies the signature and
the hash pin before admitting the agent to a round, then screens for size,
entrypoint, and copied code.

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
