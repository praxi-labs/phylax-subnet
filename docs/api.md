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
| `sandbox_image` / `sandbox_digest` | The pinned run environment |
| `agent_hash` | `sha256:` of the code |
| `signature` | ed25519 over the submission digest, by the miner's hotkey |

Miners blacklist callers without a validator permit (and below
`PHYLAX_MIN_VALIDATOR_STAKE` when set). The validator verifies the signature and
the hash pin before admitting the agent to a round, then screens for size,
entrypoint, and image pin.

## The chain

| Value | Role |
|---|---|
| Block height | Round boundaries per track |
| Start block hash | The round seed for task selection and probes |
| Weight submissions | Each validator's graduated vector |
| Yuma consensus | Stake weighted median with clipping |
| Commitments | The recognized contributor set |

## The server (product only)

The miner optionally registers its agent with `phylax-server`
(`register_track`, `submit_agent`) so it appears in the marketplace. The server
never dispatches tasks, executes agents, scores, or sets weights; the protocol
runs entirely between the chain, the validators, and the miners.
