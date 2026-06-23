# Phylax Validator Guide
## netuid 486 (testnet)

A validator scores **one track**. It pulls track tasks from the phylax-server,
runs each miner's submitted agent in an isolated sandbox, verifies the
proof-of-execution, signs the attestation, and sets top-3 per-track weights on
chain. There is no manual approval. Eligibility is on-chain.

## Eligibility

You need both, and both are on-chain:

- a validator **permit**, granted by stake weight (top nodes by stake), and
- positive **vtrust**, which proves you are actively setting weights.

Stake alone does not qualify you; you must validate. Phylax adds no central
register and no team approval on top of this.

## Requirements

- A Linux host with Docker + `docker compose`. The validator runs untrusted miner
  agents, so it needs docker socket access (the install script wires the host
  docker group).
- A Bittensor wallet with enough stake to hold a permit.
- The phylax-server URL and its pinned identity hotkey.

## 1. Chain registration and stake

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
./scripts/register_testnet.sh validator
btcli stake add --wallet.name validator --wallet.hotkey default --amount <TAO>
```

## 2. Install and configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
cd ~/phylax/validator
```

Fill in `.env`:

```ini
PHYLAX_TRACK=skills
PHYLAX_SERVER_URL=https://<phylax-server>
PHYLAX_SERVER_HOTKEY=<hex from /v1/server-identity>     # pinned anti-impersonation
PHYLAX_VALIDATOR_LABEL=<label for dashboards>
PHYLAX_INFERENCE_PROXY_URL=<metered egress for the jailed sandbox>
```

Pin the server hotkey so a hijacked DNS/URL can't impersonate the control plane:

```bash
curl -fsSL https://<phylax-server>/v1/server-identity
```

## 3. Run

```bash
docker compose pull
docker compose up -d
docker compose logs -f
```

## 4. What the validator does each round

Miners run the primary task themselves and submit signed SSSAs. The validator's
job is the independent rerun audit plus consensus weighting. Its loop
(`neurons/validator.py`):

1. **Sample**: `POST /v1/tasks/track/rerun-sample` returns a random subset of
   recently attested tasks, each with its artifact, nonce, probe, and the verdict
   the miner reported.
2. **Fetch agent**: `GET /v1/specialization/agent/{hotkey}/runnable` returns the
   agent code, entrypoint, execution key, and registered sandbox image + digest.
3. **Rerun**: run the agent on the task in the miner's registered image,
   network-jailed, with the probe threaded through.
4. **Report**: `POST /v1/tasks/track/{task_id}/rerun` with whether the verdict
   reproduced. The server folds it into the agent's `rerun_pass_rate`.
5. **Set weights**: every `WEIGHT_UPDATE_INTERVAL` blocks, `GET
   /v1/tasks/track/weights` returns the top-3 per-track weights (already adjusted
   by `rerun_pass_rate`); the validator maps hotkeys to UIDs and calls
   `set_weights`.

A verdict that does not reproduce drives the agent's `rerun_pass_rate` down,
which pushes it out of the top-3 emission slots.

## 5. Server database migration

The server owns all task/agent/score state. After upgrading the server, apply its
migrations (run from the phylax-server deployment) before validators resume, so
the agent/attestation tables match the running code.

## 6. Configuration reference

| Variable | Purpose |
|---|---|
| `PHYLAX_TRACK` | the single track this validator scores |
| `PHYLAX_SERVER_URL` | control-plane URL |
| `PHYLAX_SERVER_HOTKEY` | pinned server identity (anti-impersonation) |
| `PHYLAX_VALIDATOR_LABEL` | dashboard label |
| `PHYLAX_INFERENCE_PROXY_URL` | metered LLM egress for the jailed sandbox |
| `PHYLAX_TRACK_INTERVAL` | seconds between task polls (default 20) |
| `WEIGHT_UPDATE_INTERVAL` | blocks between weight pushes (default 360) |
| `WALLET_NAME` / `WALLET_HOTKEY` | wallet identity |

## 7. Updating

```bash
cd ~/phylax/validator
docker compose pull && docker compose up -d
# or enable auto-updates:
docker compose --profile auto-update up -d
```

## 8. Troubleshooting

- **No weights set**: `GET /track/weights` returns nothing until agents have
  accrued scores; check that tasks are being dispatched and attested.
- **All agents score 0**: the probe is not landing in traces; verify the sandbox
  can run the agent image and that the docker socket is reachable (host docker
  group GID in `.env`).
- **Registration refused**: the server requires a reachable, pinned identity;
  re-check `PHYLAX_SERVER_URL` / `PHYLAX_SERVER_HOTKEY`.
