# Phylax Validator Guide
## netuid 486 testnet

## Overview

A Phylax validator dispatches skill analysis tasks to miners, verifies their submissions, and sets weights on-chain. Validators are the evaluation infrastructure of the subnet. Running one earns emissions and strengthens the network's security guarantees.

The validator needs access to phylax-server, which coordinates task distribution and issues weight attestations. Without a valid attestation from the server, weights cannot be pushed on-chain.


## Requirements

- Docker 24+ with the compose plugin (`docker compose version` must work)
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli))
- 16 GB RAM, 4+ CPU cores, 100 GB free disk
- Outbound HTTPS to your phylax-server URL
- Outbound HTTPS to container registries miners publish to (typically `ghcr.io`, `docker.io`)
- Your shell user in the docker group: `sudo usermod -aG docker $USER && newgrp docker`


## 1. Create Wallet, Register, and Stake

```bash
btcli wallet create --wallet.name validator --wallet.hotkey default
```

Fund the coldkey with testnet TAO from the Bittensor Discord `#faucet` channel. You need TAO for the registration fee and for stake.

```bash
btcli subnet register \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name validator \
  --wallet.hotkey default

btcli stake add \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name validator \
  --wallet.hotkey default \
  --amount 1
```

Verify:

```bash
btcli wallet overview --wallet.name validator --subtensor.network test
```

Look for `validator/default` with a non-zero stake on subnet 486.


## 2. Get the Server URL

Access to phylax-server is permissionless. The server checks your hotkey directly against the Bittensor metagraph on every request. Your hotkey must hold a **validator permit** on netuid 486, which requires sufficient stake.

No manual registration or allowlist is needed. Once your hotkey holds a permit on-chain, the server grants access automatically.

Get the server URL from the Phylax community channels. Then fetch the server signing-key hotkey and pin it in your `.env` so a rogue server cannot impersonate the real one:

```bash
curl https://<phylax-server-host>/v1/server-identity
```

Set `PHYLAX_SERVER_HOTKEY` to the `server_hotkey` value returned.


## 3. Install and Configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
```

Edit `~/phylax/validator/.env`:

| Variable | What to set |
|---|---|
| `PHYLAX_NETUID` | `486` |
| `SUBTENSOR_NETWORK` | `test` |
| `WALLET_NAME` | folder name in `~/.bittensor/wallets/` |
| `WALLET_HOTKEY` | `default` (or the hotkey you registered) |
| `PHYLAX_SERVER_URL` | `https://<phylax-server-host>` |
| `PHYLAX_SERVER_HOTKEY` | hex from `curl $PHYLAX_SERVER_URL/v1/server-identity` |
| `PHYLAX_VALIDATOR_LABEL` | friendly label shown in server dashboards |

After editing, recreate the container so the new env vars take effect:

```bash
cd ~/phylax/validator
docker compose up -d --force-recreate
```


## 4. Server Database Migration

Before your first run, confirm with the phylax-server operator that the server schema is up to date. If it is not, you will see `500` errors on reputation and routing endpoints. The operator runs this on the server host:

```bash
alembic upgrade head
```


## 5. Run

```bash
cd ~/phylax/validator
docker compose pull
docker compose up -d
docker compose logs -f
```

Within about 30 seconds:

```
registered with phylax-server at https://...
starting Phylax validator on netuid=486 hotkey=...
```

Within a couple of minutes you should see round activity:

```
round <id> | tasks=12 types={'executable_python','declarative','rag_knowledge',...}
round <id> done | top_score=0.XXX epoch=0
set_weights | attestation <id> expires ...
```

If `top_score` stays at `0.000` for several rounds, no miner is responding to tasks or all responses are failing verification. Check the warning lines in the log for the specific reason.


## 6. What the Validator Does

Each round the validator fetches tasks from the phylax-server corpus across all six skill types, selects a group of miners per task, dispatches bundles concurrently, verifies every response, scores submissions, computes consensus across the group, and pushes the resulting weights on-chain.

Asynchronously it also reruns each primary miner's declared sandbox image on the same bundle to confirm their submitted traces are honest. Rerun results feed into miner reputation for the following round.

Weights are pushed on-chain only when phylax-server issues a fresh attestation confirming the validator has submitted valid round results.


## 7. Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `PHYLAX_NETUID` | (empty) | Required. Set to `486` for testnet. |
| `SUBTENSOR_NETWORK` | (empty) | Required. `test` for testnet, `finney` for mainnet. |
| `WALLET_NAME` | (empty) | Required. Folder name in `~/.bittensor/wallets/`. |
| `WALLET_HOTKEY` | `default` | Hotkey under that wallet. |
| `PHYLAX_SERVER_URL` | (empty) | Required. Base URL of phylax-server. |
| `PHYLAX_SERVER_HOTKEY` | (empty) | Pinned server signing-key hotkey. |
| `PHYLAX_VALIDATOR_LABEL` | (empty) | Friendly label shown in server dashboards. |
| `WEIGHT_UPDATE_INTERVAL` | `360` | Blocks between `set_weights` pushes. Default matches one tempo on netuid 486; the chain rate-limit is 100 blocks, so going lower than ~110 risks `set_weights returned False: too soon to commit`. |
| `QUERY_TIMEOUT` | `150` | Hard ceiling on dendrite calls in seconds. |
| `PHYLAX_RERUN_QUEUE_PATH` | `~/.phylax/rerun_queue.sqlite3` | Persistent queue for async miner-image reruns. |
| `PHYLAX_EVIDENCE_HOST_DIR` | set by install.sh | Host-side path of the evidence bind mount. |
| `PHYLAX_IMAGE_TAG` | `latest` | Pin to `sha-<short>` for reproducible deploys. |
| `WATCHTOWER_POLL_INTERVAL` | `120` | Auto-update poll interval in seconds (default 2 min). |


## 8. Updating

Auto-update (recommended):

```bash
cd ~/phylax/validator
docker compose --profile auto-update up -d
```

Manual:

```bash
cd ~/phylax/validator
docker compose pull
docker compose up -d
```

Your `.env`, rerun queue, and local state all persist across updates.


## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Container exits immediately | Hotkey not found | Check `~/.bittensor/wallets/<WALLET_NAME>/hotkeys/<WALLET_HOTKEY>` exists |
| `.env` edits not taking effect | `docker compose restart` reuses baked-in env | Use `docker compose up -d --force-recreate` |
| `403 Forbidden` from phylax-server | Hotkey does not hold a validator permit on netuid 486 | Add stake with `btcli stake add` until the hotkey earns a permit, then retry |
| `phylax-server identity mismatch` | Server signing key changed or `PHYLAX_SERVER_HOTKEY` is wrong | Re-fetch `/v1/server-identity` and update `.env` |
| `500` on reputation endpoints | Server schema out of date | Operator must run `alembic upgrade head` |
| `no dispatchable miners` in logs | No miners declared this skill type or all are filtered | Wait for more miners to register |
| `top_score` stuck at `0.000` | No miner is returning valid submissions | Check log warning lines for rejection reasons |
| `set_weights returned False` | Stake too low or chain congested | Add more stake or wait for next interval |
| `docker pull failed` during rerun | Validator cannot reach miner's registry | Test the pull manually from the validator host |
| Disk fills up | Docker image layers accumulating | `docker image prune -af` |