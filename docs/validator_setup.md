# Phylax Validator Guide
## Testnet (netuid 486)

## Overview

A Phylax validator dispatches typed skill tasks to miners, verifies their submissions, computes consensus across verification groups, and pushes weights on-chain through a server-issued attestation.

Per round the validator does six things. It fetches up to twelve tasks from the phylax-server corpus, two per skill type. It injects per-task canaries and derives nonce-based probe events. It selects a five-miner verification group (three primaries plus two auditors) per task and dispatches concurrently. It verifies each response across multiple gates (deadline, SSSA structure, sandbox manifest digest, trace bundle hashes, probe presence, semantic subset). It computes full SSSA consensus across the group (verdict, risk, findings, capabilities, dependencies, recommended policy) and applies a consensus multiplier to each miner's emission score. Asynchronously it pulls each primary's declared sandbox image and reruns it against the same bundle and nonce to confirm honesty, feeding the result into the next round's per-type reputation.

The validator needs Docker on the host for the async miner-image rerun. It also needs a path to phylax-server, since weights cannot be pushed on-chain without a fresh server-issued weight attestation.


## Requirements

- Docker 24+ with the compose plugin (`docker compose version` must work)
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli))
- 16 GB RAM, 4+ CPU cores, 100 GB free disk (image layers, evidence dirs, miner sandbox image cache, rerun queue, and collusion tracker all accumulate)
- Outbound HTTPS to your phylax-server URL
- Outbound HTTPS to any container registry you expect miners to publish sandbox images to (typically `ghcr.io`, `docker.io`)
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


## 2. Get on the Phylax-Server Allowlist

The validator pulls task batches from phylax-server and cannot push weights on-chain without a fresh server-issued weight attestation. The operator running phylax-server must add your hotkey to its allowlist before any of this works.

Send the phylax-server operator:

- Your validator hotkey ss58 (from `btcli wallet overview` above)
- The source IP your validator will dial from

They reply with the phylax-server base URL and the server signing-key hotkey. You pin that hotkey in `.env` so a rogue impostor server cannot trick you.


## 3. Install and Configure

```bash
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/scripts/install.sh | bash -s validator
```

The script is idempotent. Re-running upgrades the compose file but does not clobber `.env`.

Edit `~/phylax/validator/.env`:

| Variable | What to set |
|---|---|
| `PHYLAX_NETUID` | `486` |
| `SUBTENSOR_NETWORK` | `test` |
| `WALLET_NAME` | folder name in `~/.bittensor/wallets/` |
| `WALLET_HOTKEY` | `default` (or the hotkey you registered) |
| `PHYLAX_SERVER_URL` | `https://<phylax-server-host>` |
| `PHYLAX_SERVER_HOTKEY` | hex from `curl $PHYLAX_SERVER_URL/v1/server-identity` |
| `PHYLAX_VALIDATOR_LABEL` | friendly label that appears in server-side dashboards |

Fetch and pin the server signing key:

```bash
curl -fsSL https://<your-phylax-server>/v1/server-identity
# Copy the "hotkey" field into PHYLAX_SERVER_HOTKEY in .env
```

Quick sanity check after editing:

```bash
grep -E '^(PHYLAX_NETUID|SUBTENSOR_NETWORK|WALLET_NAME|WALLET_HOTKEY|PHYLAX_SERVER_URL|PHYLAX_SERVER_HOTKEY)=' ~/phylax/validator/.env
```

All six lines should show non-placeholder values.

If you started the validator before fixing these, recreate the container. `docker compose restart` is not enough because env vars are only read at container creation.

```bash
cd ~/phylax/validator
docker compose up -d --force-recreate
```


## 4. Server Database Migration

The server schema must be at migration `0011` or later for the validator to register sandbox images, push reputation updates, and submit rerun verifications. The phylax-server operator must run this on the server host before your validator starts:

```bash
alembic upgrade head
```

If the migration has not been applied, the validator will see `500` errors on its first `POST` to several reputation and routing endpoints. Ask the operator if you see those errors.


## 5. Run

```bash
cd ~/phylax/validator
docker compose pull
docker compose up -d
docker compose logs -f
```

Within about 30 seconds you should see:

```
registered with phylax-server at https://...
starting Phylax validator on netuid=486 hotkey=...
```

Within a couple of minutes you should see round activity:

```
round <id> | tasks=12 types={'executable_python','declarative','rag_knowledge',...}
executable_python hk=5FHneW... role=primary Q=0.512 cs=0.85 tier=tier_1_reference ε=0.78
round <id> done | top_score=0.XXX epoch=0
set_weights | attestation <id> expires ...
```

If `top_score` stays at `0.000` for several rounds, no miner is responding to that skill type yet or all responses are failing verification. Check the warning lines for the reason.


## 6. What the Validator Does Each Round

### Bundle Preparation

The validator fetches up to twelve tasks from the phylax-server corpus, two per skill type. For `declarative` and `mcp_server` slots tagged as canary, the validator generates synthetic safe bundles locally. For each task it derives a unique nonce, generates a canary and a probe specification from that nonce, and (for `rag_knowledge` and `declarative`) mutates the bundle bytes to embed the canary marker.

All twelve preparations run concurrently via `asyncio.gather`.

### Verification Group Selection

For each task the validator selects a five-miner verification group from the pool of miners who declared support for that skill type and have reputation `>= 0.2`:

- 3 primaries: top three by per_type_reputation
- 2 auditors: random sample of two from the remainder

Auditors who have been in the auditor role for the same skill type three rounds in a row are promoted into the primary slot, pushing the lowest-ranked primary into the auditor pool. Miners with collusion flags (three or more accumulated) are excluded entirely.

If the pool has fewer than five miners the group degrades gracefully. Fewer than three miners disables consensus scoring for that task.

### Concurrent Dispatch

All five miners receive the synapse concurrently. Primaries get the full per-skill-type timing window. Auditors get a tighter window because they are doing less work.

| Skill type | Primary `t_min / deadline` | Auditor `t_min / deadline` |
|---|---|---|
| `rag_knowledge` | 5s / 45s (standard) | 2s / 15s |
| `declarative` | 10s / 90s (standard) | 3s / 30s |
| `executable_python` | 30s / 300s (standard) | 10s / 90s |
| `executable_script` | 30s / 300s (standard) | 10s / 90s |
| `mcp_server` | 60s / 600s (standard) | 20s / 150s |
| `agent_composition` | 120s / 900s (standard) | 30s / 240s |

`fast` and `deep` profiles use scaled windows.

### Per-Response Verification

For each response the validator runs sequential gates:

1. Late discard. If latency exceeds `deadline_s` the submission is discarded with no score and no reputation update.
2. SSSA parse. Invalid attestation dict scores zero.
3. SSSA validity. The `skill.skill_type` must match the task's skill type. If `llm_evidence.allowed_use` is present it must be `finding_enrichment`, `mitre_owasp_mapping`, or `cve_explanation`. Violations score zero and trigger a reputation violation flag.
4. Sandbox manifest digest check (primaries on runtime types only). `sandbox_manifest.digest` must equal the `image_hash` the miner registered with phylax-server. Mismatch scores zero immediately, without waiting for the async rerun.
5. Trace bundle verification (primaries on runtime types only):
   - Total bundle under 30 MB compressed, each file under its per-file cap
   - All required files for the skill type present
   - Each file decompresses, parses as JSONL, and hashes (with `ts`-sorted + key-sorted + no-whitespace normalisation) to exactly the hash the miner declared in their SSSA evidence block
6. Probe verification. The `synapse.probe_evidence` field must contain `{file_path, file_content, dns_host, process_echo}` derived from the nonce. For runtime types the probe file write must appear in `fs.jsonl`, the probe DNS host must appear in `network.jsonl`, and the probe `echo` must appear in `process.jsonl`. Missing any of these scores zero.
7. Axis scoring. Compute α, ε, π, η plus the type-specific axis (μ for declarative, σ for executable_script, ψ and τ for mcp_server, χ for agent_composition, ρ for rag_knowledge). Apply the per-type composite Q formula. Below `ε = 0.10` the composite Q is zero.

### Full SSSA Consensus

After all valid responses from the group are scored, the validator computes consensus across the group:

| Component | Weight |
|---|---|
| Findings recall (canonical key matching) | 0.30 |
| Findings precision | 0.15 |
| Verdict agreement | 0.15 |
| Capabilities agreement | 0.15 |
| Risk score agreement (median ± 15 = full, ± 30 = partial) | 0.10 |
| Dependencies agreement (CVE intersection) | 0.10 |
| Policy derivation (policy aligns with capability consensus) | 0.05 |

Each miner's `consensus_score` is the weighted sum in [0, 1]. It multiplies the miner's base emission score for this task.

A finding is canonically identified by `(layer_source, owasp_or_mitre_ref, affected_file, line_bucket)` where the line bucket is the line number divided by 5 to allow ±5 lines tolerance. This stops trivial wording differences from breaking finding agreement.

### Emission Score Per Task

```
emission = composite_Q
         × base_weight[skill_type]
         × tier_multiplier[tier]
         × early_submission_bonus
         × (0.6 if auditor else 1.0)
         × consensus_score
         × (bootstrap_bonus_if_applicable)
```

Bootstrap bonus adds +0.5 to base weight for `mcp_server` and `agent_composition` during the first 30 epochs.

### Selective Async Rerun

The validator does not rerun every primary's sandbox every round. It triggers async rerun only when needed:

- Consensus breakdown (more than half the group diverges from majority): rerun all diverging primaries
- Some primaries diverge but consensus holds: rerun only those primaries
- Clean consensus: rerun one randomly selected primary as a sampling check

Each rerun job is enqueued to a persistent SQLite queue at `~/.phylax/rerun_queue.sqlite3`. A background thread pulls jobs one at a time, pulls the miner's registered Docker image, verifies the pulled digest matches what they registered, runs the image against the same bundle with the same nonce, and compares:

- `fs_trace_hash` must match exactly (canary write is deterministic)
- Semantic agreement on `network.jsonl`, `process.jsonl`, `secrets.jsonl` must be at least 0.7

A pass adds +0.02 to that miner's per_type_reputation. A fail multiplies it by 0.7. Results feed into the next round, not the current one.

### Collusion Tracking

After each round the validator records per (hotkey, skill_type, round_id) the miner's agreement with primaries and agreement with auditors. Over the last 30 samples, if a miner's agreement with primaries exceeds 0.90 while their agreement with random auditors stays below 0.60, the validator accumulates a collusion flag. Three flags eject the miner from group selection until investigated.

### Reputation Updates

After each round the validator pushes one update per (miner, task) to the server:

- Canary task: pass / fail binary
- Standard task: epsilon value
- Bounty task: pass / fail with elevated reward
- Violation: triggers x0.5 reputation hit

The server applies the spec'd update rules (canary pass +0.05 / fail x0.7, standard ε≥0.8 +0.02 / ε<0.5 x0.95, bounty pass +0.05 / fail x0.7, violation x0.5) and the recovery streak logic.

### Round Aggregation and Set Weights

Per-miner round score is the weighted mean of per-task emission scores, weighted by the type's base weight. The result is blended into a per-uid EMA at α = 0.2. When at least `WEIGHT_UPDATE_INTERVAL` blocks have passed since the last push, the validator requests a fresh weight attestation from the server and calls `subtensor.set_weights` with the EMA-normalised weights.


## 7. Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `PHYLAX_NETUID` | (empty) | Required. Subnet to validate on. Set to `486` for testnet. |
| `SUBTENSOR_NETWORK` | (empty) | Required. `test` for testnet, `finney` for mainnet. |
| `WALLET_NAME` | (empty) | Required. Folder name in `~/.bittensor/wallets/`. |
| `WALLET_HOTKEY` | `default` | Hotkey under that wallet. |
| `PHYLAX_SERVER_URL` | (empty) | Required. Base URL of phylax-server. Without it weights cannot be pushed. |
| `PHYLAX_SERVER_HOTKEY` | (empty) | Recommended. Pinned server signing-key hotkey for impersonation defence. |
| `PHYLAX_VALIDATOR_LABEL` | (empty) | Friendly label shown in server dashboards. |
| `SERVER_CURATED_PULL` | `18` | Maximum corpus tasks pulled per round. Round will use at most 12 after stratification. |
| `WEIGHT_UPDATE_INTERVAL` | `100` | Blocks between `set_weights` pushes. |
| `EMA_ALPHA` | `0.2` | Per-round EMA blending factor. |
| `QUERY_TIMEOUT` | `150` | Hard ceiling on dendrite call, in seconds. |
| `PHYLAX_INFERENCE_PROXY_URL` | (empty) | If set, included in synapse `inference_config.proxy_url` for miners that use LLM for finding enrichment. |
| `PHYLAX_ALLOWED_MODELS` | (empty) | Comma-separated list. Included in synapse `inference_config.allowed_models`. |
| `PHYLAX_COMPOSITION_DEPTH` | `5` | Default `composition_depth` for `agent_composition` ground truth runs. |
| `PHYLAX_RERUN_QUEUE_PATH` | `~/.phylax/rerun_queue.sqlite3` | Persistent queue for async miner-image reruns. |
| `PHYLAX_COLLUSION_DB_PATH` | `~/.phylax/collusion.sqlite3` | Persistent store for per-(miner, skill_type) consensus agreement history and collusion flags. |
| `PHYLAX_EVIDENCE_HOST_DIR` | set by `install.sh` | Host-side absolute path of the evidence bind mount. Required for docker-in-docker. |
| `DOCKER_GID` | set by `install.sh` | Host docker group GID. The validator container joins this group to open `/var/run/docker.sock`. |
| `HOST_UID` / `HOST_GID` | set by `install.sh` | Your shell user's UID/GID. The container runs as this user so bind mounts stay writable. |
| `PHYLAX_IMAGE_TAG` | `latest` | Pin to `sha-<short>` for reproducible deploys. |
| `WATCHTOWER_POLL_INTERVAL` | `21600` | When auto-update profile is active: GHCR poll interval in seconds (default 6h). |


## 8. Updating

### Auto-update (recommended)

```bash
cd ~/phylax/validator
docker compose --profile auto-update up -d
```

Only containers carrying the `com.centurylinklabs.watchtower.enable=true` label are touched. Tune the cadence:

```bash
echo "WATCHTOWER_POLL_INTERVAL=3600" >> .env   # 1h instead of 6h
docker compose --profile auto-update up -d
```

Disable later:

```bash
docker compose stop watchtower && docker compose rm -f watchtower
```

### Manual

```bash
cd ~/phylax/validator
docker compose pull
docker compose up -d
```

`.env`, your evidence dir, your rerun queue, and your collusion DB all persist across updates.


## 9. Local State Files

The validator maintains three local SQLite files. Each has its own purpose. Do not delete them while the validator is running.

| Path | Purpose |
|---|---|
| `~/.phylax/rerun_queue.sqlite3` | Persistent queue of pending async miner-image reruns. Survives validator restart. Job is removed once the rerun completes (pass or fail). |
| `~/.phylax/collusion.sqlite3` | 30-round window of per-(miner, skill_type) consensus agreement data. Used by the collusion detector to accumulate flags. |
| The Docker image cache | Per-miner sandbox images pulled at rerun time. Docker manages this automatically. Use `docker image prune -af` if it grows too large. |


## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker compose: command not found` | docker compose plugin missing | `sudo apt install docker-compose-plugin` |
| Container exits immediately | Hotkey not found in `~/.bittensor` | Check `ls ~/.bittensor/wallets/<WALLET_NAME>/hotkeys/<WALLET_HOTKEY>` |
| Container uses the wrong hotkey | `WALLET_NAME` mismatch | `btcli w list` to see actual folder names, align `WALLET_NAME`, then `docker compose up -d --force-recreate` |
| Validator subscribes to the wrong subnet | `PHYLAX_NETUID` left at template default | Set to `486` in `.env`, recreate |
| `.env` edits not taking effect | `docker compose restart` reuses baked-in env | Use `docker compose up -d --force-recreate` instead |
| `phylax-server registration failed: 403 Forbidden` | Your hotkey or source IP is not on the server allowlist | Contact the server operator |
| `phylax-server identity mismatch` | Server signing key changed or `PHYLAX_SERVER_HOTKEY` is wrong | Re-fetch `/v1/server-identity` and update `.env` |
| `500` on `POST /v1/reputation/...` | Server is on an old schema | Operator must run `alembic upgrade head` on the server host |
| `no dispatchable miners` log line | No miner has declared the skill type, or all declared miners are filtered out by recency, active-task, or collusion-flag rules | Wait for more miners to register, or check the validator log for the specific exclusion reason |
| `trace verification failed: <reason>` for many miners | Miners are not following the trace bundle contract or the trace normalisation rule | Confirm miners are on a recent miner image version |
| `sandbox digest mismatch` for a specific miner | The miner's `PHYLAX_SANDBOX_DIGEST` does not match the `image_hash` they registered with phylax-server | The miner needs to update either their env or their registration so the two agree |
| `probe verification failed` for many miners | Miners are not emitting probe events into their fs/network/process traces | Confirm miners are on a recent miner image version |
| `docker pull failed` log line during rerun | Validator host cannot reach the miner's container registry, or the image is not publicly readable | Test pull manually from the validator host. Miner must publish their image with public read access. |
| Rerun queue keeps growing | Rerun worker cannot keep up with submissions, or Docker is broken on the host | Check `docker info` works, check rerun worker log lines, consider raising `WEIGHT_UPDATE_INTERVAL` to slow rounds |
| `top_score` stuck at `0.000` | No miner is returning valid SSSAs that pass all gates | Inspect validator log for the rejection reasons. Common causes: miners on old version, no sandbox image registered, probe events not emitted |
| `set_weights returned False` | Stake too low for permit, or chain is congested | `btcli stake add` more TAO, or wait and try next interval |
| `set_weights: phylax-server refused to issue a weight attestation` | Your hotkey was removed from the allowlist, or you have not pushed any round results yet | Contact server operator |
| Disk fills up | Docker images accumulating | `docker image prune -af`, or enable the auto-update profile (Watchtower prunes automatically) |
| Validator hangs on round start | Bundle preparation is blocked on a slow harness | Check the in-process reference harness logs. A misbehaving bundle should still time out but verify `SANDBOX_TIMEOUT` is sane |


## 11. What Makes a Validator Run Well

A well-functioning validator has:

- **Reliable phylax-server connectivity**. Every round needs `/v1/tasks/by-type`, `/v1/specialization/routing`, `/v1/specialization/generalists`, `/v1/specialization/tier-table`, `/v1/reputation/per-type`. Server outages block rounds.
- **Public network egress for image pulls**. The async rerun worker pulls miner sandbox images. If your host cannot reach the registries miners publish to, reruns will fail and you cannot verify honesty.
- **Docker working as the host user**. The rerun worker uses `docker run` directly. If the user inside the container cannot reach the Docker socket, no reruns happen and async verification stalls.
- **A registered hotkey with non-zero stake**. Without stake you cannot set weights on-chain. Top up periodically.
- **Server allowlist membership**. The server gates all reputation, routing, and weight-attestation endpoints behind allowlist + signature. Without it, the validator runs but produces no on-chain effect.
- **Up-to-date image**. Validator code evolves rapidly. Enable the auto-update profile so you stay on the same version as miners and the server.

If all five hold, the validator runs rounds continuously, accumulates per-type reputation history, builds collusion-detection signal, and converges on a stable weight distribution that rewards honest, high-quality miner work.
