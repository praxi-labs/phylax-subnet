# Miner Setup Guide

Run a Phylax miner on testnet (netuid 486) from a clean host. Copy-paste from top to bottom.

## 1. Prerequisites

- Docker 24+ (`docker` runnable by your user; add yourself to the `docker` group if not).
- `btcli` ([install guide](https://docs.bittensor.com/getting-started/install-btcli)).
- 16 GB RAM, 4+ CPU cores, 50 GB free disk.
- Inbound TCP **8091** open to the public internet (validators dial this port).

## 2. Wallet

```bash
btcli wallet create --wallet.name miner --wallet.hotkey default
```

Fund the **coldkey** with testnet TAO from the Bittensor Discord `#faucet` channel — you need ~1 TAO to register on the subnet.

## 3. Register on subnet 486

```bash
btcli subnet register \
  --netuid 486 \
  --subtensor.network test \
  --wallet.name miner \
  --wallet.hotkey default
```

The transaction prompts for a registration fee (paid from the coldkey balance). On success the hotkey gets assigned a UID on subnet 486.

Verify:

```bash
btcli wallet overview --wallet.name miner --subtensor.network test | grep -A1 'UID'
```

## 4. Pull the images

The miner image bundles the analysis pipeline. The sandbox image is what the miner shells out to `docker run` per scan.

```bash
docker pull ghcr.io/praxi-labs/phylax-miner:latest
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
```

## 5. Configuration

Pull the example `.env`, edit the few fields you need, save anywhere convenient:

```bash
mkdir -p ~/phylax && cd ~/phylax
curl -fsSL https://raw.githubusercontent.com/praxi-labs/phylax-subnet/main/.env.example -o .env
mkdir -p evidence
```

The defaults already point `PHYLAX_SANDBOX_IMAGE` at the published sandbox tag and `PHYLAX_EVIDENCE_DIR` at `/opt/phylax/evidence` (which the miner image pre-creates and the run command bind-mounts). For a miner you do **not** need any phylax-server env vars — those are validator-only.

## 6. Run

```bash
docker run -d --name phylax-miner --restart=unless-stopped \
  -p 8091:8091 \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/.bittensor:/root/.bittensor:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/phylax/evidence:/opt/phylax/evidence" \
  --env-file "$HOME/phylax/.env" \
  ghcr.io/praxi-labs/phylax-miner:latest \
  python neurons/miner.py \
    --netuid 486 \
    --subtensor.network test \
    --wallet.name miner \
    --wallet.hotkey default \
    --axon.port 8091 \
    --logging.debug
```

What each mount does:

| Mount | Why |
|---|---|
| `~/.bittensor` (read-only) | Hotkey to sign SSSAs |
| `/var/run/docker.sock` | Miner shells out to `docker run` to launch the sandbox container |
| `~/phylax/evidence` | Host-side scratch for per-scan trace artefacts (shared with the sandbox by bind mount) |
| `--user $(id -u):$(id -g)` | Required so the sandbox's bind-mounted `/evidence` is writable from inside the container |

## 7. Verify

```bash
# Container is up
docker ps --filter name=phylax-miner --format 'table {{.Names}}\t{{.Status}}'

# Tail logs — within ~30s you should see "Axon serving on [::]:8091"
docker logs -f phylax-miner

# Once a validator queries you, log lines like:
#   Received scan request: sha256:...
#   Running Layer 3: Sandbox detonation (seed=...)
```

## 8. Updating

```bash
docker pull ghcr.io/praxi-labs/phylax-miner:latest
docker pull ghcr.io/praxi-labs/phylax-sandbox:latest
docker rm -f phylax-miner
# Re-run the docker run command from step 6.
```

## How the miner answers each query

| Step | Whitepaper § | Description |
|---|---|---|
| Receive | §5.1 | Synapse carries `skill_bundle`, `nonce`, `round_id`, `deadline_unix` |
| Layer 1 | §4.1 | Static pattern scan + prompt-injection rules |
| Layer 2 | §4.1 | SBOM + osv.dev CVE lookup + typosquat + install-hook scan |
| Layer 3 | §4.1 | Sandbox detonation seeded by `synapse.nonce` |
| Assemble | §3 | Build SSSA with capabilities, findings, policy, evidence pack |
| Sign | §3 | ED25519 signature with the miner hotkey |
| Return | §5.1 | Reply within the deadline |

The miner refuses to detonate if no nonce is supplied — running with a hardcoded seed would break the subnet's anti-copy guarantee.

## Tuning

| Variable | Default | Meaning |
|---|---|---|
| `SANDBOX_TIMEOUT` | `60` | Per-detonation timeout (seconds), 5× for `deep` profile |
| `PHYLAX_LOG_LEVEL` | `INFO` | Stdlib logger level |
| `PHYLAX_EVIDENCE_DIR` | `/opt/phylax/evidence` | Where evidence packs are written before hashing (mount this from the host) |
| `PHYLAX_SANDBOX_IMAGE` | `ghcr.io/praxi-labs/phylax-sandbox:latest` | Sandbox image the detonator launches |

Override any of these by setting them in `~/phylax/.env`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Container exits immediately | Wallet path not mounted, or hotkey doesn't exist | Confirm `~/.bittensor/wallets/miner/hotkeys/default` exists on the host |
| `Permission denied: '/opt/phylax/evidence'` | You omitted `--user "$(id -u):$(id -g)"` | Add the flag |
| `Cannot connect to the Docker daemon` from inside container | Forgot to mount `/var/run/docker.sock` | Add the `-v /var/run/docker.sock:/var/run/docker.sock` flag |
| No `Received scan request` ever | Inbound 8091 closed in firewall/security group, or axon not registered yet | Open the port; allow ~12 blocks (~2 min) after `subnet register` for the axon to propagate |
| `Bundle hash mismatch` | Wrong bytes downloaded | Check `bundle_url` reachability from inside the container |
| `validator did not supply a nonce` | Talking to a pre-1.1.0 validator | Tell the validator operator to upgrade |
| Sandbox timeouts | Heavy bundles, `deep` profile | Bump `SANDBOX_TIMEOUT` in `.env` and recreate the container |
| ε scored 0 on the leaderboard | Sandbox produced no trace files | Run `ls ~/phylax/evidence/$(ls -1t ~/phylax/evidence \| head -1)` — you should see `network.jsonl`, `fs.jsonl`, `process.jsonl`, `secrets.jsonl`. If only `log.txt`, check that log for the harness error |
