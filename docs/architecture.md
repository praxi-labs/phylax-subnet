# Architecture

Phylax spans two codebases. `phylax-subnet` is the decentralized part: the miner and
validator neurons, the synapse protocol between them, and the scoring code the
validator runs. `phylax-server` is the product layer and is off the protocol's
critical path.

## phylax-subnet (the neurons and the protocol)

| Path | Role |
|---|---|
| `neurons/miner.py` | axon neuron: receive a task synapse, run own agent, return signed SSSA; serve agent for reruns |
| `neurons/validator.py` | dendrite neuron: dispatch tasks, verify proof, score, rerun a sample, set weights |
| `phylax/protocol.py` | the synapse definitions exchanged between validator and miner |
| `phylax/analysis/` | scoring spine, proof verification, capability taxonomy, per-track evaluators (run by the validator) |
| `phylax/harness/runner.py` | shared agent runner (miner runs, validator reruns) |
| `phylax/harness/executor.py` | runs an agent in the registered image, network-jailed |
| `phylax/harness/inference_proxy.py` | metered LLM egress for the jailed sandbox |
| `phylax/harness/corpus.py` | loads the bundled benchmark and zips artifacts for dispatch |
| `phylax/harness/skills_reference_agent.py` | reference skills agent (probe + dual-plane) |
| `corpora/` | the labelled benchmark per track, bundled so validators need no server |
| `phylax/server_client.py` | thin client for the server's product endpoints (registration only) |

## The synapse protocol

The validator and miner exchange Bittensor synapses; there is no HTTP server in the
loop.

| Synapse | Direction | Carries |
|---|---|---|
| `TaskSynapse` | validator to miner | track, artifact, nonce, probe; miner fills in the signed SSSA |
| `AgentSynapse` | validator to miner | a request for the miner's agent bundle so the validator can rerun it |

The validator derives the nonce and probe itself, so each validator's audit is
independent and cannot be precomputed. See [api.md](api.md) for the full field
shapes.

## Where scoring runs

Scoring is **in the validator**, not on a server. The `phylax/analysis/` package
holds the spine (`scoring.py`), proof verification (`proof.py`), the capability
taxonomy (`capability.py`), and the per-track evaluators. Each validator runs them on
every SSSA it receives, using the labels in its local `corpora/`. This is what makes
the subnet decentralized: no single service decides scores. See [scoring.md](scoring.md).

## phylax-server (server work only)

| Concern | Role |
|---|---|
| agent registration | store a miner's agent (code + image + key) for discovery and rentals |
| marketplace + leaderboard | surface attested artifacts and rentable agents |
| rentals + accounts | the consumer-facing product |

The server never dispatches tasks, verifies proofs, scores, or sets weights, so the
protocol does not depend on it being available.

## Isolation

The validator reruns untrusted miner agents, so it runs each one in the miner's
registered image on an internal `phylax-jail` network with capabilities dropped and
CPU, memory, and PID limits applied. The only egress from that network is the metered
inference proxy, so a submitted agent cannot exfiltrate its key or reach the open
internet. The same executor (`phylax/harness/executor.py`) runs the agent for the
miner and reruns it for the validator, so a run and its audit happen in identical
conditions.

## Eligibility and consensus

Validator eligibility is on-chain and permissionless: a node needs a validator permit
(granted by stake weight) and positive vtrust (which proves it is actively setting
weights). Each validator sets weights independently, and Yuma consensus aggregates
them by stake. There is no central register and no team approval.
