# Protocol & API

The protocol runs validator to miner over Bittensor synapses; the server is product
only and is not in the protocol path. A validator dispatches a task (artifact,
nonce, probe) to a miner, the miner runs its agent and returns a signed SSSA, and
the validator verifies the proof, scores it locally, reruns a sample peer to peer,
and sets weights on chain.

The full reference, the `TaskSynapse` / `AgentSynapse` fields, the chain surface,
and the server's product API, lives in the canonical docs:

https://docs.phyi.dev/reference/protocol
