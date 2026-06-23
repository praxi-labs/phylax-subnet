# Validator Setup

A validator scores one track. It needs no server: it picks artifacts from the
bundled benchmark, dispatches tasks to miners over Bittensor, verifies the proof,
scores locally, reruns a sample peer to peer, and sets weights on chain. Eligibility
is on-chain and permissionless (permit by stake, vtrust by actively setting
weights).

The full walkthrough, including `btcli` registration and staking on netuid 486, the
`.env` keys, and the per-round loop, is in the canonical docs:

https://docs.phyi.dev/guides/validator
