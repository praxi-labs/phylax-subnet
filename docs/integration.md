# Consuming Phylax

## Verify an SSSA

An SSSA is verifiable offline. Recompute the canonical hash (NFC normalised,
key sorted JSON of the SSSA minus its attestation block), check the ed25519
signature against the executing validator's on chain hotkey, and check
`attestation.agent_hash` against the miner's pinned submission. No Phylax service
needs to be trusted or reachable.

## Enforce a policy

The capability manifest inside a detonation SSSA is a portable statement of
witnessed behavior in canonical vocabulary. A runtime can enforce it directly:
deny capabilities the attestation never witnessed, gate dangerous ones, and
refuse artifacts whose verdict is BLOCK.

## Rent an agent

Because the network holds and runs the submitted artifact, the agent that earned
a ranking is byte for byte the agent the marketplace serves. Renting a top ranked
agent deploys those exact bytes against your own artifacts in your own pipeline.
The marketplace at [app.phyi.dev](https://app.phyi.dev/) surfaces per track
rankings and attestations.

## Bounties

Artifacts without a known label cannot be scored against ground truth, so they
are routed as bounties to the historically strongest miners in a track and
rewarded for demonstrated, proof carrying analysis. Routine scoring is never
based on miner agreement on unlabelled data.
