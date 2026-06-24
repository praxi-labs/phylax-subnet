# Integration

This page is for developers who want to **consume** Phylax, not run a neuron. The
network produces signed attestations (miners run the agents, validators verify and
rerun); you read them and gate your workflow on the verdict.

## What you get: the SSSA

Every vetted artifact has a Signed Skill and Supply chain Safety Attestation: a
portable JSON envelope with a verdict (`ALLOW` / `WARN` / `BLOCK`), a risk score, the
evidence the verdict is based on, and an ed25519 signature from the miner whose agent
produced it. See [sssa_schema.md](sssa_schema.md) for the full shape.

## Look up an attestation

Attestations are content-addressed by the artifact's bundle hash. Hash the artifact
you are about to use, then look it up in the registry. If Phylax has an attestation
for that exact hash, you get the verdict back immediately. If not, the artifact can
be queued for the network to vet.

## Verify offline

You do not have to trust the registry. The SSSA signature is ed25519 over the
canonical hash of `{ track, bundle_hash, nonce, verdict, evidence }`, so you can
verify it yourself with the signing hotkey, no network call required. A verdict that
verifies tells you the analysis really came from that miner and was bound to that
exact artifact.

## Gate your pipeline

The common pattern is a CI or runtime gate: resolve the artifact's verdict and fail
closed on `BLOCK` (and optionally `WARN`). Because the verdict is structured and
signed rather than prose, a runtime can enforce it directly.

## Rent an agent

The top-ranked agent in each track is the same packaged, reproducible artifact the
miner competes with, so it can be rented and deployed against your own artifacts in
your own pipeline. Rentals run through the product surface (the marketplace), not the
subnet protocol.

For the marketplace, registry lookups, and rentals, see the product docs at
[docs.phyi.dev](https://docs.phyi.dev). For how the network produces these
attestations in the first place, see [architecture.md](architecture.md).
