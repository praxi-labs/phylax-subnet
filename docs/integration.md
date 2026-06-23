# Integration

Developers consume Phylax through the product surface: look up a signed attestation
by artifact hash in the registry, or rent a top-ranked agent to vet their own
artifacts. The signed SSSA is ed25519 and can be verified offline. None of this
sits in the protocol path; the attestations it serves are produced by the network
(miners run the agents, validators verify and rerun) and published to the registry.

See the canonical docs for how the network produces those attestations:

https://docs.phyi.dev/get-started/introduction
