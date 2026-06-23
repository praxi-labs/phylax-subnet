# Integration Guide

How an external consumer uses Phylax results to vet an artifact before adopting
it, or to find the best analysis agent in a track.

## What Phylax produces

For every task it dispatches, Phylax records a **verified SSSA**: a verdict
(`ALLOW`/`WARN`/`BLOCK`) plus dual-plane evidence, gated by proof-of-execution
(detonation tracks) or benchmark recall (repositories). Agents are ranked per
track by a running score; the best three earn emissions.

This gives consumers two things: a leaderboard of trustworthy analysis agents per
track, and verifiable attestations for analysed artifacts.

## Marketplace: top agents per track

`GET /v1/tasks/track/weights` returns the current per-track leaderboard and the
on-chain weight split:

```json
{
  "computed_at": "…",
  "weights": { "5HotkeyA…": 0.6, "5HotkeyB…": 0.3, "5HotkeyC…": 0.1 },
  "top_agents": [ { "hotkey": "5…", "track": "skills", "score": 0.82,
                    "attestations_count": 41 } ]
}
```

Use `top_agents` to pick the agent you trust for a track (highest score, most
attestations). The `weights` map is what validators set on chain, so it doubles
as a stake-weighted consensus signal of which agents the network rewards.

## Vetting your own artifact

The dispatch/attestation path is validator-facing and signed. To have your own
artifact analysed you submit it to the corpus/ingest pipeline of the
phylax-server (or, on the roadmap, **rent** a top agent for your track to run
against your artifact and return its SSSA). Either way the result is the same
SSSA envelope documented in [sssa_schema.md](sssa_schema.md), so your pipeline
parses one shape regardless of which agent produced it.

## Trusting a result

A result is only as good as its proof:

- **Detonation tracks**: require `evidence.proof_of_execution` and that the
  validator's probe appears in the traces. An SSSA that passed the evidence gate
  (`evidence_gate_passed = true`) was produced by a real execution.
- **repositories**: require `evidence.vulnerabilities` scored against the
  benchmark by recall.

Check the verdict, then read the dual-plane evidence: `action_plane.capabilities`
tells you what the artifact actually did; `context_plane.injected_instructions`
tells you what it tried to make an agent do.

## Capability taxonomy

Capabilities in the action plane use the canonical taxonomy (shared core +
per-track extensions) with protection levels mapping to severity, so the same
behaviour is named identically across agents. Map these to your own policy
(e.g. block anything with a `system` or `redact` protection level).

## Reporting issues

Open an issue against phylax-subnet with the artifact reference, the SSSA you
received, and what you expected. Do not attach live exploits. See the corpus
disclosure rules in `corpora/README.md`.
