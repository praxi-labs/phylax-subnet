# Phylax Corpora

This folder defines what an artifact looks like in each Phylax track, and how its
ground truth is recorded. It is the reference that miners, validators, and the
analysis harness all build against.

## Why this is organised by track

The four Phylax tracks are isolated. Their artifacts have different shapes, and
their ground truth is scored differently. There is no shared evaluation path and
no cross-track comparison.

- A **skill** is a bundle, scored on dual-plane evidence (action plane + context plane).
- An **MCP server** is a manifest plus a server, scored on tool integrity and poisoning.
- A **package** is an install-hooked manifest, scored on install-time and import-time behavior.
- A **repository** is a source tree, scored on recovered known vulnerabilities (recall).

Each track therefore has its own folder, its own artifact layout, and its own
label format.

## Folder layout

```
corpora/
├── README.md            this file
├── SCHEMA.md            the shared label/metadata schema
├── skills/
│   ├── README.md
│   ├── known-good/      benign skills (measure false positives)
│   ├── known-bad/       malicious skills (measure detection)
│   └── _label.example.json
├── mcp_servers/
│   ├── README.md
│   ├── known-good/
│   ├── known-bad/
│   └── _label.example.json
├── packages/
│   ├── README.md
│   ├── known-good/
│   ├── known-bad/
│   └── _label.example.json
└── repositories/
    ├── README.md
    ├── known-good/
    ├── known-bad/
    └── _label.example.json
```

## The one invariant that matters most

**Every artifact carries a `label.json` next to it, and the label format for a
track must line up exactly with that track's SSSA evidence schema, because the
label is the ground truth a miner's SSSA is scored against.**

If the label format and the SSSA evidence schema drift apart, scoring breaks.
When you change a track's evidence schema, update that track's label format in
the same change.

## known-good vs known-bad

- `known-good/` holds benign artifacts. They measure the **false positive rate**:
  a good agent should return ALLOW and an empty findings list for these.
- `known-bad/` holds malicious artifacts. They measure **detection**: a good agent
  should return BLOCK (or WARN) and recover the expected findings.

A near-miss subfolder (benign artifacts that superficially resemble threats) can
be added per track to calibrate over-blocking, but is optional.

## How a label is used

For the three detonation tracks (skills, mcp_servers, packages), the label's
`expected_findings` and `expected_capabilities` are compared against what the
miner's agent reports after detonating the artifact, and the evidence gate
(probe-in-traces + dual-plane) must be satisfied.

For the repositories track, the label's `expected_findings` IS the benchmark: the
agent is scored on how many known vulnerabilities it recovers (recall). There is
no probe and no capabilities block for this track.

See `SCHEMA.md` for the shared label fields, and each track's `README.md` for the
track-specific shape.
