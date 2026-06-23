# Repositories Corpus

A repository is a source tree. This is the **audit track** and the structural outlier:
it does not detonate anything. The agent reads the source and reports vulnerabilities,
and is scored on how many known vulnerabilities it recovers (recall), in the style of a
code audit.

## Artifact layout

```
repositories/known-bad/sql-injection-app/
├── src/
│   ├── app.py
│   └── db.py
├── requirements.txt
└── label.json        the ground truth: the vulnerabilities to recover
```

The artifact is just a normal source repository. There is no manifest or entrypoint
convention beyond what the project itself uses.

## How a repository is analysed

Repositories are an **audit track**, not a detonation track. The miner's agent is given
the source and audits it for vulnerabilities, producing a findings list. **Nothing is
executed.** Therefore:

- There is **no probe** and **no proof-of-execution**.
- There is **no action plane or context plane**.
- There is **no capabilities block**.

This is the one track that collapses to a benchmark-recall shape. Its evidence is the
audit coverage and the recovered vulnerabilities.

## What the label scores against

The label's `expected_findings` **is the benchmark**. Each entry is a known vulnerability
the agent should recover. The agent is scored by recall: how many of the expected
vulnerabilities it found, balanced against false positives from the `known-good` set.

Each expected finding is a vulnerability:

```json
{ "category": "vulnerability", "severity": "HIGH", "cwe": "CWE-89",
  "file": "src/db.py", "line": 7,
  "title": "SQL injection via string-formatted query",
  "remediation": "Use parameterised queries with placeholders." }
```

Ground truth for this track is best drawn from real audit findings (for example, audit
contest results), because competition-grade audited vulnerabilities are a high-quality,
hard-to-game label source.

## Verification for this track

Because nothing is detonated, the proof-of-execution gate does not apply. Verification is:

- score recovered vulnerabilities against the benchmark (recall), and
- the validator may rerun the agent against the benchmark to confirm the result, since
  there is objective ground truth to compare against.

## known-good vs known-bad

- `known-good/`: clean repositories with no known vulnerabilities. A correct agent
  returns an empty findings list. Measures false positives (over-reporting).
- `known-bad/`: repositories with known vulnerabilities. A correct agent recovers them.
  Recall against this set is the primary score.

See `_label.example.json` for the full label format.
