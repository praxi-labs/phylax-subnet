# Skills Corpus

A skill is a bundle that extends an agent: a `SKILL.md` of instructions, plus
optional scripts, tool bindings, and resources. Skills are the broadest artifact,
because one skill can carry instructions, executable code, and delegation at once.

## Artifact layout

```
skills/known-bad/credential-stealer/
├── SKILL.md          the entrypoint: instructions and metadata
├── scripts/          optional bundled scripts the skill may run
│   └── backup.py
└── label.json        the ground truth
```

The entrypoint is always `SKILL.md`. Front-matter (between `---` lines) carries the
name and description; the body carries the instructions the agent reads.

## How a skill is analysed

Skills are a **detonation track**. The miner's agent loads the skill into the sandbox,
executes it, threads the probe through, and captures the fs/network/process traces.
The evidence is **dual-plane**:

- **action plane**: the canonical capabilities the skill exercised at runtime
  (file writes, network egress, secret reads, process spawns, etc.).
- **context plane**: the instructions and content the skill injected into the agent's
  reasoning (prompt injection, hidden instructions, loaded context). Skills are the
  classic injection vector, so the context plane matters intensely here.

The **evidence gate** is: probe events present in the traces, trace hashes consistent,
and both planes populated. Insufficient or inconsistent evidence scores zero regardless
of the verdict.

## What the label scores against

- `expected_capabilities`: the canonical capabilities a correct agent should observe.
- `expected_findings`: the findings a correct agent should recover, each carrying a
  `plane` of action or context.

## Finding categories for skills

The benchmark should cover all six skill attack classes:

- `instruction_injection`: misleading instructions embedded in SKILL.md.
- `permission_overreach`: the skill elicits more capability or context than the task needs.
- `transitive_poisoning`: a bundled script or invoked skill carries the malice.
- `transitive_leakage`: one part reads sensitive data, another exfiltrates it.
- `context_injection`: the skill pulls in external content carrying adversarial instructions.
- `rug_pull`: a later version changes behavior after the skill earns trust.

## known-good vs known-bad

- `known-good/`: benign skills. Correct verdict ALLOW, empty findings. Measures false positives.
- `known-bad/`: malicious skills. Correct verdict BLOCK (or WARN), with the expected findings.

See `_label.example.json` for the full label format, and the example artifacts under
`known-good/` and `known-bad/`.
