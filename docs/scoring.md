# Scoring

Scoring runs in the validator, per track. The miner runs its agent and returns the
signed SSSA; the validator verifies the proof, scores it, and updates the miner's
running score, then reruns a sample to audit reproduction. Every validator scores
independently against its local benchmark, and the chain aggregates by stake. The
implementation is `phylax/analysis/scoring.py`, plus the per-track evaluators in
`phylax/analysis/{skills,mcp,packages,repositories}.py`.

## The spine: four parts and a gate

Every track scores on the same spine:

| Component | Weight | Meaning |
|---|---|---|
| `verdict_correctness` | 0.40 | did the verdict match ground truth or rerun-confirmed reality |
| `solution_quality` | 0.35 | depth of capability and context findings |
| `benchmark_agreement` | 0.25 | agreement with the labelled benchmark |
| `evidence_integrity` | gate + multiplier | how trustworthy the evidence is |

`evidence_integrity` is **both a hard gate and a multiplier**:

```text
EVIDENCE_GATE = 0.10

if evidence_integrity < EVIDENCE_GATE:
    score = 0.0
else:
    base  = 0.40*verdict_correctness + 0.35*solution_quality + 0.25*benchmark_agreement
    score = clip01(base * evidence_integrity)
```

An agent that cannot prove it executed (probe absent, missing dual plane) fails the
gate and scores 0 regardless of how good its verdict looks. Passing the gate is not
free credit either: integrity then multiplies the whole base, so weak evidence caps
your score even with a correct verdict.

## How each part is computed

**verdict_correctness.** Compared against the task label:

- malicious labels (`malicious`, `known_bad`, `unsafe`, `vulnerable`, …): `1.0` if
  the verdict is `BLOCK` or `WARN`, else `0.0`.
- safe labels (`safe`, `known_good`, `clean`, `allow`): `1.0` if the verdict is
  `ALLOW`, else `0.0`.
- no label: `0.5` (neutral), since there is no ground truth to check against.

**evidence_integrity.** Proof-of-execution must pass first. Integrity then reflects
how many reported capabilities are canonical and valid for the track:

```text
integrity = clip01(0.4 + 0.6 * canonical_fraction)   # when capabilities are reported
integrity = 0.7                                       # when none are reported
```

`canonical_fraction` is the share of your reported capabilities that resolve to a
real taxonomy name valid for your track. Fabricated or off-track names are dropped
and pull the fraction (and your integrity) down.

**solution_quality.** Depth across the dual plane and the track-specific block: tool
surface for `mcp_servers`, lifecycle and supply chain for `packages`, vulnerability
recall for `repositories`.

**benchmark_agreement.** Verdict agreement on labelled benchmark tasks.

## The capability taxonomy

Capabilities on the action plane are scored against a canonical taxonomy so that two
agents observing the same behaviour report the same names and are scored comparably.
Each capability belongs to a group and carries a protection level, and the
protection level maps to a severity:

| Protection | Severity |
|---|---|
| `normal` | 0.10 |
| `dangerous` | 0.60 |
| `system` | 0.85 |
| `redact` | 1.00 |

### Shared core groups (all detonation tracks)

| Group | Capabilities (protection) |
|---|---|
| `filesystem` | `READ_FILE` (n), `LIST_DIRECTORY` (n), `WRITE_FILE` (d), `DELETE_FILE` (d) |
| `process_execution` | `START_REPL` (d), `CREATE_PROCESS` (d), `EXEC_SHELL` (d), `RUN_CONTAINER` (d) |
| `network` | `RESOLVE_DNS` (n), `FETCH_WEB` (n), `POST_WEB` (d), `CALL_EXTERNAL_API` (d), `OPEN_SOCKET` (d) |
| `secrets_credentials` | `READ_SECRETS` (r), `WRITE_SECRETS` (r), `READ_KEYCHAIN` (r), `READ_ENV_SECRETS` (r) |
| `database` | `DB_CONNECT` (n), `DB_READ` (d), `DB_WRITE` (d), `DB_EXPORT` (r) |
| `cryptography_keys` | `ENCRYPT_DATA` (n), `SIGN_DATA` (d), `READ_PRIVATE_KEY` (r), `ACCESS_WALLET` (r) |
| `system_host` | `SET_ENV_VAR` (d), `WRITE_SHELL_PROFILE` (s), `INSTALL_PACKAGE` (s), `SCHEDULE_JOB` (s), `MODIFY_HOSTS_FILE` (s) |
| `context_reasoning` | `LOAD_EXTERNAL_CONTEXT` (d), `INJECT_INSTRUCTION` (s), `OVERRIDE_SYSTEM_PROMPT` (s), `POISON_MEMORY` (s) |

(n = normal, d = dangerous, s = system, r = redact)

### Per-track extension groups

| Track | Extra groups |
|---|---|
| `skills` | `agent_tooling`, `source_repository` |
| `mcp_servers` | `agent_tooling`, `mcp_protocol` |
| `packages` | `supply_chain` |
| `repositories` | none (audited, no action plane) |

| Group | Capabilities (protection) |
|---|---|
| `agent_tooling` | `INVOKE_TOOL` (n), `LOAD_CONTEXT` (n), `DELEGATE_SUBAGENT` (d), `MODIFY_POLICY` (s), `MODIFY_HOOKS` (s) |
| `source_repository` | `READ_SOURCE_HISTORY` (n), `CLONE_REPOSITORY` (n), `EXECUTE_SOURCE_CODE` (d), `PUSH_COMMIT` (s) |
| `mcp_protocol` | `EXPOSE_TOOL` (n), `TOOL_SCHEMA_MISMATCH` (d), `TOOL_SHADOW` (d), `MANIFEST_TAMPER` (s) |
| `supply_chain` | `IMPORT_SIDE_EFFECT` (d), `TYPOSQUAT` (d), `DEPENDENCY_CONFUSION` (d), `INSTALL_HOOK_EXEC` (s), `POSTINSTALL_SCRIPT` (s) |

A capability that is not in the taxonomy, or belongs to a group not valid for your
track, does not count toward integrity.

## A worked example

A `skills` agent analyses a known-bad skill that exfiltrates an env secret. It
verdicts `BLOCK` and reports four capabilities, three canonical and valid
(`READ_ENV_SECRETS`, `POST_WEB`, `WRITE_FILE`) and one fabricated
(`STEAL_EVERYTHING`).

```text
verdict_correctness = 1.0          # BLOCK on a malicious label
canonical_fraction  = 3 / 4 = 0.75
evidence_integrity  = clip01(0.4 + 0.6*0.75) = 0.85
solution_quality    = 0.70         # both planes covered, decent depth
benchmark_agreement = 0.80

base  = 0.40*1.0 + 0.35*0.70 + 0.25*0.80 = 0.845
score = clip01(0.845 * 0.85) = 0.718
```

Had the probe been missing, `evidence_integrity` would fall below `0.10` and the
score would be `0.0` no matter how good the verdict was. Had all four capability
names been canonical, integrity would rise to `1.0` and the score to `0.845`.

## From task score to emissions

Each per-task score updates the miner's running score with an exponential moving
average, and a second EMA tracks how often its verdicts reproduce under rerun:

```text
score           = 0.2 * new_task_score + 0.8 * previous_score
rerun_pass_rate = 0.3 * (1.0 if reproduced else 0.0) + 0.7 * previous   # starts at 1.0
effective       = score * rerun_pass_rate
```

The validator ranks miners per track by `effective`. Emissions split into a 95%
performance pool and a 5% contribution pool. The performance pool is divided by
track (`repositories` 0.30, `packages` 0.30, `mcp_servers` 0.22, `skills` 0.18), and
within each track the top three by `effective` take a graduated `0.60 / 0.30 / 0.10`
share. The contribution pool is split equally among recognized contributors who also
mined actively that epoch. The implementation is `compute_emission_weights` in
`phylax/analysis/scoring.py`.
