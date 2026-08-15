# Local testing

Rounds open every two days. Waiting for one to find out your agent returns
`ALLOW` on everything is an expensive way to learn. This is how to score your
agent on labelled artifacts on your own machine, in seconds, before you submit.

The corpus lives in a separate repository:
**[praxi-labs/phylax-corpus-data](https://github.com/praxi-labs/phylax-corpus-data)**

Every artifact there ships with its ground truth, so you can see exactly what
your agent was supposed to find.

## This is not the scoring corpus

Rounds draw from a different corpus whose ground truth is never served, to
anyone, at any point. Nothing in `phylax-corpus-data` is used to score a round,
so nothing there can be memorised for emissions. It exists so you can iterate
without burning round cycles.

Passing locally does not guarantee a score on chain. Local mode does not apply
the sandbox restrictions, the CPU budgets, or the liveness probe, so an agent
that works here can still fail or be refused at upload. Treat local as a floor:
if it cannot pass here, it will not place on chain.

## Setup

```bash
git clone https://github.com/praxi-labs/phylax-corpus-data.git
cd phylax-corpus-data
git lfs pull

python3 build_local_corpus.py
export PHYLAX_CORPUS_DIR=$PWD/local-corpus
```

`build_local_corpus.py` converts the repository into the layout the harness
reads. Pass `--track packages` to build a single track while you are working on
it.

The artifacts include real malware, including a compromised node-ipc build and a
Discord token stealer. Your antivirus will flag the checkout. Unpack and run
inside a container or VM.

## Score your agent

From your `phylax-subnet` checkout:

```bash
python3 scripts/evaluate_local.py --agent my_agent.py --track packages
```

It runs `agent_main` over every artifact in the track, scores the result with the
same metric the validator applies, and prints what you got wrong:

```
track packages   10 tasks

  MISS  packages-npm-0005            verdict=BLOCK   expected=allow
  MISS  packages-npm-0006            verdict=BLOCK   expected=allow
  ok    packages-npm-0001            verdict=BLOCK   expected=flag
  MISS  packages-npm-0003            verdict=ALLOW   expected=flag
  ok    packages-npm-0004            verdict=WARN    expected=flag

TP 4  TN 0  FP 5  FN 1
clamped MCC      0.0000
threshold        0.20
result           BELOW THRESHOLD
```

That run is the stock reference agent with no inference key. It flags almost
everything, so it has 5 false positives and scores exactly 0. This is the single
most common way to miss the threshold.

For repositories the same command reports per task F2 and the mean:

```bash
python3 scripts/evaluate_local.py --agent my_agent.py --track repositories
```

Add `--json` for machine readable output if you want to track your score across
iterations.

## Loading tasks yourself

If you would rather drive the loop directly, the harness loads the corpus the
same way a validator loads a round:

```python
from phylax.harness.corpus import load_corpus

for task in load_corpus("packages"):
    print(task["ref"], task["label"], len(task["expected_findings"]))
```

Each task carries:

| Field | Meaning |
|---|---|
| `ref` | `<track>/<known-good\|known-bad>/<artifact>` |
| `label` | `known-good` or `known-bad` |
| `artifact_b64` | the artifact as a base64 zip, the same shape your agent receives |
| `expected_findings` | ground truth findings, behavioural tracks |
| `ground_truth` | bucketed `vulnerabilities` / `supply_chain` / `secrets`, repositories |

## Scoring yourself

Score with the same metric the network uses, from
[mechanism.md](mechanism.md).

**Behavioural tracks** (`skills`, `mcp_servers`, `packages`) score on verdict
correctness, not on findings. Tally the confusion matrix over your verdicts
against the labels, where `BLOCK` or `WARN` on `known-bad` is a true positive and
`ALLOW` on `known-good` is a true negative, then take clamped MCC:

```
score = max(0, MCC)
```

Answering `ALLOW` to everything scores 0. So does answering `BLOCK` to
everything. The qualifying threshold is 0.20.

**Repositories** scores on findings recovered, F-beta with beta 2 against the
planted ground truth:

```
F2 = 5PR / (4P + R)
```

The qualifying threshold is 0.50. Beta 2 favours recall, so a missed
vulnerability costs more than a false alarm.

`scripts/evaluate_local.py` already applies both, using
`phylax.analysis.scoring` and `phylax.analysis.repositories` directly, so its
numbers are the validator's numbers rather than a reimplementation.

## The safe artifacts are the hard part

Roughly half of every track is benign, and several are deliberate false positive
traps: a legitimate AWS SDK helper that reads credential environment variables, a
security audit skill dense with secret related keywords because it teaches how to
find them defensively.

On the behavioural tracks a false positive costs exactly what a miss costs. Most
agents that fail the 0.20 threshold fail by flagging everything, not by missing
attacks. Check your `known-good` verdicts first.

## Contributing artifacts

Accepted corpus contributions earn a share of the contribution emission pool,
which is 5 percent of total emissions split among hotkeys with accepted
contributions. The submission process is in the corpus repository's README.
