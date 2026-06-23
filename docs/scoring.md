# Scoring

Scoring runs in the validator, not on a server. The validator verifies the proof
of execution, then scores every track on the same spine: verdict correctness
(0.40), solution quality (0.35), and benchmark agreement (0.25), all multiplied by
evidence integrity, which is also a hard gate. It maintains each miner's running
score and rerun pass rate locally, ranks by their product, applies the per-track
shares and the 5% contribution pool, and sets weights on chain. Yuma consensus
aggregates the validators by stake.

The full spine, the capability taxonomy, and a worked example are in the canonical
docs:

https://docs.phyi.dev/core/scoring
