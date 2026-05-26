from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from phylax.protocol import SSSA, Verdict


@dataclass
class AxisScores:
    detection: float
    evidence: float
    policy: float
    efficiency: float

    def as_tuple(self) -> tuple[float, float, float, float]:
        return (self.detection, self.evidence, self.policy, self.efficiency)


_V_RANK = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}

LAMBDA_FALSE_NEGATIVE = 1.0
LAMBDA_FALSE_POSITIVE = 0.4


def _verdict_rank(v: str | Verdict) -> int:
    if isinstance(v, str):
        v = Verdict(v.upper())
    return _V_RANK[v]


def score_detection(sssa: SSSA, task: dict) -> float:
    predicted = _verdict_rank(sssa.verdict.decision)
    truth = _verdict_rank(task.get("expected_verdict", "ALLOW"))

    distance = abs(predicted - truth)
    if distance == 0:
        return 1.0

    lam = LAMBDA_FALSE_POSITIVE if predicted > truth else LAMBDA_FALSE_NEGATIVE
    base = max(0.0, 1.0 - lam * distance / 2.0)

    expected_risk = task.get("expected_risk_score")
    if expected_risk is not None and distance == 0:
        delta = abs(sssa.verdict.risk_score - int(expected_risk)) / 100.0
        base *= max(0.9, 1.0 - 0.1 * delta)
    return base


def score_evidence(sssa: SSSA, task: dict) -> float:
    """Hash-equality between miner's evidence and validator's baseline replay.

    Two semantics that look subtle but matter a lot:

    1. **Canary gate on F (filesystem).** The harness writes + reads a
       per-task canary file at startup, so the validator's baseline always
       produces a non-null fs_trace_hash. A miner whose F is null (or
       different from validator's) demonstrably didn't run the sandbox
       honestly — short-circuit to 0 regardless of other axes. This is the
       proof-of-execution gate.

    2. **Vacuous matches count.** When both miner and validator agree
       there's nothing to observe on an axis (e.g. both N=None because the
       skill made no network calls), that's a real agreement signal — an
       honest miner observing a benign skill shouldn't be punished for the
       skill being benign. Use `==` rather than `is not None and ==`, since
       `None == None` is True.
    """
    miner_hashes = sssa.evidence.component_hashes()
    truth = task.get("ground_truth_evidence") or {}

    if truth:
        truth_f = truth.get("F")
        if truth_f is not None and miner_hashes.get("F") != truth_f:
            return 0.0

        matches = sum(
            1
            for k in ("N", "F", "P", "K")
            if miner_hashes.get(k) == truth.get(k)
        )
        return matches / 4.0

    components = [miner_hashes[k] for k in ("N", "F", "P", "K")]
    if any(h is None for h in components):
        return 0.0
    if any(not _is_sha256_ref(h) for h in components):
        return 0.0
    return 0.5


def _is_sha256_ref(s: str | None) -> bool:
    return bool(s) and s.startswith("sha256:") and len(s) == 71


POLICY_BETA = 0.5


def _policy_constraint_set(policy: dict | object) -> set[tuple[str, str]]:
    if hasattr(policy, "model_dump"):
        p = policy.model_dump()
    elif hasattr(policy, "dict"):
        p = policy.dict()
    elif isinstance(policy, dict):
        p = policy
    else:
        p = {}

    out: set[tuple[str, str]] = set()
    for dom in p.get("egress_allowlist", []) or []:
        out.add(("egress", dom))
    for dom in p.get("egress_denylist", []) or []:
        out.add(("deny_egress", dom))
    for env in p.get("env_allowlist", []) or []:
        out.add(("env", env))
    fs = p.get("filesystem") or {}
    for path in fs.get("read_only", []) or []:
        out.add(("fs_read", path))
    for path in fs.get("restricted_write", []) or []:
        out.add(("fs_write", path))
    out.add(("shell_access", str(bool(p.get("shell_access", False)))))
    return out


def score_policy(sssa: SSSA, task: dict) -> float:
    miner = _policy_constraint_set(sssa.recommended_policy)
    expected = _policy_constraint_set(task.get("expected_policy", {}) or {})

    if not miner and not expected:
        return 1.0
    if not miner or not expected:
        return 0.0

    intersection = len(miner & expected)
    precision = intersection / len(miner) if miner else 0.0
    recall = intersection / len(expected) if expected else 0.0

    if precision == 0.0 and recall == 0.0:
        f_beta = 0.0
    else:
        b2 = POLICY_BETA * POLICY_BETA
        f_beta = (1 + b2) * precision * recall / (b2 * precision + recall + 1e-9)

    expected_pol = task.get("expected_policy", {}) or {}
    mem_factor = _envelope_factor(
        sssa.recommended_policy.max_memory_mb,
        expected_pol.get("max_memory_mb", 256),
    )
    to_factor = _envelope_factor(
        sssa.recommended_policy.timeout_seconds,
        expected_pol.get("timeout_seconds", 30),
    )
    envelope_penalty = (mem_factor + to_factor) / 2.0

    return max(0.0, min(1.0, f_beta * (0.8 + 0.2 * envelope_penalty)))


def _envelope_factor(actual: int, expected: int) -> float:
    if expected <= 0:
        return 1.0
    ratio = max(actual, 1) / expected
    if 0.5 <= ratio <= 2.0:
        return 1.0
    return max(0.0, 1.0 - abs(math.log2(ratio)) / 4.0)


TAU_MIN_MS = {
    "fast": 200,
    "standard": 2_000,
    "deep": 10_000,
}
TAU_MAX_MS = {
    "fast": 30_000,
    "standard": 180_000,
    "deep": 900_000,
}


def score_efficiency(sssa: SSSA, task: dict) -> float:
    profile = task.get("test_profile", "standard")
    tau_min = TAU_MIN_MS.get(profile, TAU_MIN_MS["standard"])
    tau_max = TAU_MAX_MS.get(profile, TAU_MAX_MS["standard"])

    tau = task.get("submission_latency_ms")
    if tau is None:
        tau = sssa.run_metadata.analysis_duration_ms
        cap = 0.7
    else:
        cap = 1.0

    if tau < tau_min:
        return 0.0

    mu_tau = float(task.get("median_latency_ms") or tau_max // 2)
    denom = max(1.0, tau_max - mu_tau)
    return max(0.0, min(cap, 1.0 - (tau - mu_tau) / denom))


def score_all_axes(sssa: SSSA, task: dict) -> AxisScores:
    return AxisScores(
        detection=score_detection(sssa, task),
        evidence=score_evidence(sssa, task),
        policy=score_policy(sssa, task),
        efficiency=score_efficiency(sssa, task),
    )


def round_median_latency(latencies_ms: Iterable[int]) -> float:
    arr = sorted(int(x) for x in latencies_ms if x is not None and x > 0)
    if not arr:
        return 0.0
    n = len(arr)
    if n % 2 == 1:
        return float(arr[n // 2])
    return (arr[n // 2 - 1] + arr[n // 2]) / 2.0

