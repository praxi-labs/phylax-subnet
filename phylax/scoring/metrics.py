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


_PROVENANCE_WEIGHT_DEFAULTS = {
    "human":             1.0,
    "consensus":         0.7,
    "consensus_expired": 0.4,
}


def _provenance_weight(task: dict) -> float:
    metadata = task.get("metadata") or {}
    annotated_by = metadata.get("annotated_by") or task.get("annotated_by")
    if annotated_by is None:
        return 1.0
    weights = metadata.get("provenance_weights") or _PROVENANCE_WEIGHT_DEFAULTS
    weight = weights.get(annotated_by)
    if weight is None:
        raise ValueError(
            f"unknown annotated_by={annotated_by!r} on task "
            f"{task.get('bundle_hash')!r}; row should not be in "
            "Track A scoring. Check batch construction."
        )
    return float(weight)


def _verdict_rank(v: str | Verdict) -> int:
    if isinstance(v, str):
        v = Verdict(v.upper())
    return _V_RANK[v]


def score_detection(sssa: SSSA, task: dict) -> float:
    predicted = _verdict_rank(sssa.verdict.decision)
    truth = _verdict_rank(task.get("expected_verdict", "ALLOW"))

    distance = abs(predicted - truth)
    if distance == 0:
        base = 1.0
    else:
        lam = LAMBDA_FALSE_POSITIVE if predicted > truth else LAMBDA_FALSE_NEGATIVE
        base = max(0.0, 1.0 - lam * distance / 2.0)

    expected_risk = task.get("expected_risk_score")
    if expected_risk is not None and distance == 0:
        delta = abs(sssa.verdict.risk_score - int(expected_risk)) / 100.0
        base *= max(0.9, 1.0 - 0.1 * delta)

    return base * _provenance_weight(task)


def score_evidence(sssa: SSSA, task: dict) -> float:
    metadata = task.get("metadata") or {}
    skill_type = metadata.get("skill_type") or task.get("skill_type")
    if skill_type == "declarative":
        return score_evidence_declarative(sssa, task)

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


def score_evidence_declarative(sssa: SSSA, task: dict) -> float:
    expected = (task.get("metadata") or {}).get("declarative_canary_id") \
               or task.get("declarative_canary_id")
    miner_canary = _extract_miner_canary(sssa)
    if expected is None:
        miner_findings = _miner_declarative_findings_count(sssa)
        return 0.5 if miner_findings > 0 else 0.0
    if miner_canary is None or miner_canary != expected:
        return 0.0
    return 1.0


def _extract_miner_canary(sssa: SSSA) -> str | None:
    evidence = getattr(sssa, "evidence", None)
    declarative = getattr(evidence, "declarative", None) if evidence else None
    if declarative is not None:
        cid = getattr(declarative, "canary_id_found", None)
        if cid is None and isinstance(declarative, dict):
            cid = declarative.get("canary_id_found")
        if cid:
            return str(cid)
    refs = getattr(sssa, "evidence_refs", None) or {}
    if isinstance(refs, dict):
        cid = refs.get("declarative_canary_id") or refs.get("canary_id_found")
        if cid:
            return str(cid)
    return None


def _miner_declarative_findings_count(sssa: SSSA) -> int:
    evidence = getattr(sssa, "evidence", None)
    declarative = getattr(evidence, "declarative", None) if evidence else None
    if declarative is None:
        return 0
    n = getattr(declarative, "findings_count", None)
    if n is None and isinstance(declarative, dict):
        n = declarative.get("findings_count", 0)
    try:
        return int(n or 0)
    except (TypeError, ValueError):
        return 0


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


_TIME_SWEET_SPOT_FRAC = 0.25
_TIME_DEADLINE_FLOOR = 0.60


def score_time_window(
    completion_ms: int,
    *,
    deadline_seconds: int,
    t_min_seconds: int,
    has_evidence: bool,
) -> float:
    if not has_evidence:
        return 0.0
    if deadline_seconds <= t_min_seconds:
        return _TIME_DEADLINE_FLOOR
    completion_sec = max(0.0, completion_ms / 1000.0)
    if completion_sec < t_min_seconds:
        return 0.0
    window = deadline_seconds - t_min_seconds
    elapsed = completion_sec - t_min_seconds
    fraction = min(1.0, elapsed / window)
    if fraction <= _TIME_SWEET_SPOT_FRAC:
        return fraction / _TIME_SWEET_SPOT_FRAC
    decay = (fraction - _TIME_SWEET_SPOT_FRAC) / (1.0 - _TIME_SWEET_SPOT_FRAC)
    return 1.0 - decay * (1.0 - _TIME_DEADLINE_FLOOR)


def score_efficiency(sssa: SSSA, task: dict) -> float:
    metadata = task.get("metadata") or {}
    deadline_s = metadata.get("deadline_seconds") or task.get("deadline_seconds")
    t_min_s = metadata.get("t_min_seconds") or task.get("t_min_seconds")
    if deadline_s and t_min_s:
        tau = task.get("submission_latency_ms")
        if tau is None:
            tau = sssa.run_metadata.analysis_duration_ms
        miner_hashes = sssa.evidence.component_hashes()
        has_evidence = any(miner_hashes.get(k) for k in ("N", "F", "P", "K"))
        return score_time_window(
            int(tau),
            deadline_seconds=int(deadline_s),
            t_min_seconds=int(t_min_s),
            has_evidence=has_evidence,
        )

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


def task_skill_type(task: dict) -> str:
    metadata = task.get("metadata") or {}
    skill_type = metadata.get("skill_type") or task.get("skill_type")
    if skill_type in ("executable", "declarative", "mixed"):
        return skill_type
    return "executable"


def canary_outcome(sssa: SSSA, task: dict) -> str | None:
    skill_type = task_skill_type(task)
    metadata = task.get("metadata") or {}

    if skill_type == "declarative":
        expected_canary = metadata.get("declarative_canary_id") \
                          or task.get("declarative_canary_id")
        if not expected_canary:
            return None
        miner_canary = _extract_miner_canary(sssa)
        return "pass" if miner_canary == expected_canary else "fail"

    truth = task.get("ground_truth_evidence") or {}
    truth_f = truth.get("F")
    if truth_f is None:
        return None
    miner_hashes = sssa.evidence.component_hashes()
    return "pass" if miner_hashes.get("F") == truth_f else "fail"


def round_median_latency(latencies_ms: Iterable[int]) -> float:
    arr = sorted(int(x) for x in latencies_ms if x is not None and x > 0)
    if not arr:
        return 0.0
    n = len(arr)
    if n % 2 == 1:
        return float(arr[n // 2])
    return (arr[n // 2 - 1] + arr[n // 2]) / 2.0

