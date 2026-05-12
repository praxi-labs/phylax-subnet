"""
phylax/scoring/metrics.py

Per-axis scoring functions for an SSSA against ground-truth task metadata.

Four axes:
    1. Detection accuracy    (45%)
    2. Evidence integrity    (25%)
    3. Policy effectiveness  (20%)
    4. Efficiency            (10%)

Each axis returns a float in [0.0, 1.0]. Axis weights are applied later
in phylax.scoring.rewards.compute_total_score.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

from phylax.protocol import SSSA, Verdict


@dataclass
class AxisScores:
    detection:  float
    evidence:   float
    policy:     float
    efficiency: float


# ---------------------------------------------------------------------------
# Axis 1 — Detection accuracy
# ---------------------------------------------------------------------------

VERDICT_DISTANCE = {
    # Distance between predicted and true verdict, normalised to [0, 1]
    ("ALLOW", "ALLOW"): 0.0,
    ("WARN",  "WARN"):  0.0,
    ("BLOCK", "BLOCK"): 0.0,
    ("ALLOW", "WARN"):  0.4,
    ("WARN",  "ALLOW"): 0.4,
    ("WARN",  "BLOCK"): 0.4,
    ("BLOCK", "WARN"):  0.4,
    ("ALLOW", "BLOCK"): 1.0,
    ("BLOCK", "ALLOW"): 1.0,
}


def score_detection(sssa: SSSA, task: dict) -> float:
    """
    1.0  if predicted verdict matches ground truth and risk_score is close
    0.0  if catastrophically wrong (BLOCK vs ALLOW)

    Penalty is the weighted sum of verdict-distance and risk-score-distance.
    """
    truth = task.get("expected_verdict", "ALLOW").upper()
    pred  = sssa.verdict.decision.value
    truth_risk = task.get("expected_risk_score", 0)
    pred_risk  = sssa.verdict.risk_score

    verdict_penalty = VERDICT_DISTANCE.get((pred, truth), 1.0)
    # Risk-score MSE (normalised by 100^2)
    risk_penalty = ((pred_risk - truth_risk) / 100.0) ** 2

    # 70% verdict, 30% risk-score
    penalty = 0.7 * verdict_penalty + 0.3 * risk_penalty
    return max(0.0, 1.0 - penalty)


# ---------------------------------------------------------------------------
# Axis 2 — Evidence integrity
# ---------------------------------------------------------------------------

def score_evidence(sssa: SSSA, task: dict) -> float:
    """
    Reward miners who back claims with verifiable evidence hashes.

    Heuristic (full validators perform replay verification):
      - All evidence hashes present → 1.0
      - Each missing hash subtracts 0.2
      - Hash format invalid → 0.0
    """
    ev = sssa.evidence
    expected_hashes = [
        ev.network_trace_hash,
        ev.fs_trace_hash,
        ev.process_trace_hash,
        ev.secrets_trace_hash,
        ev.sandbox_log_hash,
    ]

    # Findings should also carry trace_hash references
    findings_with_hashes = sum(
        1 for f in sssa.findings if f.evidence and f.evidence.trace_hash
    )
    findings_total = max(1, len(sssa.findings))

    present_score = sum(1 for h in expected_hashes if h) / len(expected_hashes)

    bad_format = any(
        h and not h.startswith("sha256:") for h in expected_hashes
    )
    if bad_format:
        return 0.0

    finding_score = findings_with_hashes / findings_total

    # 70% from trace hashes, 30% from per-finding evidence
    return 0.7 * present_score + 0.3 * finding_score


# ---------------------------------------------------------------------------
# Axis 3 — Policy effectiveness
# ---------------------------------------------------------------------------

def score_policy(sssa: SSSA, task: dict) -> float:
    """
    A good policy reduces risk without overreach.

    Compare the recommended_policy against the task's expected policy.
    Penalise:
      - Allowing domains that should be denied (security failure)
      - Denying domains that should be allowed (over-restriction)
      - Enabling shell_access when the task says no
      - Disabling shell_access when the task requires it
    """
    expected = task.get("expected_policy", {}) or {}
    p = sssa.recommended_policy

    expected_egress = set(expected.get("egress_allowlist", []))
    actual_egress   = set(p.egress_allowlist)

    if expected_egress or actual_egress:
        union = expected_egress | actual_egress
        intersection = expected_egress & actual_egress
        egress_score = (len(intersection) / len(union)) if union else 1.0
    else:
        egress_score = 1.0

    # Shell access alignment
    expected_shell = expected.get("shell_access", False)
    shell_score = 1.0 if expected_shell == p.shell_access else 0.0

    # Memory / timeout reasonableness — within 2× of expected gets full credit
    def _envelope(actual: int, expected_val: int) -> float:
        if expected_val <= 0:
            return 1.0
        ratio = actual / expected_val
        if 0.5 <= ratio <= 2.0:
            return 1.0
        return max(0.0, 1.0 - abs(math.log2(ratio)) / 4.0)

    mem_score     = _envelope(p.max_memory_mb,    expected.get("max_memory_mb",    256))
    timeout_score = _envelope(p.timeout_seconds,  expected.get("timeout_seconds",  30))

    return 0.5 * egress_score + 0.2 * shell_score + 0.15 * mem_score + 0.15 * timeout_score


# ---------------------------------------------------------------------------
# Axis 4 — Efficiency
# ---------------------------------------------------------------------------

# Aim: 60s standard, 5min deep. Reward < target, penalise > target.
EFFICIENCY_TARGETS_MS = {
    "fast":     5_000,
    "standard": 60_000,
    "deep":     300_000,
}


def score_efficiency(sssa: SSSA, task: dict) -> float:
    profile = task.get("test_profile", "standard")
    target  = EFFICIENCY_TARGETS_MS.get(profile, 60_000)
    duration = sssa.run_metadata.analysis_duration_ms or target

    if duration <= target:
        return 1.0
    # Exponential decay beyond target
    over = duration / target
    return max(0.0, math.exp(-(over - 1.0)))


# ---------------------------------------------------------------------------

def score_all_axes(sssa: SSSA, task: dict) -> AxisScores:
    return AxisScores(
        detection  = score_detection(sssa, task),
        evidence   = score_evidence(sssa, task),
        policy     = score_policy(sssa, task),
        efficiency = score_efficiency(sssa, task),
    )
