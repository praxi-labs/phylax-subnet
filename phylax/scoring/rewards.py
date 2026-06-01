from __future__ import annotations

from collections.abc import Iterable

from phylax.scoring.legacy_metrics import AxisScores

W_DETECTION = 0.45
W_EVIDENCE = 0.30
W_POLICY = 0.20
W_EFFICIENCY = 0.05

EVIDENCE_GATE = 0.10

_NON_EVIDENCE_WEIGHT_SUM = W_DETECTION + W_POLICY + W_EFFICIENCY


def compute_total_score(axes: AxisScores) -> float:
    """Evidence-gated composite. Drives emissions.

    Diverges from the original whitepaper §5.3 linear sum: evidence is a
    multiplicative gate, not an additive term. Below ``EVIDENCE_GATE`` the
    composite is zero — no proof of execution means no reward, even if the
    other axes look perfect. Above the gate, the non-evidence axes
    (detection, policy, efficiency) are weighted, renormalised so a perfect
    miner reaches 1.0, then scaled by the evidence quality. This preserves
    smooth gradients (80% evidence ≈ 80% credit) while zeroing out true
    non-participants.
    """
    d = _clip01(axes.detection)
    e = _clip01(axes.evidence)
    p = _clip01(axes.policy)
    f = _clip01(axes.efficiency)
    if e < EVIDENCE_GATE:
        return 0.0
    non_evidence = W_DETECTION * d + W_POLICY * p + W_EFFICIENCY * f
    return (non_evidence / _NON_EVIDENCE_WEIGHT_SUM) * e


def compute_harmonic_score(axes: AxisScores) -> float:
    """Diagnostic harmonic mean. Useful for spotting single-axis collapses."""
    d = _clip01(axes.detection)
    e = _clip01(axes.evidence)
    p = _clip01(axes.policy)
    f = _clip01(axes.efficiency)
    eps = 1e-6
    weights = W_DETECTION + W_EVIDENCE + W_POLICY + W_EFFICIENCY
    denom = (
        W_DETECTION / (d + eps)
        + W_EVIDENCE / (e + eps)
        + W_POLICY / (p + eps)
        + W_EFFICIENCY / (f + eps)
    )
    return weights / denom


def aggregate_epoch(per_task_scores: Iterable[float]) -> float:
    """Arithmetic mean over the epoch's per-task composite scores."""
    arr = [_clip01(x) for x in per_task_scores]
    if not arr:
        return 0.0
    return sum(arr) / len(arr)


def _clip01(x: float) -> float:
    if x != x:
        return 0.0
    return max(0.0, min(1.0, float(x)))

