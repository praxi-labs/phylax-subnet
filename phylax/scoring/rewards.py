from __future__ import annotations

from collections.abc import Iterable

from phylax.scoring.metrics import AxisScores

W_DETECTION = 0.45
W_EVIDENCE = 0.30
W_POLICY = 0.20
W_EFFICIENCY = 0.05


def compute_total_score(axes: AxisScores) -> float:
    """Weighted linear sum. This is the value that drives emissions."""
    d = _clip01(axes.detection)
    e = _clip01(axes.evidence)
    p = _clip01(axes.policy)
    f = _clip01(axes.efficiency)
    return W_DETECTION * d + W_EVIDENCE * e + W_POLICY * p + W_EFFICIENCY * f


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
    if x != x:  # NaN guard
        return 0.0
    return max(0.0, min(1.0, float(x)))
