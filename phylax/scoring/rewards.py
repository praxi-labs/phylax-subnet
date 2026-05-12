"""
phylax/scoring/rewards.py

Aggregate per-axis scores into a single miner reward in [0, 1].

Uses the weighted harmonic mean to punish miners with any near-zero axis.
A miner with 100% detection but 0% evidence integrity scores ~0 — the
harmonic mean refuses to average away a weakness.
"""

from __future__ import annotations

from phylax.scoring.metrics import AxisScores

# Axis weights — must sum to 1.0
W_DETECTION  = 0.45
W_EVIDENCE   = 0.25
W_POLICY     = 0.20
W_EFFICIENCY = 0.10

EPS = 1e-6  # avoid div-by-zero in harmonic mean


def compute_total_score(axes: AxisScores) -> float:
    """
    Weighted harmonic mean of the four axes.

    Formula:
        TS = sum(weights) / sum(w_i / (s_i + eps))

    Properties:
        - Each axis in [0,1] ⇒ output in [0,1]
        - Any axis at zero collapses the whole score toward zero
        - All axes at 1.0 ⇒ output 1.0
    """
    s_d = max(0.0, min(1.0, axes.detection))
    s_e = max(0.0, min(1.0, axes.evidence))
    s_p = max(0.0, min(1.0, axes.policy))
    s_f = max(0.0, min(1.0, axes.efficiency))

    numerator   = W_DETECTION + W_EVIDENCE + W_POLICY + W_EFFICIENCY
    denominator = (
        W_DETECTION  / (s_d + EPS) +
        W_EVIDENCE   / (s_e + EPS) +
        W_POLICY     / (s_p + EPS) +
        W_EFFICIENCY / (s_f + EPS)
    )
    return numerator / denominator


def compute_weighted_arithmetic_score(axes: AxisScores) -> float:
    """
    Alternative scorer (less punitive): weighted arithmetic mean.

    Provided for diagnostic comparison only — NOT used to set weights.
    """
    return (
        W_DETECTION  * axes.detection  +
        W_EVIDENCE   * axes.evidence   +
        W_POLICY     * axes.policy     +
        W_EFFICIENCY * axes.efficiency
    )
