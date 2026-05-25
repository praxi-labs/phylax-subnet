import pytest

from phylax.protocol import (
    SSSA,
    EvidencePack,
    RecommendedPolicy,
    RunMetadata,
    SkillIdentity,
    Verdict,
    VerdictBlock,
)
from phylax.scoring import (
    W_DETECTION,
    W_EFFICIENCY,
    W_EVIDENCE,
    W_POLICY,
    AxisScores,
    aggregate_epoch,
    compute_harmonic_score,
    compute_total_score,
    round_median_latency,
    score_detection,
    score_efficiency,
    score_evidence,
    score_policy,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _sssa(
    *,
    verdict: str = "ALLOW",
    risk: int = 5,
    duration_ms: int = 10_000,
    hashes: dict | None = None,
    policy: dict | None = None,
) -> SSSA:
    hashes = hashes or {
        "N": "sha256:" + "1" * 64,
        "F": "sha256:" + "2" * 64,
        "P": "sha256:" + "3" * 64,
        "K": "sha256:" + "4" * 64,
    }
    return SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(
            decision=Verdict(verdict),
            risk_score=risk,
            confidence=0.9,
            summary="s",
        ),
        evidence=EvidencePack(
            network_trace_hash=hashes.get("N"),
            fs_trace_hash=hashes.get("F"),
            process_trace_hash=hashes.get("P"),
            secrets_trace_hash=hashes.get("K"),
            sandbox_log_hash="sha256:" + "5" * 64,
        ),
        recommended_policy=RecommendedPolicy(**(policy or {})),
        run_metadata=RunMetadata(determinism_seed=42, analysis_duration_ms=duration_ms),
    )


# ---------------------------------------------------------------------------
# Detection (α)  asymmetric verdict penalty
# ---------------------------------------------------------------------------


def test_detection_perfect_verdict_gets_one():
    task = {"expected_verdict": "ALLOW", "expected_risk_score": 5}
    assert score_detection(_sssa("ALLOW", 5), task) == pytest.approx(1.0)


def test_detection_false_negative_costs_more_than_false_positive():
    """λ_FN = 1.0, λ_FP = 0.4. ALLOW-for-BLOCK should score worse than BLOCK-for-ALLOW."""
    fn_task = {"expected_verdict": "BLOCK", "expected_risk_score": 90}
    fp_task = {"expected_verdict": "ALLOW", "expected_risk_score": 5}
    fn = score_detection(_sssa("ALLOW", 5), fn_task)
    fp = score_detection(_sssa("BLOCK", 90), fp_task)
    assert fn < fp


def test_detection_warn_adjacency_is_softer_than_allow_block_gap():
    block_task = {"expected_verdict": "BLOCK"}
    warn_only = score_detection(_sssa("WARN", 50), block_task)
    allow_only = score_detection(_sssa("ALLOW", 5), block_task)
    assert warn_only > allow_only


# ---------------------------------------------------------------------------
# Evidence (ε)  hash equality
# ---------------------------------------------------------------------------


def test_evidence_all_match_full_score():
    truth = {
        "N": "sha256:" + "a" * 64,
        "F": "sha256:" + "b" * 64,
        "P": "sha256:" + "c" * 64,
        "K": "sha256:" + "d" * 64,
    }
    sssa = _sssa(hashes=truth)
    score = score_evidence(sssa, {"ground_truth_evidence": truth})
    assert score == pytest.approx(1.0)


def test_evidence_zero_when_hashes_diverge():
    truth = {
        "N": "sha256:" + "a" * 64,
        "F": "sha256:" + "b" * 64,
        "P": "sha256:" + "c" * 64,
        "K": "sha256:" + "d" * 64,
    }
    miner_hashes = {k: "sha256:" + ("f" * 64) for k in truth}
    sssa = _sssa(hashes=miner_hashes)
    score = score_evidence(sssa, {"ground_truth_evidence": truth})
    assert score == 0.0


def test_evidence_partial_match_proportional():
    truth = {
        "N": "sha256:" + "a" * 64,
        "F": "sha256:" + "b" * 64,
        "P": "sha256:" + "c" * 64,
        "K": "sha256:" + "d" * 64,
    }
    miner_hashes = dict(truth)
    miner_hashes["K"] = "sha256:" + "e" * 64  # one mismatch
    sssa = _sssa(hashes=miner_hashes)
    score = score_evidence(sssa, {"ground_truth_evidence": truth})
    assert score == pytest.approx(0.75)


def test_evidence_degraded_mode_capped():
    """Without ground-truth replay, presence-only path caps at 0.5."""
    sssa = _sssa()
    assert score_evidence(sssa, {}) <= 0.5


def test_evidence_zero_when_miner_returns_no_evidence():
    """A miner that returns an SSSA with no component hashes earns zero on
    the evidence axis, on both the truth-replay path AND the degraded
    fall-through path. This is the contract that protects validators from
    miners that skip Layer 3 entirely."""
    empty_hashes = {"N": None, "F": None, "P": None, "K": None}
    sssa = _sssa(hashes=empty_hashes)

    # Truth-replay path: validator has ground truth, miner has nothing
    truth = {
        "N": "sha256:" + "a" * 64,
        "F": "sha256:" + "b" * 64,
        "P": "sha256:" + "c" * 64,
        "K": "sha256:" + "d" * 64,
    }
    assert score_evidence(sssa, {"ground_truth_evidence": truth}) == 0.0

    # Degraded path: no ground truth available, miner has nothing
    assert score_evidence(sssa, {}) == 0.0


def test_evidence_zero_when_miner_returns_malformed_hashes():
    """Hashes that aren't well-formed sha256 refs earn zero in degraded
    mode — prevents 'random string in hash field' griefing."""
    junk = {k: "not-a-real-hash" for k in ("N", "F", "P", "K")}
    sssa = _sssa(hashes=junk)
    assert score_evidence(sssa, {}) == 0.0


# ---------------------------------------------------------------------------
# Policy (π)  F0.5 over constraint set
# ---------------------------------------------------------------------------


def test_policy_perfect_match():
    sssa = _sssa(policy={"egress_allowlist": ["api.stripe.com"], "env_allowlist": ["K1"]})
    task = {"expected_policy": {"egress_allowlist": ["api.stripe.com"], "env_allowlist": ["K1"]}}
    assert score_policy(sssa, task) >= 0.9


def test_policy_over_permissive_hurts_precision():
    sssa = _sssa(policy={"egress_allowlist": ["api.stripe.com", "evil.example"]})
    task = {"expected_policy": {"egress_allowlist": ["api.stripe.com"]}}
    over = score_policy(sssa, task)
    sssa_exact = _sssa(policy={"egress_allowlist": ["api.stripe.com"]})
    exact = score_policy(sssa_exact, task)
    assert over < exact


# ---------------------------------------------------------------------------
# Efficiency (η)  τ_min floor + median-anchored decay
# ---------------------------------------------------------------------------


def test_efficiency_floor_blocks_implausibly_fast():
    task = {"test_profile": "standard", "submission_latency_ms": 100}
    assert score_efficiency(_sssa(), task) == 0.0


def test_efficiency_at_median_full_credit():
    task = {
        "test_profile": "standard",
        "submission_latency_ms": 50_000,
        "median_latency_ms": 50_000,
    }
    assert score_efficiency(_sssa(), task) == 1.0


def test_efficiency_falls_off_as_latency_grows():
    base = {"test_profile": "standard", "median_latency_ms": 50_000}
    fast = score_efficiency(_sssa(), {**base, "submission_latency_ms": 60_000})
    slow = score_efficiency(_sssa(), {**base, "submission_latency_ms": 170_000})
    assert fast > slow


def test_efficiency_self_report_capped():
    """When the validator didn't measure latency, falls back to miner self-report but caps at 0.7."""
    score = score_efficiency(_sssa(duration_ms=10_000), {"test_profile": "standard"})
    assert 0.0 <= score <= 0.7


# ---------------------------------------------------------------------------
# Composite + weights
# ---------------------------------------------------------------------------


def test_weights_match_whitepaper():
    assert W_DETECTION == 0.45
    assert W_EVIDENCE == 0.30
    assert W_POLICY == 0.20
    assert W_EFFICIENCY == 0.05
    assert W_DETECTION + W_EVIDENCE + W_POLICY + W_EFFICIENCY == pytest.approx(1.0)


def test_composite_is_linear_weighted_sum():
    axes = AxisScores(detection=0.8, evidence=0.6, policy=0.4, efficiency=0.2)
    expected = (
        W_DETECTION * 0.8 + W_EVIDENCE * 0.6 + W_POLICY * 0.4 + W_EFFICIENCY * 0.2
    )
    assert compute_total_score(axes) == pytest.approx(expected)


def test_harmonic_diagnostic_exists_and_differs():
    axes = AxisScores(detection=1.0, evidence=0.0, policy=1.0, efficiency=1.0)
    linear = compute_total_score(axes)
    harmonic = compute_harmonic_score(axes)
    assert linear > harmonic  # harmonic collapses on the zero axis


def test_aggregate_epoch_is_arithmetic_mean():
    assert aggregate_epoch([0.2, 0.4, 0.6]) == pytest.approx(0.4)
    assert aggregate_epoch([]) == 0.0


def test_round_median_latency_basic():
    assert round_median_latency([10, 20, 30]) == 20.0
    assert round_median_latency([10, 30]) == 20.0
    assert round_median_latency([]) == 0.0
