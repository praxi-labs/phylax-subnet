import pytest

from phylax.protocol import (
    SCHEMA_VERSION,
    SSSA,
    EvidencePack,
    PhylaxSynapse,
    RecommendedPolicy,
    SkillBundle,
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
    compute_total_score,
    score_detection,
    score_efficiency,
    score_evidence,
    score_policy,
)

# ---------------------------------------------------------------------------
# §3 — SSSA schema canonical JSON stability
# ---------------------------------------------------------------------------


def test_canonical_json_is_stable():
    """§3 — canonical JSON must be byte-stable so signatures verify reliably."""
    sssa = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
    )
    a = sssa.canonical_json()
    b = sssa.canonical_json()
    assert a == b


def test_schema_version_is_1_1_0():
    assert SCHEMA_VERSION == "1.1.0"


# ---------------------------------------------------------------------------
# §5.1 — Synapse carries a nonce
# ---------------------------------------------------------------------------


def test_synapse_has_nonce_field():
    """§5.1 — the wire object MUST carry a per-miner nonce."""
    syn = PhylaxSynapse(
        skill_bundle=SkillBundle(bundle_hash="sha256:" + "0" * 64),
        nonce=42,
    )
    assert syn.nonce == 42


# ---------------------------------------------------------------------------
# §5.3 — Composite weights and aggregation
# ---------------------------------------------------------------------------


def test_section_5_3_axis_weights():
    """§5.3 reference weight table."""
    assert (W_DETECTION, W_EVIDENCE, W_POLICY, W_EFFICIENCY) == (0.45, 0.30, 0.20, 0.05)
    assert W_DETECTION + W_EVIDENCE + W_POLICY + W_EFFICIENCY == pytest.approx(1.0)


def test_section_5_3_composite_formula():
    """§5.3 — Q = w_α·α + w_ε·ε + w_π·π + w_η·η."""
    axes = AxisScores(detection=0.9, evidence=0.8, policy=0.7, efficiency=0.6)
    expected = 0.45 * 0.9 + 0.30 * 0.8 + 0.20 * 0.7 + 0.05 * 0.6
    assert compute_total_score(axes) == pytest.approx(expected)


# ---------------------------------------------------------------------------
# §5.3 Dimension 1 — asymmetric verdict penalty
# ---------------------------------------------------------------------------


def test_section_5_3_detection_asymmetry_false_negative_costs_more():
    """λ_FN = 1.0, λ_FP = 0.4."""
    fn = score_detection(
        SSSA(
            skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
            verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        ),
        {"expected_verdict": "BLOCK"},
    )
    fp = score_detection(
        SSSA(
            skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
            verdict=VerdictBlock(decision=Verdict.BLOCK, risk_score=80, confidence=0.9, summary=""),
        ),
        {"expected_verdict": "ALLOW"},
    )
    # FN (predicted=0, truth=2) ⇒ 1 - 1.0 * 2 / 2 = 0
    # FP (predicted=2, truth=0) ⇒ 1 - 0.4 * 2 / 2 = 0.6
    assert fn == pytest.approx(0.0)
    assert fp == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# §5.3 Dimension 2 — Evidence integrity is hash equality
# ---------------------------------------------------------------------------


def test_section_5_3_evidence_zero_without_replay_match():
    """ε = 0 when miner hashes don't match the validator's replay hashes."""
    sssa = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        evidence=EvidencePack(
            network_trace_hash="sha256:" + "a" * 64,
            fs_trace_hash="sha256:" + "a" * 64,
            process_trace_hash="sha256:" + "a" * 64,
            secrets_trace_hash="sha256:" + "a" * 64,
        ),
    )
    gt = {k: "sha256:" + "b" * 64 for k in ("N", "F", "P", "K")}
    assert score_evidence(sssa, {"ground_truth_evidence": gt}) == 0.0


# ---------------------------------------------------------------------------
# §5.3 Dimension 4 — τ_min floor
# ---------------------------------------------------------------------------


def test_section_5_3_efficiency_floor():
    """η = 0 if τ_i < τ_min."""
    sssa = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
    )
    assert score_efficiency(sssa, {"test_profile": "standard", "submission_latency_ms": 10}) == 0.0


# ---------------------------------------------------------------------------
# §5.3 Dimension 3 — Precision-weighted policy effectiveness
# ---------------------------------------------------------------------------


def test_section_5_3_policy_precision_weighted():
    """Over-permissive policies score worse than precise ones."""
    base = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        recommended_policy=RecommendedPolicy(egress_allowlist=["api.stripe.com"]),
    )
    over = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        recommended_policy=RecommendedPolicy(egress_allowlist=["api.stripe.com", "evil.example"]),
    )
    task = {"expected_policy": {"egress_allowlist": ["api.stripe.com"]}}
    assert score_policy(base, task) > score_policy(over, task)


# ---------------------------------------------------------------------------
# §6.2 — Validator countersignature surface exists
# ---------------------------------------------------------------------------


def test_section_6_2_countersignature_field_exists():
    sssa = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
    )
    assert "countersignature" in sssa.model_dump()


# ---------------------------------------------------------------------------
# §7.4 — All seven corpus families recognised
# ---------------------------------------------------------------------------


def test_section_7_4_seven_families():
    from phylax.validator.corpus import FAMILIES

    assert set(FAMILIES) == {
        "known_bad",
        "known_good",
        "near_miss",
        "adversarial",
        "canaries",
        "regression",
        "synthetic",
    }
