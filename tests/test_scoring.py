"""Tests for the scoring axes and harmonic-mean aggregator."""

import pytest

from phylax.protocol import (
    SSSA, SkillIdentity, VerdictBlock, Verdict, EvidencePack, RunMetadata,
)
from phylax.scoring.metrics import (
    score_detection, score_evidence, score_policy, score_efficiency,
    score_all_axes, AxisScores,
)
from phylax.scoring.rewards import compute_total_score


def _sssa(verdict="ALLOW", risk=5, duration_ms=10_000) -> SSSA:
    return SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(
            decision=Verdict(verdict),
            risk_score=risk,
            confidence=0.9,
            summary="s",
        ),
        evidence=EvidencePack(
            network_trace_hash="sha256:" + "1" * 64,
            fs_trace_hash="sha256:" + "2" * 64,
            process_trace_hash="sha256:" + "3" * 64,
            secrets_trace_hash="sha256:" + "4" * 64,
            sandbox_log_hash="sha256:" + "5" * 64,
        ),
        run_metadata=RunMetadata(analysis_duration_ms=duration_ms),
    )


def test_perfect_detection():
    task = {"expected_verdict": "ALLOW", "expected_risk_score": 5}
    assert score_detection(_sssa("ALLOW", 5), task) == pytest.approx(1.0)


def test_catastrophic_detection():
    task = {"expected_verdict": "BLOCK", "expected_risk_score": 90}
    # Predicting ALLOW for a BLOCK task is the worst possible miss.
    assert score_detection(_sssa("ALLOW", 5), task) < 0.4


def test_evidence_complete():
    task = {}
    assert score_evidence(_sssa(), task) >= 0.6


def test_evidence_missing_hashes():
    sssa = _sssa()
    sssa.evidence = EvidencePack()  # no hashes at all
    assert score_evidence(sssa, {}) == pytest.approx(0.3, abs=0.01)


def test_efficiency_within_target():
    task = {"test_profile": "standard"}
    assert score_efficiency(_sssa(duration_ms=10_000), task) == 1.0


def test_efficiency_slow_run():
    task = {"test_profile": "standard"}
    # 10× over target
    assert score_efficiency(_sssa(duration_ms=600_000), task) < 0.05


def test_harmonic_mean_punishes_weak_axis():
    axes = AxisScores(detection=1.0, evidence=0.0, policy=1.0, efficiency=1.0)
    total = compute_total_score(axes)
    assert total < 0.001  # near zero


def test_harmonic_mean_all_perfect():
    axes = AxisScores(detection=1.0, evidence=1.0, policy=1.0, efficiency=1.0)
    assert compute_total_score(axes) == pytest.approx(1.0, abs=1e-3)
