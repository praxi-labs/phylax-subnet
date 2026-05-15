import pytest

from phylax.protocol import (
    EvidencePack,
    RunMetadata,
    SkillIdentity,
    SSSA,
    Verdict,
    VerdictBlock,
)
from phylax.scoring import score_evidence


def _sssa_with_hashes(prefix: str) -> SSSA:
    """An SSSA whose evidence hashes encode the miner identity."""
    return SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        evidence=EvidencePack(
            network_trace_hash=f"sha256:{prefix * 8}",
            fs_trace_hash=f"sha256:{prefix * 8}",
            process_trace_hash=f"sha256:{prefix * 8}",
            secrets_trace_hash=f"sha256:{prefix * 8}",
            sandbox_log_hash=f"sha256:{prefix * 8}",
        ),
        run_metadata=RunMetadata(determinism_seed=12345),
    )


def test_copying_miner_fails_evidence_under_a_different_nonce():
    """Validator GT for miner B uses miner B's nonce — B's hashes differ from A's."""

    # Ground truth replayed by the validator under miner B's nonce:
    gt_B = {
        "N": "sha256:" + "b" * 64,
        "F": "sha256:" + "b" * 64,
        "P": "sha256:" + "b" * 64,
        "K": "sha256:" + "b" * 64,
    }

    # Miner A computed honestly under its own nonce — different hashes:
    miner_A_hashes_seen_by_validator_A = {k: f"sha256:{'a' * 64}" for k in gt_B}

    # Miner B copies miner A's SSSA verbatim, then submits it to the validator.
    # The validator scores miner B against GT_B, not GT_A.
    copied_sssa = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        evidence=EvidencePack(
            network_trace_hash=miner_A_hashes_seen_by_validator_A["N"],
            fs_trace_hash=miner_A_hashes_seen_by_validator_A["F"],
            process_trace_hash=miner_A_hashes_seen_by_validator_A["P"],
            secrets_trace_hash=miner_A_hashes_seen_by_validator_A["K"],
        ),
    )

    score = score_evidence(copied_sssa, {"ground_truth_evidence": gt_B})
    assert score == 0.0, "Copying must produce zero evidence credit under a different nonce"


def test_honest_miner_under_correct_nonce_scores_full_evidence():
    gt = {
        "N": "sha256:" + "9" * 64,
        "F": "sha256:" + "9" * 64,
        "P": "sha256:" + "9" * 64,
        "K": "sha256:" + "9" * 64,
    }
    sssa = SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=0.9, summary=""),
        evidence=EvidencePack(
            network_trace_hash=gt["N"],
            fs_trace_hash=gt["F"],
            process_trace_hash=gt["P"],
            secrets_trace_hash=gt["K"],
        ),
    )
    score = score_evidence(sssa, {"ground_truth_evidence": gt})
    assert score == pytest.approx(1.0)


def test_fabricated_hashes_score_zero():
    """If the miner invents hashes without running detonation, they don't match the GT."""
    gt = {
        "N": "sha256:" + "9" * 64,
        "F": "sha256:" + "9" * 64,
        "P": "sha256:" + "9" * 64,
        "K": "sha256:" + "9" * 64,
    }
    sssa = _sssa_with_hashes("f")
    score = score_evidence(sssa, {"ground_truth_evidence": gt})
    assert score == 0.0
