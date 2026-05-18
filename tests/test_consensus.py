from phylax.protocol import (
    SSSA,
    AttestationBlock,
    SkillIdentity,
    Verdict,
    VerdictBlock,
)
from phylax.validator.consensus import ConsensusAggregator, MinerSubmission


def _signed(verdict: Verdict) -> SSSA:
    return SSSA(
        skill=SkillIdentity(name="t", bundle_hash="sha256:" + "0" * 64),
        verdict=VerdictBlock(decision=verdict, risk_score=50, confidence=0.9, summary=""),
        attestation=AttestationBlock(
            miner_hotkey="dummy",
            signature="ed25519:" + "0" * 128,
            timestamp="2026-01-01T00:00:00Z",
        ),
    )


def _sub(uid: int, verdict: Verdict, quality: float) -> MinerSubmission:
    return MinerSubmission(
        uid=uid,
        hotkey=f"m{uid}",
        sssa=_signed(verdict),
        quality_score=quality,
        submission_latency_ms=1000,
    )


def test_majority_wins_when_qualities_equal():
    aggr = ConsensusAggregator()
    subs = [
        _sub(1, Verdict.ALLOW, 0.5),
        _sub(2, Verdict.ALLOW, 0.5),
        _sub(3, Verdict.BLOCK, 0.5),
    ]
    result = aggr.aggregate(subs)
    assert result.verdict == Verdict.ALLOW


def test_single_high_quality_miner_outweighs_low_quality_majority():
    aggr = ConsensusAggregator()
    subs = [
        _sub(1, Verdict.ALLOW, 0.1),
        _sub(2, Verdict.ALLOW, 0.1),
        _sub(3, Verdict.BLOCK, 0.95),
    ]
    result = aggr.aggregate(subs)
    assert result.verdict == Verdict.BLOCK
    assert result.winning_submission.uid == 3


def test_empty_submissions_returns_none():
    aggr = ConsensusAggregator()
    assert aggr.aggregate([]) is None
