import pytest

from phylax.protocol import (
    SSSA,
    AttestationBlock,
    SkillIdentity,
    Verdict,
    VerdictBlock,
)
from phylax.validator.registry import AttestationRegistry


def _signed_sssa(bundle_hash: str, verdict: Verdict = Verdict.ALLOW) -> SSSA:
    return SSSA(
        skill=SkillIdentity(name="t", bundle_hash=bundle_hash),
        verdict=VerdictBlock(decision=verdict, risk_score=10, confidence=0.9, summary=""),
        attestation=AttestationBlock(
            miner_hotkey="hk1",
            signature="ed25519:" + "0" * 128,
            timestamp="2026-01-01T00:00:00Z",
        ),
    )


@pytest.fixture
def registry(tmp_path):
    return AttestationRegistry(tmp_path / "reg.sqlite3")


def test_put_then_get_roundtrips(registry):
    h = "sha256:" + "a" * 64
    registry.put(_signed_sssa(h), round_id="r1", quality_score=0.8)
    entry = registry.get(h)
    assert entry is not None
    assert entry.bundle_hash == h
    assert entry.is_valid


def test_get_missing_returns_none(registry):
    assert registry.get("sha256:" + "f" * 64) is None


def test_invalidate_hides_entry(registry):
    h = "sha256:" + "b" * 64
    registry.put(_signed_sssa(h), round_id="r1", quality_score=0.8)
    assert registry.invalidate(h, reason="test")
    assert registry.get(h) is None
    entry = registry.get(h, only_valid=False)
    assert entry is not None and not entry.is_valid


def test_invalidate_by_publisher(registry):
    for i in range(3):
        h = "sha256:" + f"{i:064x}"
        registry.put(_signed_sssa(h), round_id="r1", quality_score=0.5)
    invalidated = registry.invalidate_by_publisher("hk1", reason="publisher_compromised")
    assert invalidated == 3


def test_stats_counts_verdicts(registry):
    registry.put(_signed_sssa("sha256:" + "1" * 64, Verdict.ALLOW), round_id="r", quality_score=0.5)
    registry.put(_signed_sssa("sha256:" + "2" * 64, Verdict.WARN), round_id="r", quality_score=0.5)
    registry.put(_signed_sssa("sha256:" + "3" * 64, Verdict.BLOCK), round_id="r", quality_score=0.5)
    stats = registry.stats()
    assert stats["active"] == 3
    assert stats["block"] == 1
    assert stats["warn"] == 1
    assert stats["allow"] == 1
