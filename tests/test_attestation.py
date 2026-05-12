"""Tests for the SSSA schema and signing."""

import pytest

from phylax.attestation.schema import validate_sssa
from phylax.protocol import (
    SSSA, SkillIdentity, VerdictBlock, Verdict,
)


def _minimal_sssa_dict() -> dict:
    return {
        "skill": {
            "name": "test-skill",
            "version": "1.0.0",
            "bundle_hash": "sha256:" + "0" * 64,
        },
        "verdict": {
            "decision": "ALLOW",
            "risk_score": 5,
            "confidence": 0.9,
            "summary": "all good",
        },
    }


def test_validate_minimal_sssa():
    ok, err, sssa = validate_sssa(_minimal_sssa_dict())
    assert ok, err
    assert sssa is not None
    assert sssa.verdict.decision == Verdict.ALLOW


def test_canonical_json_deterministic():
    sssa = SSSA(**_minimal_sssa_dict())
    a = sssa.canonical_json()
    b = sssa.canonical_json()
    assert a == b


def test_signing_hash_excludes_attestation():
    sssa = SSSA(**_minimal_sssa_dict())
    h1 = sssa.signing_hash()
    # Adding attestation shouldn't change the signing hash
    sssa.attestation = None
    h2 = sssa.signing_hash()
    assert h1 == h2


def test_unsupported_schema_version_rejected():
    payload = _minimal_sssa_dict()
    payload["run_metadata"] = {"schema_version": "999.0.0"}
    ok, err, sssa = validate_sssa(payload)
    assert not ok
    assert "schema_version" in (err or "")


def test_invalid_bundle_hash():
    payload = _minimal_sssa_dict()
    payload["skill"]["bundle_hash"] = "not-a-hash"
    ok, err, _ = validate_sssa(payload)
    assert not ok
