import pytest

from phylax.attestation import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    validate_sssa,
)
from phylax.protocol import (
    EvidencePack,
    SkillIdentity,
    SSSA,
    Verdict,
)


def _minimal_payload() -> dict:
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
    ok, err, sssa = validate_sssa(_minimal_payload())
    assert ok, err
    assert sssa is not None
    assert sssa.verdict.decision == Verdict.ALLOW


def test_canonical_json_excludes_both_signature_blocks():
    sssa = SSSA(**_minimal_payload())
    body = sssa.canonical_json()
    assert "attestation" not in body
    assert "countersignature" not in body


def test_signing_hash_stable_across_repeated_calls():
    sssa = SSSA(**_minimal_payload())
    h1 = sssa.signing_hash()
    h2 = sssa.signing_hash()
    assert h1 == h2


def test_unsupported_schema_version_rejected():
    payload = _minimal_payload()
    payload["run_metadata"] = {"schema_version": "999.0.0"}
    ok, err, _ = validate_sssa(payload)
    assert not ok
    assert "schema_version" in (err or "")


def test_legacy_1_0_0_still_accepted():
    payload = _minimal_payload()
    payload["run_metadata"] = {"schema_version": "1.0.0"}
    ok, err, _ = validate_sssa(payload)
    assert ok, err


def test_invalid_bundle_hash_rejected():
    payload = _minimal_payload()
    payload["skill"]["bundle_hash"] = "not-a-hash"
    ok, err, _ = validate_sssa(payload)
    assert not ok


def test_current_schema_in_supported_set():
    assert CURRENT_SCHEMA_VERSION in SUPPORTED_SCHEMA_VERSIONS


def test_component_hashes_helper_returns_npfk_keys():
    sssa = SSSA(
        **_minimal_payload(),
        evidence=EvidencePack(
            network_trace_hash="sha256:" + "1" * 64,
            fs_trace_hash="sha256:" + "2" * 64,
            process_trace_hash="sha256:" + "3" * 64,
            secrets_trace_hash="sha256:" + "4" * 64,
        ),
    )
    h = sssa.evidence.component_hashes()
    assert set(h.keys()) == {"N", "F", "P", "K"}
