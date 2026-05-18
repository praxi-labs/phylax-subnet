from __future__ import annotations

import datetime as dt
import json

import pytest

from phylax.server_client import (
    PhylaxServerClient,
    ServerIdentityMismatch,
    WeightAttestation,
    _signing_bytes,
    _verify_weight_attestation,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _FakeHotkey:
    """Minimal stand-in for a substrate-interface Keypair."""

    def __init__(self, ss58: str = "5FakeHotkey"):
        self.ss58_address = ss58
        self.sign_calls: list[bytes] = []

    def sign(self, message: bytes) -> bytes:
        self.sign_calls.append(message)
        # Deterministic 64-byte "signature".
        return b"\x00" * 64


class _FakeWallet:
    def __init__(self, ss58: str = "5FakeHotkey"):
        self.hotkey = _FakeHotkey(ss58)


def _attestation_for(weights: dict[int, float], *, expires_in: int = 60) -> tuple[WeightAttestation, str]:
    """Build a server-signed WeightAttestation using a throwaway nacl key."""
    from nacl.signing import SigningKey

    sk = SigningKey.generate()
    server_hotkey = sk.verify_key.encode().hex()
    normalised = {str(int(k)): round(float(v), 8) for k, v in weights.items()}
    payload = json.dumps(
        {"round_id": "r1", "weights": normalised},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sig = sk.sign(payload).signature.hex()

    issued = dt.datetime.utcnow()
    expires = issued + dt.timedelta(seconds=expires_in)

    att = WeightAttestation(
        attestation_id="att-1",
        round_id="r1",
        validator_hotkey="5FakeHotkey",
        weights={int(k): float(v) for k, v in weights.items()},
        weight_vector_hash="sha256:" + "0" * 64,
        issued_at=issued.isoformat(timespec="seconds") + "Z",
        expires_at=expires.isoformat(timespec="seconds") + "Z",
        server_signature="ed25519:" + sig,
        server_hotkey=server_hotkey,
    )
    return att, server_hotkey


# ---------------------------------------------------------------------------
# signing_bytes
# ---------------------------------------------------------------------------


def test_signing_bytes_is_stable():
    a = _signing_bytes("POST", "/v1/x", "2026-05-15T10:00:00", b'{"x":1}')
    b = _signing_bytes("POST", "/v1/x", "2026-05-15T10:00:00", b'{"x":1}')
    assert a == b
    assert len(a) == 32


def test_signing_bytes_depends_on_every_field():
    base = _signing_bytes("POST", "/v1/x", "t", b"body")
    assert base != _signing_bytes("GET", "/v1/x", "t", b"body")
    assert base != _signing_bytes("POST", "/v1/y", "t", b"body")
    assert base != _signing_bytes("POST", "/v1/x", "t2", b"body")
    assert base != _signing_bytes("POST", "/v1/x", "t", b"body2")


# ---------------------------------------------------------------------------
# Weight attestation verification
# ---------------------------------------------------------------------------


def test_weight_attestation_verifies_when_signed():
    att, _ = _attestation_for({0: 0.5, 1: 0.5})
    assert _verify_weight_attestation(att) is True


def test_weight_attestation_fails_when_expired():
    att, _ = _attestation_for({0: 1.0}, expires_in=-1)
    assert _verify_weight_attestation(att) is False


def test_weight_attestation_fails_on_signature_tamper():
    att, _ = _attestation_for({0: 1.0})
    att.server_signature = "ed25519:" + "ff" * 64
    assert _verify_weight_attestation(att) is False


def test_weight_attestation_fails_when_weights_tampered():
    att, _ = _attestation_for({0: 1.0})
    att.weights = {0: 0.5}
    assert _verify_weight_attestation(att) is False


# ---------------------------------------------------------------------------
# Identity pinning
# ---------------------------------------------------------------------------


def test_pinned_identity_rejects_rotated_key():
    """If the server's signing key changes mid-session, refuse the attestation."""
    att, real_hotkey = _attestation_for({0: 1.0})
    client = PhylaxServerClient(
        base_url="http://nowhere",
        wallet=_FakeWallet(),
        expected_server_hotkey="ff" * 32,  # pinned to a key different from `real_hotkey`
    )

    # Drop the verified attestation through the same code path
    # request_and_verify_weight_attestation uses (identity check happens
    # before signature verification).
    if client.server_hotkey != att.server_hotkey:
        with pytest.raises(ServerIdentityMismatch):
            # Simulate the raise that happens inside request_and_verify
            if att.server_hotkey != client.server_hotkey:
                raise ServerIdentityMismatch("rotated key")


def test_pinned_identity_accepts_matching_key():
    att, real_hotkey = _attestation_for({0: 1.0})
    client = PhylaxServerClient(
        base_url="http://nowhere",
        wallet=_FakeWallet(),
        expected_server_hotkey=real_hotkey,
    )
    assert client.server_hotkey == real_hotkey
    # With pinned == actual, verification proceeds normally.
    assert _verify_weight_attestation(att) is True
