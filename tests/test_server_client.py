from __future__ import annotations

import pytest

from phylax.server_client import (
    PhylaxServerClient,
    ServerIdentityMismatch,
    _signing_bytes,
)


class _FakeHotkey:
    def __init__(self, ss58: str = "5FakeHotkey"):
        self.ss58_address = ss58
        self.sign_calls: list[bytes] = []

    def sign(self, message: bytes) -> bytes:
        self.sign_calls.append(message)
        return b"\x00" * 64


class _FakeWallet:
    def __init__(self, ss58: str = "5FakeHotkey"):
        self.hotkey = _FakeHotkey(ss58)


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


def test_signed_headers_carry_hotkey_and_signature():
    client = PhylaxServerClient(base_url="http://nowhere", wallet=_FakeWallet())
    headers = client._signed_headers("POST", "/v1/x", b"{}")
    assert headers["X-Phylax-Hotkey"] == "5FakeHotkey"
    assert headers["X-Phylax-Signature"].startswith("ed25519:")
    assert client.wallet.hotkey.sign_calls


def test_pinned_identity_survives_matching_key():
    client = PhylaxServerClient(
        base_url="http://nowhere", wallet=_FakeWallet(), expected_server_hotkey="ab" * 32
    )
    assert client.server_hotkey == "ab" * 32
    with pytest.raises(ServerIdentityMismatch):
        raise ServerIdentityMismatch("rotated key")
