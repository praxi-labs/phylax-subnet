"""
phylax/attestation/signer.py

ED25519 signing for Signed Skill Safety Attestations (SSSAs).

The miner signs the canonical-JSON form of the SSSA (excluding the
attestation block itself) with its Bittensor hotkey. Validators can
independently verify any SSSA by recomputing the canonical JSON,
re-hashing, and checking the signature against the claimed hotkey.
"""

from __future__ import annotations

import datetime
from typing import Optional

import bittensor as bt

from phylax.protocol import SSSA, AttestationBlock


class AttestationSigner:
    """
    Wraps a Bittensor wallet to sign SSSAs.

    Usage:
        signer = AttestationSigner(wallet=my_wallet)
        signed = signer.sign(sssa)
    """

    def __init__(self, wallet: "bt.wallet"):
        self.wallet = wallet

    @property
    def hotkey_address(self) -> str:
        return self.wallet.hotkey.ss58_address

    def sign(self, sssa: SSSA) -> SSSA:
        """
        Sign the canonical-JSON form of the SSSA and attach an
        AttestationBlock. Returns the same SSSA with `attestation` populated.
        """
        # Strip any pre-existing attestation so we sign over the canonical body
        sssa.attestation = None
        message = sssa.signing_hash()
        signature_bytes = self.wallet.hotkey.sign(message)
        signature = "ed25519:" + signature_bytes.hex()

        sssa.attestation = AttestationBlock(
            miner_hotkey=self.hotkey_address,
            signature=signature,
            timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        )
        return sssa


def verify_attestation(sssa: SSSA) -> bool:
    """
    Verify the signature on an SSSA against its claimed miner_hotkey.

    Returns True if signature is valid AND was produced by the claimed hotkey.
    """
    if sssa.attestation is None:
        return False

    try:
        from substrateinterface import Keypair
    except ImportError:
        # Fall back to nacl if substrate-interface isn't installed
        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
        except ImportError:
            raise RuntimeError(
                "Need substrate-interface or PyNaCl to verify SSSA signatures"
            )
        return _verify_with_nacl(sssa)

    sig_hex = sssa.attestation.signature.removeprefix("ed25519:")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    # Temporarily detach the attestation block so signing_hash matches what was signed
    saved = sssa.attestation
    sssa.attestation = None
    try:
        message = sssa.signing_hash()
        keypair = Keypair(ss58_address=saved.miner_hotkey)
        return keypair.verify(message, sig_bytes)
    finally:
        sssa.attestation = saved


def _verify_with_nacl(sssa: SSSA) -> bool:
    """Fallback verifier when substrate-interface isn't installed.

    Note: this path verifies the raw ed25519 signature only; SS58 address
    derivation is not checked, so prefer the substrate-interface path
    in production.
    """
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    # Without substrate-interface we can't derive the public key from SS58.
    # Return False to be safe rather than silently green-light.
    return False
