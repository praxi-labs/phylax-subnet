from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass

import bittensor as bt

from phylax.protocol import (
    SSSA,
    AttestationBlock,
    ValidatorCountersignature,
)


class AttestationSigner:
    """Wraps a Bittensor wallet to sign SSSAs."""

    def __init__(self, wallet: bt.Wallet):
        self.wallet = wallet

    @property
    def hotkey_address(self) -> str:
        return self.wallet.hotkey.ss58_address

    def sign(self, sssa: SSSA) -> SSSA:
        """Attach a miner AttestationBlock signing the canonical body."""
        sssa.attestation = None
        sssa.countersignature = None
        message = sssa.signing_hash()
        signature_bytes = self.wallet.hotkey.sign(message)
        sssa.attestation = AttestationBlock(
            miner_hotkey=self.hotkey_address,
            signature="ed25519:" + signature_bytes.hex(),
            timestamp=_utcnow_iso(),
        )
        return sssa




class ValidatorCountersigner:
    """Validator-side countersignature on a consensus SSSA."""

    def __init__(self, wallet: bt.Wallet):
        self.wallet = wallet

    @property
    def hotkey_address(self) -> str:
        return self.wallet.hotkey.ss58_address

    def countersign(self, sssa: SSSA, *, round_id: str, quality_score: float) -> SSSA:
        if sssa.attestation is None:
            raise ValueError("cannot countersign an unsigned SSSA")
        message = sssa.consensus_signing_bytes(round_id)
        signature_bytes = self.wallet.hotkey.sign(message)
        sssa.countersignature = ValidatorCountersignature(
            validator_hotkey=self.hotkey_address,
            signature="ed25519:" + signature_bytes.hex(),
            timestamp=_utcnow_iso(),
            round_id=round_id,
            quality_score=max(0.0, min(1.0, quality_score)),
        )
        return sssa




@dataclass
class VerificationResult:
    ok: bool
    reason: str | None = None
    miner_signature_ok: bool = False
    validator_signature_ok: bool = False
    bundle_hash_ok: bool = False
    sbom_hash_ok: bool = False
    fresh: bool = False


def verify_attestation(
    sssa: SSSA,
    *,
    local_bundle_hash: str | None = None,
    local_sbom_hash: str | None = None,
    require_countersignature: bool = False,
    max_age_seconds: int | None = None,
) -> VerificationResult:
    """Verify an SSSA: bundle hash, miner signature, optional validator
    countersignature, SBOM hash, and freshness. Returns a structured result
    so callers can surface which step failed.
    """
    result = VerificationResult(ok=False)

    if sssa.attestation is None:
        result.reason = "missing miner attestation"
        return result

    if local_bundle_hash is not None:
        result.bundle_hash_ok = local_bundle_hash == sssa.skill.bundle_hash
        if not result.bundle_hash_ok:
            result.reason = "bundle_hash mismatch"
            return result
    else:
        result.bundle_hash_ok = True

    result.miner_signature_ok = _verify_miner_signature(sssa)
    if not result.miner_signature_ok:
        result.reason = "miner signature invalid"
        return result

    if require_countersignature:
        if sssa.countersignature is None:
            result.reason = "missing validator countersignature"
            return result
        result.validator_signature_ok = _verify_countersignature(sssa)
        if not result.validator_signature_ok:
            result.reason = "validator countersignature invalid"
            return result
    elif sssa.countersignature is not None:
        result.validator_signature_ok = _verify_countersignature(sssa)

    if local_sbom_hash is not None:
        result.sbom_hash_ok = local_sbom_hash == (sssa.skill.sbom_hash or "")
        if not result.sbom_hash_ok:
            result.reason = "sbom_hash mismatch"
            return result
    else:
        result.sbom_hash_ok = True

    if max_age_seconds is not None:
        try:
            issued = datetime.datetime.fromisoformat(sssa.attestation.timestamp.rstrip("Z"))
            now = datetime.datetime.utcnow()
            age = (now - issued).total_seconds()
            result.fresh = age <= max_age_seconds
        except Exception:  # noqa: BLE001
            result.fresh = False
        if not result.fresh:
            result.reason = "attestation expired"
            return result
    else:
        result.fresh = True

    result.ok = True
    return result


def _verify_miner_signature(sssa: SSSA) -> bool:
    if sssa.attestation is None:
        return False
    sig_hex = sssa.attestation.signature.removeprefix("ed25519:")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    saved_att = sssa.attestation
    saved_counter = sssa.countersignature
    sssa.attestation = None
    sssa.countersignature = None
    try:
        message = sssa.signing_hash()
        return _verify_ed25519(saved_att.miner_hotkey, message, sig_bytes)
    finally:
        sssa.attestation = saved_att
        sssa.countersignature = saved_counter


def _verify_countersignature(sssa: SSSA) -> bool:
    cs = sssa.countersignature
    if cs is None or sssa.attestation is None:
        return False
    sig_hex = cs.signature.removeprefix("ed25519:")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False

    saved_counter = sssa.countersignature
    sssa.countersignature = None
    try:
        message = sssa.consensus_signing_bytes(cs.round_id)
        return _verify_ed25519(cs.validator_hotkey, message, sig_bytes)
    finally:
        sssa.countersignature = saved_counter


def _verify_ed25519(ss58_address: str, message: bytes, signature: bytes) -> bool:
    try:
        from substrateinterface import Keypair  # type: ignore
    except ImportError:
        return False
    try:
        keypair = Keypair(ss58_address=ss58_address)
        return bool(keypair.verify(message, signature))
    except Exception:  # noqa: BLE001
        return False


def _utcnow_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"


def sha256_of_bytes(data: bytes) -> str:
    """Convenience for callers that need the canonical bundle-hash form."""
    return "sha256:" + hashlib.sha256(data).hexdigest()

