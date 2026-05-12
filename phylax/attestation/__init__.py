"""Phylax attestation: SSSA schema validation and ed25519 signing."""

from phylax.attestation.schema import validate_sssa
from phylax.attestation.signer import AttestationSigner, verify_attestation

__all__ = ["validate_sssa", "AttestationSigner", "verify_attestation"]
