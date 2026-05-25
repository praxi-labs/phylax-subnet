from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from phylax.attestation import VerificationResult, verify_attestation
from phylax.protocol import SSSA, RecommendedPolicy, Verdict



class PhylaxClient:
    """Tiny client around the Phylax REST API."""

    def __init__(self, base_url: str = "http://localhost:8080", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout


    def get_attestation(self, bundle_hash: str) -> SSSA | None:
        import httpx

        url = f"{self.base_url}/v1/attestation/{bundle_hash}"
        r = httpx.get(url, timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return SSSA(**r.json())

    def scan(
        self,
        bundle_bytes: bytes,
        *,
        metadata: dict | None = None,
        test_profile: str = "standard",
    ) -> SSSA:
        import base64

        import httpx

        payload = {
            "bundle_bytes": base64.b64encode(bundle_bytes).decode(),
            "metadata": metadata or {},
            "test_profile": test_profile,
        }
        r = httpx.post(f"{self.base_url}/v1/scan", json=payload, timeout=self.timeout * 3)
        r.raise_for_status()
        return SSSA(**r.json()["attestation"])




def fetch_and_verify(
    bundle_bytes: bytes,
    *,
    base_url: str = "http://localhost:8080",
    require_countersignature: bool = False,
    max_age_seconds: int | None = 86_400,
) -> tuple[SSSA | None, VerificationResult]:
    """High-level entry: fetch attestation for ``bundle_bytes`` and verify it.

    Returns ``(sssa, verification_result)``. If the attestation does not
    exist in the registry, the API's POST /v1/scan path is used to
    synthesise one on the fly.
    """
    client = PhylaxClient(base_url=base_url)
    bundle_hash = "sha256:" + hashlib.sha256(bundle_bytes).hexdigest()

    sssa = client.get_attestation(bundle_hash)
    if sssa is None:
        sssa = client.scan(bundle_bytes)

    sbom_hash = sssa.skill.sbom_hash
    result = verify_attestation(
        sssa,
        local_bundle_hash=bundle_hash,
        local_sbom_hash=sbom_hash,
        require_countersignature=require_countersignature,
        max_age_seconds=max_age_seconds,
    )
    return sssa, result




@dataclass
class PolicyEnforcer:
    sssa: SSSA

    @property
    def policy(self) -> RecommendedPolicy:
        return self.sssa.recommended_policy

    def must_block(self) -> bool:
        return self.sssa.verdict.decision == Verdict.BLOCK

    def must_warn(self) -> bool:
        return self.sssa.verdict.decision == Verdict.WARN

    def sandbox_config(self) -> dict[str, Any]:
        p = self.policy
        return {
            "egress_allowlist": list(p.egress_allowlist),
            "egress_denylist": list(p.egress_denylist),
            "shell_access": bool(p.shell_access),
            "env_allowlist": list(p.env_allowlist),
            "filesystem": dict(p.filesystem),
            "max_memory_mb": int(p.max_memory_mb),
            "timeout_seconds": int(p.timeout_seconds),
            "rate_limit_rps": p.rate_limit_rps,
        }

