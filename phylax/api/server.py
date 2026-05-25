from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi import Path as ApiPath
from pydantic import BaseModel, Field

from phylax.attestation import sha256_of_bytes, verify_attestation
from phylax.protocol import (
    SCHEMA_VERSION,
    SSSA,
    RunMetadata,
    SkillIdentity,
)
from phylax.validator.baseline import BaselineRunner, GroundTruth
from phylax.validator.registry import AttestationRegistry



class ScanRequest(BaseModel):
    bundle_url: str | None = None
    bundle_bytes: str | None = Field(
        default=None, description="Base64-encoded bundle bytes"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
    test_profile: str = "standard"


class ScanResponse(BaseModel):
    attestation: dict
    evidence_refs: dict[str, str | None]
    from_cache: bool


class HealthResponse(BaseModel):
    ok: bool
    schema_version: str
    registry: dict[str, int]




def create_app(
    *,
    registry: AttestationRegistry | None = None,
    baseline: BaselineRunner | None = None,
    wallet: Any | None = None,
) -> FastAPI:
    app = FastAPI(title="Phylax", version=SCHEMA_VERSION)
    state = _ApiState(
        registry=registry
        or AttestationRegistry(
            os.getenv("PHYLAX_REGISTRY_PATH")
            or str(Path(__file__).parent.parent.parent / "phylax_registry.sqlite3")
        ),
        baseline=baseline or BaselineRunner(),
        wallet=wallet,
        admin_token=os.getenv("PHYLAX_API_ADMIN_TOKEN", ""),
    )
    app.state.phylax = state

    @app.get("/v1/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            ok=True,
            schema_version=SCHEMA_VERSION,
            registry=state.registry.stats(),
        )

    @app.post("/v1/scan", response_model=ScanResponse)
    def scan(req: ScanRequest) -> ScanResponse:
        bundle_bytes = _resolve_bundle_bytes(req)
        bundle_hash = sha256_of_bytes(bundle_bytes)
        cached = state.registry.get(bundle_hash)
        if cached is not None and cached.is_valid:
            sssa = cached.sssa
            return ScanResponse(
                attestation=sssa.model_dump(mode="json"),
                evidence_refs=sssa.evidence.component_hashes(),
                from_cache=True,
            )

        sssa = state.attest_fresh(
            bundle_bytes,
            bundle_hash=bundle_hash,
            metadata=req.metadata,
            test_profile=req.test_profile,
        )
        return ScanResponse(
            attestation=sssa.model_dump(mode="json"),
            evidence_refs=sssa.evidence.component_hashes(),
            from_cache=False,
        )

    @app.get("/v1/attestation/{bundle_hash}")
    def get_attestation(bundle_hash: str = ApiPath(...)) -> dict:
        entry = state.registry.get(bundle_hash)
        if entry is None:
            raise HTTPException(status_code=404, detail="no attestation for that bundle_hash")
        return entry.sssa.model_dump(mode="json")

    @app.post("/v1/attestation/{bundle_hash}/invalidate")
    def invalidate(
        bundle_hash: str = ApiPath(...),
        body: dict = Body(...),
    ) -> dict:
        token = body.get("token", "")
        if not state.admin_token or not secrets.compare_digest(token, state.admin_token):
            raise HTTPException(status_code=403, detail="invalid admin token")
        reason = body.get("reason") or "unspecified"
        ok = state.registry.invalidate(bundle_hash, reason=reason)
        if not ok:
            raise HTTPException(status_code=404, detail="no active attestation to invalidate")
        return {"ok": True, "bundle_hash": bundle_hash, "reason": reason}

    @app.post("/v1/attestation/verify")
    def verify(payload: dict = Body(...)) -> dict:
        try:
            sssa = SSSA(**payload)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"invalid SSSA: {e}") from e
        result = verify_attestation(sssa)
        return {
            "ok": result.ok,
            "reason": result.reason,
            "miner_signature_ok": result.miner_signature_ok,
            "validator_signature_ok": result.validator_signature_ok,
            "bundle_hash_ok": result.bundle_hash_ok,
            "sbom_hash_ok": result.sbom_hash_ok,
            "fresh": result.fresh,
        }

    return app




class _ApiState:
    def __init__(
        self,
        *,
        registry: AttestationRegistry,
        baseline: BaselineRunner,
        wallet: Any | None,
        admin_token: str,
    ):
        self.registry = registry
        self.baseline = baseline
        self.wallet = wallet
        self.admin_token = admin_token

    def attest_fresh(
        self,
        bundle_bytes: bytes,
        *,
        bundle_hash: str,
        metadata: dict,
        test_profile: str,
    ) -> SSSA:
        deep = test_profile == "deep"
        nonce = secrets.randbits(63)
        gt: GroundTruth = self.baseline.run_from_bytes(bundle_bytes, nonce=nonce, deep=deep)

        sssa = SSSA(
            skill=SkillIdentity(
                name=str(metadata.get("name") or "unknown"),
                version=str(metadata.get("version") or "unknown"),
                bundle_hash=bundle_hash,
                sbom_hash=gt.sbom_hash,
                declared_permissions=list(metadata.get("permissions") or []),
            ),
            verdict=gt.verdict,
            capabilities=gt.capabilities,
            findings=gt.findings,
            recommended_policy=gt.policy,
            run_metadata=RunMetadata(
                tools={"bandit": "1.7.5", "syft": "1.0.0"},
                determinism_seed=nonce,
                analysis_duration_ms=gt.duration_ms,
            ),
        )
        sssa.evidence.network_trace_hash = gt.evidence_hashes.get("N")
        sssa.evidence.fs_trace_hash = gt.evidence_hashes.get("F")
        sssa.evidence.process_trace_hash = gt.evidence_hashes.get("P")
        sssa.evidence.secrets_trace_hash = gt.evidence_hashes.get("K")

        if self.wallet is not None:
            try:
                from phylax.attestation import AttestationSigner

                AttestationSigner(self.wallet).sign(sssa)
            except Exception:  # noqa: BLE001
                pass
        return sssa


def _resolve_bundle_bytes(req: ScanRequest) -> bytes:
    if req.bundle_bytes:
        try:
            return base64.b64decode(req.bundle_bytes)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"bad base64: {e}") from e
    if req.bundle_url:
        try:
            import httpx

            r = httpx.get(req.bundle_url, follow_redirects=True, timeout=20)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"upstream {r.status_code}")
            return r.content
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"fetch failed: {e}") from e
    raise HTTPException(status_code=400, detail="bundle_bytes or bundle_url required")




def main() -> None:
    import uvicorn

    app = create_app()
    host = os.getenv("PHYLAX_API_HOST", "0.0.0.0")
    port = int(os.getenv("PHYLAX_API_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()

