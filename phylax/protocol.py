from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Optional

import bittensor as bt
from pydantic import BaseModel, ConfigDict, Field, field_validator


SCHEMA_VERSION = "1.1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TestProfile(str, Enum):
    FAST = "fast"          # Static + SBOM only (~5s)
    STANDARD = "standard"  # All 3 layers, standard timeout (~60s)
    DEEP = "deep"          # All 3 layers, extended detonation (~5min)


# ---------------------------------------------------------------------------
# Sub-models nested inside SSSA
# ---------------------------------------------------------------------------


class SkillIdentity(BaseModel):
    name: str
    version: str = "unknown"
    bundle_hash: str
    sbom_hash: Optional[str] = None
    entrypoints: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)


class SkillBundle(BaseModel):
    """Inbound payload from validator to miner."""

    bundle_hash: str
    bundle_url: Optional[str] = None
    bundle_bytes: Optional[bytes] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    test_profile: TestProfile = TestProfile.STANDARD

    @field_validator("bundle_hash")
    @classmethod
    def _hash_shape(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != 71:
            raise ValueError("bundle_hash must be 'sha256:<64 hex chars>'")
        return v


class VerdictBlock(BaseModel):
    decision: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = ""
    top_reasons: list[str] = Field(default_factory=list)


class FilesystemCapability(BaseModel):
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)
    deletes: list[str] = Field(default_factory=list)


class NetworkCapability(BaseModel):
    egress: bool = False
    observed_domains: list[str] = Field(default_factory=list)
    observed_ips: list[str] = Field(default_factory=list)
    observed_ports: list[int] = Field(default_factory=list)
    persistent_connections: int = 0
    allowlist_suggestion: list[str] = Field(default_factory=list)
    denylist_suggestion: list[str] = Field(default_factory=list)


class ProcessCapability(BaseModel):
    spawns: bool = False
    shell_exec: bool = False
    observed_commands: list[str] = Field(default_factory=list)


class SecretsCapability(BaseModel):
    env_access: bool = False
    observed_vars: list[str] = Field(default_factory=list)
    keychain_access: bool = False


class CapabilityMap(BaseModel):
    filesystem: FilesystemCapability = Field(default_factory=FilesystemCapability)
    network: NetworkCapability = Field(default_factory=NetworkCapability)
    process: ProcessCapability = Field(default_factory=ProcessCapability)
    secrets: SecretsCapability = Field(default_factory=SecretsCapability)


class FindingEvidence(BaseModel):
    trace_hash: Optional[str] = None
    line_ref: Optional[str] = None
    snippet: Optional[str] = None


class Finding(BaseModel):
    severity: Severity
    title: str
    description: str = ""
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    recommendation: str = ""
    owasp_ref: Optional[str] = None
    mitre_ref: Optional[str] = None


class DependencyInfo(BaseModel):
    sbom_hash: Optional[str] = None
    high_risk_packages: list[str] = Field(default_factory=list)
    known_vulns: list[str] = Field(default_factory=list)
    install_hooks: list[str] = Field(default_factory=list)


class RecommendedPolicy(BaseModel):
    """Machine-enforceable runtime policy a consuming runtime applies before
    invoking the skill. Miners set fields to only what was observed."""

    sandbox_runtime_image: Optional[str] = None
    egress_allowlist: list[str] = Field(default_factory=list)
    egress_denylist: list[str] = Field(default_factory=list)
    filesystem: dict[str, Any] = Field(default_factory=dict)
    shell_access: bool = False
    env_allowlist: list[str] = Field(default_factory=list)
    max_memory_mb: int = 512
    timeout_seconds: int = 30
    rate_limit_rps: Optional[int] = None


class EvidencePack(BaseModel):
    """Content-addressed hashes of the detonation traces. Validators replay
    detonation with the miner's nonce and require byte-equal hashes."""

    network_trace_hash: Optional[str] = None
    fs_trace_hash: Optional[str] = None
    process_trace_hash: Optional[str] = None
    secrets_trace_hash: Optional[str] = None
    sandbox_log_hash: Optional[str] = None
    pcap_hash: Optional[str] = None

    def component_hashes(self) -> dict[str, Optional[str]]:
        return {
            "N": self.network_trace_hash,
            "F": self.fs_trace_hash,
            "P": self.process_trace_hash,
            "K": self.secrets_trace_hash,
        }


class RunMetadata(BaseModel):
    tools: dict[str, str] = Field(default_factory=dict)
    runtime_image: Optional[str] = None
    determinism_seed: int = 0  # set per-task from validator nonce; never hardcoded
    analysis_duration_ms: int = 0
    schema_version: str = SCHEMA_VERSION


class AttestationBlock(BaseModel):
    miner_hotkey: str
    signature: str
    timestamp: str
    schema_version: str = SCHEMA_VERSION


class ValidatorCountersignature(BaseModel):
    """Optional validator countersignature on a consensus SSSA, for runtimes
    that require both a miner signature and a validator one."""

    validator_hotkey: str
    signature: str
    timestamp: str
    round_id: str
    quality_score: float = Field(ge=0.0, le=1.0)


class SSSA(BaseModel):
    """Signed Skill Safety Attestation."""

    model_config = ConfigDict(extra="forbid")

    skill: SkillIdentity
    verdict: VerdictBlock
    capabilities: CapabilityMap = Field(default_factory=CapabilityMap)
    findings: list[Finding] = Field(default_factory=list)
    dependencies: DependencyInfo = Field(default_factory=DependencyInfo)
    recommended_policy: RecommendedPolicy = Field(default_factory=RecommendedPolicy)
    evidence: EvidencePack = Field(default_factory=EvidencePack)
    run_metadata: RunMetadata = Field(default_factory=RunMetadata)
    attestation: Optional[AttestationBlock] = None
    countersignature: Optional[ValidatorCountersignature] = None

    def canonical_json(self) -> str:
        """Sorted, separator-stable JSON omitting both signatures."""
        data = self.model_dump(exclude={"attestation", "countersignature"}, mode="json")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def signing_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_json().encode()).digest()

    def consensus_signing_bytes(self, round_id: str) -> bytes:
        # Binds the countersignature to a specific round so it can't be
        # replayed onto a different one.
        if self.attestation is None:
            raise ValueError("cannot countersign an unsigned SSSA")
        payload = {
            "body": self.canonical_json(),
            "miner_sig": self.attestation.signature,
            "miner_hotkey": self.attestation.miner_hotkey,
            "round_id": round_id,
        }
        canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canon.encode()).digest()


class PhylaxSynapse(bt.Synapse):
    """
    Wire object between validator and miner.

    ``nonce`` is the determinism seed the miner threads into the sandbox
    detonation; validators replay with the same nonce and require matching
    evidence hashes. Without it the anti-copy property collapses.
    """

    # Input (validator → miner)
    skill_bundle: SkillBundle
    nonce: int = 0
    round_id: str = ""
    deadline_unix: float = 0.0

    # Output (miner → validator)
    attestation: Optional[dict] = None
    evidence_refs: Optional[dict] = None
    error: Optional[str] = None

    def get_sssa(self) -> Optional[SSSA]:
        if self.attestation is None:
            return None
        return SSSA(**self.attestation)

    def is_valid_response(self) -> bool:
        if self.error or self.attestation is None:
            return False
        try:
            sssa = self.get_sssa()
            return sssa is not None and sssa.attestation is not None
        except Exception:  # noqa: BLE001
            return False
