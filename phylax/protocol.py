"""
phylax/protocol.py

Defines the wire protocol between Phylax validators and miners.
This is the single most important file in the codebase — both miners
and validators depend on this schema. Do not change field names without
a schema version bump.

The PhylaxSynapse carries a skill bundle inbound (validator → miner)
and a Signed Skill Safety Attestation (SSSA) outbound (miner → validator).
"""

import hashlib
import json
from enum import Enum
from typing import Optional

import bittensor as bt
from pydantic import BaseModel, Field, validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN  = "WARN"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class TestProfile(str, Enum):
    FAST     = "fast"      # Static + SBOM only (~5s)
    STANDARD = "standard"  # All 3 layers, standard timeout (~60s)
    DEEP     = "deep"      # All 3 layers, extended detonation (~5min)


# ---------------------------------------------------------------------------
# Sub-models (nested inside SSSA)
# ---------------------------------------------------------------------------

class SkillIdentity(BaseModel):
    """Identifies the skill bundle being analyzed."""
    name: str
    version: str = "unknown"
    bundle_hash: str          # sha256:<hex> of the submitted bundle zip
    sbom_hash: Optional[str] = None  # sha256:<hex> of generated SBOM
    entrypoints: list[str] = []
    declared_permissions: list[str] = []


class SkillBundle(BaseModel):
    """
    Input payload sent by the validator to the miner.
    Either bundle_url or bundle_bytes must be provided.
    """
    bundle_hash: str                          # sha256:<hex> — primary identifier
    bundle_url: Optional[str] = None          # URL validators provide for large bundles
    bundle_bytes: Optional[bytes] = None      # Raw bytes for small bundles
    metadata: dict = Field(default_factory=dict)
    test_profile: TestProfile = TestProfile.STANDARD

    @validator("bundle_hash")
    def hash_must_be_sha256(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != 71:
            raise ValueError("bundle_hash must be 'sha256:<64 hex chars>'")
        return v


class VerdictBlock(BaseModel):
    decision: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    top_reasons: list[str] = []


class FilesystemCapability(BaseModel):
    reads: list[str] = []
    writes: list[str] = []
    deletes: list[str] = []


class NetworkCapability(BaseModel):
    egress: bool = False
    observed_domains: list[str] = []
    observed_ips: list[str] = []
    allowlist_suggestion: list[str] = []
    denylist_suggestion: list[str] = []


class ProcessCapability(BaseModel):
    spawns: bool = False
    shell_exec: bool = False
    observed_commands: list[str] = []


class SecretsCapability(BaseModel):
    env_access: bool = False
    observed_vars: list[str] = []
    keychain_access: bool = False


class CapabilityMap(BaseModel):
    filesystem: FilesystemCapability = Field(default_factory=FilesystemCapability)
    network: NetworkCapability = Field(default_factory=NetworkCapability)
    process: ProcessCapability = Field(default_factory=ProcessCapability)
    secrets: SecretsCapability = Field(default_factory=SecretsCapability)


class FindingEvidence(BaseModel):
    trace_hash: Optional[str] = None   # sha256:<hex> of relevant trace segment
    line_ref: Optional[str] = None     # e.g. "src/main.py:42"
    snippet: Optional[str] = None      # Short code/log excerpt (max 200 chars)


class Finding(BaseModel):
    severity: Severity
    title: str
    description: str
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    recommendation: str = ""
    owasp_ref: Optional[str] = None    # e.g. "AG05 — Data Exfiltration"
    mitre_ref: Optional[str] = None    # e.g. "AML.T0037"


class DependencyInfo(BaseModel):
    sbom_hash: Optional[str] = None
    high_risk_packages: list[str] = []
    known_vulns: list[str] = []        # CVE IDs
    install_hooks: list[str] = []      # Detected postinstall scripts


class RecommendedPolicy(BaseModel):
    """
    Machine-readable policy a runtime can enforce before executing the skill.
    All fields are optional — only include what is relevant to this skill.
    """
    sandbox_runtime_image: Optional[str] = None
    egress_allowlist: list[str] = []
    egress_denylist: list[str] = []
    filesystem: dict = Field(default_factory=dict)
    shell_access: bool = False
    env_allowlist: list[str] = []
    max_memory_mb: int = 512
    timeout_seconds: int = 30
    rate_limit_rps: Optional[int] = None


class EvidencePack(BaseModel):
    """
    Content-addressed hashes of sandbox artifacts.
    Validators replay detonation and check these hashes for reproducibility.
    """
    network_trace_hash: Optional[str] = None   # sha256 of pcap/network summary
    fs_trace_hash: Optional[str] = None        # sha256 of filesystem access log
    process_trace_hash: Optional[str] = None   # sha256 of process tree log
    secrets_trace_hash: Optional[str] = None   # sha256 of env/keychain probe log
    sandbox_log_hash: Optional[str] = None     # sha256 of full sandbox stdout/stderr


class RunMetadata(BaseModel):
    tools: dict = Field(default_factory=dict)  # tool_name -> version
    runtime_image: Optional[str] = None        # sha256 of sandbox Docker image
    determinism_seed: int = 1337
    analysis_duration_ms: int = 0
    schema_version: str = "1.0.0"


class AttestationBlock(BaseModel):
    miner_hotkey: str
    signature: str                             # ed25519:<hex>
    timestamp: str                             # ISO 8601
    schema_version: str = "1.0.0"


class SSSA(BaseModel):
    """
    Signed Skill Safety Attestation — the commodity produced by this subnet.

    This is the canonical output of the Phylax miner pipeline. It is:
    - Portable: works across runtimes and marketplaces
    - Verifiable: evidence hashes allow independent validation
    - Enforceable: recommended_policy is machine-readable
    - Signed: miner_hotkey + ed25519 signature for non-repudiation
    """
    skill: SkillIdentity
    verdict: VerdictBlock
    capabilities: CapabilityMap = Field(default_factory=CapabilityMap)
    findings: list[Finding] = []
    dependencies: DependencyInfo = Field(default_factory=DependencyInfo)
    recommended_policy: RecommendedPolicy = Field(default_factory=RecommendedPolicy)
    evidence: EvidencePack = Field(default_factory=EvidencePack)
    run_metadata: RunMetadata = Field(default_factory=RunMetadata)
    attestation: Optional[AttestationBlock] = None

    def canonical_json(self) -> str:
        """
        Normalized, sorted JSON for signing.
        Excludes the attestation block itself (signed over the rest).
        """
        data = self.dict(exclude={"attestation"})
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def signing_hash(self) -> bytes:
        """SHA-256 of the canonical JSON, ready for ed25519 signing."""
        return hashlib.sha256(self.canonical_json().encode()).digest()


# ---------------------------------------------------------------------------
# The Synapse — wire protocol object exchanged between validators and miners
# ---------------------------------------------------------------------------

class PhylaxSynapse(bt.Synapse):
    """
    The Bittensor Synapse for the Phylax subnet.

    Validators populate `skill_bundle` and send this to miners via dendrite.
    Miners populate `attestation` (and optionally `error`) and return it.

    Field naming follows Bittensor conventions:
    - Input fields are set by the validator before sending
    - Output fields are filled by the miner and read by the validator
    """

    # ---------- Input (validator → miner) ----------
    skill_bundle: SkillBundle

    # ---------- Output (miner → validator) ----------
    attestation: Optional[dict] = None   # Serialized SSSA (use SSSA.dict())
    evidence_refs: Optional[dict] = None # Evidence blob URLs (optional, for deep profile)
    error: Optional[str] = None          # Set if miner pipeline failed

    # ---------- Helpers ----------

    def get_sssa(self) -> Optional[SSSA]:
        """Deserialize the attestation dict back into an SSSA model."""
        if self.attestation is None:
            return None
        return SSSA(**self.attestation)

    def is_valid_response(self) -> bool:
        """Quick check: did the miner return a complete, parseable SSSA?"""
        if self.error or self.attestation is None:
            return False
        try:
            sssa = self.get_sssa()
            return sssa is not None and sssa.attestation is not None
        except Exception:
            return False
