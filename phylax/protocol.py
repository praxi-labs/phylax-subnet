from __future__ import annotations

import base64
import hashlib
import json
from enum import Enum
from typing import Any

import bittensor as bt
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

SCHEMA_VERSION = "1.1.0"
SCHEMA_VERSION_V04 = "0.4"
SKILL_TYPE_VERSION = "1.0"


class SkillType(str, Enum):
    RAG_KNOWLEDGE = "rag_knowledge"
    DECLARATIVE = "declarative"
    EXECUTABLE_PYTHON = "executable_python"
    EXECUTABLE_SCRIPT = "executable_script"
    MCP_SERVER = "mcp_server"
    AGENT_COMPOSITION = "agent_composition"


class TaskType(str, Enum):
    SERVER_CURATED = "server_curated"
    LOCAL_SYNTH = "local_synth"
    CANARY = "canary"


class FindingLayer(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class FindingType(str, Enum):
    STATIC = "static"
    SBOM = "sbom"
    RUNTIME = "runtime"
    MANIFEST = "manifest"
    CONTENT = "content"


class FindingSeverityV04(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class LLMAllowedUse(str, Enum):
    FINDING_ENRICHMENT = "finding_enrichment"
    MITRE_OWASP_MAPPING = "mitre_owasp_mapping"
    CVE_EXPLANATION = "cve_explanation"


class ChildVerdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"




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
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"




class SkillIdentity(BaseModel):
    name: str
    version: str = "unknown"
    bundle_hash: str
    sbom_hash: str | None = None
    entrypoints: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)


class SkillBundle(BaseModel):
    """Inbound payload from validator to miner."""

    bundle_hash: str = ""
    bundle_url: str | None = None
    bundle_bytes: bytes | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    test_profile: TestProfile = TestProfile.STANDARD

    @field_validator("bundle_hash")
    @classmethod
    def _hash_shape(cls, v: str) -> str:
        if not v:
            return v
        if not v.startswith("sha256:") or len(v) != 71:
            raise ValueError("bundle_hash must be 'sha256:<64 hex chars>'")
        return v

    @field_serializer("bundle_bytes")
    def _ser_bundle_bytes(self, v: bytes | None) -> str | None:
        return base64.b64encode(v).decode("ascii") if v else None

    @field_validator("bundle_bytes", mode="before")
    @classmethod
    def _val_bundle_bytes(cls, v: Any) -> bytes | None:
        if v is None or isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return base64.b64decode(v)
        raise TypeError(f"bundle_bytes must be bytes, base64 str, or None (got {type(v).__name__})")


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
    trace_hash: str | None = None
    line_ref: str | None = None
    snippet: str | None = None


class Finding(BaseModel):
    severity: Severity
    title: str
    description: str = ""
    evidence: FindingEvidence = Field(default_factory=FindingEvidence)
    recommendation: str = ""
    owasp_ref: str | None = None
    mitre_ref: str | None = None


class DependencyInfo(BaseModel):
    sbom_hash: str | None = None
    high_risk_packages: list[str] = Field(default_factory=list)
    known_vulns: list[str] = Field(default_factory=list)
    install_hooks: list[str] = Field(default_factory=list)


class RecommendedPolicy(BaseModel):
    """Machine-enforceable runtime policy a consuming runtime applies before
    invoking the skill. Miners set fields to only what was observed."""

    sandbox_runtime_image: str | None = None
    egress_allowlist: list[str] = Field(default_factory=list)
    egress_denylist: list[str] = Field(default_factory=list)
    filesystem: dict[str, Any] = Field(default_factory=dict)
    shell_access: bool = False
    env_allowlist: list[str] = Field(default_factory=list)
    max_memory_mb: int = 512
    timeout_seconds: int = 30
    rate_limit_rps: int | None = None


class DeclarativeEvidenceBlock(BaseModel):
    canary_id_found: str | None = None
    skill_md_fingerprint: str | None = None
    findings_count: int = 0
    layer0_sync_hash: str = ""
    analysis_duration_ms: int = 0


class EvidencePack(BaseModel):
    """Content-addressed hashes of the detonation traces. Validators replay
    detonation with the miner's nonce and require byte-equal hashes."""

    network_trace_hash: str | None = None
    fs_trace_hash: str | None = None
    process_trace_hash: str | None = None
    secrets_trace_hash: str | None = None
    sandbox_log_hash: str | None = None
    pcap_hash: str | None = None
    declarative: DeclarativeEvidenceBlock | None = None

    def component_hashes(self) -> dict[str, str | None]:
        return {
            "N": self.network_trace_hash,
            "F": self.fs_trace_hash,
            "P": self.process_trace_hash,
            "K": self.secrets_trace_hash,
        }


class RunMetadata(BaseModel):
    tools: dict[str, str] = Field(default_factory=dict)
    runtime_image: str | None = None
    determinism_seed: int = 0
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
    attestation: AttestationBlock | None = None
    countersignature: ValidatorCountersignature | None = None

    def canonical_json(self) -> str:
        """Sorted, separator-stable JSON omitting both signatures."""
        data = self.model_dump(exclude={"attestation", "countersignature"}, mode="json")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def signing_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_json().encode()).digest()

    def consensus_signing_bytes(self, round_id: str) -> bytes:
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

    ``canary_id`` + ``canary_val`` are the functional proof-of-execution
    challenge. The validator generates fresh values per (miner, task) and
    the miner must thread them into the sandbox environment. The harness
    writes ``canary_val`` to ``/evidence/.phylax_canary_<canary_id>`` and
    reads it back; both write and read get recorded in fs.jsonl. A miner
    that didn't actually launch the sandbox has no way to produce the
    matching fs_trace_hash (which combines the canary records with all the
    skill's own observations).
    """

    skill_bundle: SkillBundle
    nonce: int = 0
    round_id: str = ""
    deadline_unix: float = 0.0
    canary_id: str = ""
    canary_val: str = ""
    deadline_seconds: int = 0
    t_min_seconds: int = 0

    attestation: dict | None = None
    evidence_refs: dict | None = None
    error: str | None = None

    def get_sssa(self) -> SSSA | None:
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


class SkillIdentityV04(BaseModel):
    name: str
    bundle_hash: str
    skill_type: SkillType
    profile: TestProfile
    schema_version: str = SCHEMA_VERSION_V04


class VerdictBlockV04(BaseModel):
    decision: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    verdict_sources: list[str] = Field(default_factory=list)


class CapabilitiesV04Filesystem(BaseModel):
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)


class CapabilitiesV04Network(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)


class CapabilitiesV04(BaseModel):
    filesystem: CapabilitiesV04Filesystem = Field(default_factory=CapabilitiesV04Filesystem)
    network: CapabilitiesV04Network = Field(default_factory=CapabilitiesV04Network)
    process_spawns: list[str] = Field(default_factory=list)
    secrets_access: list[str] = Field(default_factory=list)
    shell_commands: list[str] = Field(default_factory=list)
    tool_calls: list[str] = Field(default_factory=list)
    child_skills: list[str] = Field(default_factory=list)


class FindingV04(BaseModel):
    finding_id: str
    severity: FindingSeverityV04
    title: str
    description: str = ""
    owasp_ref: str | None = None
    mitre_ref: str | None = None
    evidence_snippet: str = ""
    layer_source: FindingLayer
    finding_type: FindingType


class ChildSkillVerdict(BaseModel):
    skill_name: str
    bundle_hash: str
    verdict: ChildVerdict


class DependenciesV04(BaseModel):
    sbom_hash: str | None = None
    high_risk_packages: list[str] = Field(default_factory=list)
    known_cves: list[str] = Field(default_factory=list)
    install_hooks: list[str] = Field(default_factory=list)
    mcp_manifest_hash: str | None = None
    child_skill_verdicts: list[ChildSkillVerdict] = Field(default_factory=list)


class RecommendedPolicyV04(BaseModel):
    egress_allow: list[str] = Field(default_factory=list)
    egress_deny: list[str] = Field(default_factory=list)
    fs_read: list[str] = Field(default_factory=list)
    fs_write: list[str] = Field(default_factory=list)
    shell_access: bool = False
    max_memory_mb: int = 512
    timeout_s: int = 30
    env_allowlist: list[str] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    child_skill_allowlist: list[str] = Field(default_factory=list)


class EvidenceBaseV04(BaseModel):
    network_trace_hash: str | None = None
    fs_trace_hash: str | None = None
    process_trace_hash: str | None = None
    secrets_trace_hash: str | None = None


class RAGKnowledgeEvidence(BaseModel):
    rag_content_fingerprint: str
    hidden_instruction_score: float = Field(ge=0.0, le=1.0)
    embedded_urls: list[str] = Field(default_factory=list)
    document_count: int = Field(ge=0)
    canary_id_found: bool


class DeclarativeEvidenceV04(BaseModel):
    canary_id_found: bool
    findings_count: int = Field(ge=0)
    skill_md_fingerprint: str
    prompt_injection_ml_score: float = Field(ge=0.0, le=1.0)
    unicode_anomaly_detected: bool
    layer0_sync_hash: str


class ExecutablePythonEvidence(BaseModel):
    imports_trace_hash: str


class ExecutableScriptEvidence(BaseModel):
    shell_commands_hash: str


class MCPServerEvidence(BaseModel):
    tool_calls_hash: str
    mcp_manifest_hash: str
    tool_poisoning_score: float = Field(ge=0.0, le=1.0)
    tool_shadowing_detected: bool
    rug_pull_risk: bool


class AgentCompositionEvidence(BaseModel):
    agent_calls_hash: str
    dependency_graph_hash: str
    transitive_risk_score: float = Field(ge=0.0, le=1.0)
    composition_depth_observed: int = Field(ge=0)


class TypeSpecificEvidence(BaseModel):
    rag_knowledge: RAGKnowledgeEvidence | None = None
    declarative: DeclarativeEvidenceV04 | None = None
    executable_python: ExecutablePythonEvidence | None = None
    executable_script: ExecutableScriptEvidence | None = None
    mcp_server: MCPServerEvidence | None = None
    agent_composition: AgentCompositionEvidence | None = None


class LLMEvidence(BaseModel):
    model_id: str | None = None
    prompt_hash: str | None = None
    response_hash: str | None = None
    api_request_id: str | None = None
    token_count: int | None = None
    timestamp: str | None = None
    allowed_use: LLMAllowedUse | None = None


class EvidencePackV04(BaseModel):
    base: EvidenceBaseV04 = Field(default_factory=EvidenceBaseV04)
    type_specific: TypeSpecificEvidence = Field(default_factory=TypeSpecificEvidence)
    llm_evidence: LLMEvidence | None = None


class AttestationBlockV04(BaseModel):
    miner_hotkey: str
    supported_types_declared: list[SkillType]
    ed25519_signature: str
    timestamp: str
    schema_version: str = SCHEMA_VERSION_V04
    skill_type_version: str = SKILL_TYPE_VERSION


class SSSAV04(BaseModel):
    model_config = ConfigDict(extra="forbid")

    skill: SkillIdentityV04
    verdict: VerdictBlockV04
    capabilities: CapabilitiesV04 = Field(default_factory=CapabilitiesV04)
    findings: list[FindingV04] = Field(default_factory=list)
    dependencies: DependenciesV04 = Field(default_factory=DependenciesV04)
    recommended_policy: RecommendedPolicyV04 = Field(default_factory=RecommendedPolicyV04)
    evidence: EvidencePackV04 = Field(default_factory=EvidencePackV04)
    attestation: AttestationBlockV04 | None = None

    def canonical_json(self) -> str:
        data = self.model_dump(mode="json")
        if data.get("attestation") is not None:
            data["attestation"].pop("ed25519_signature", None)
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def signing_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_json().encode()).digest()


class BundleMetadataV04(BaseModel):
    skill_name: str
    skill_version: str = "unknown"
    skill_type: SkillType
    profile: TestProfile = TestProfile.STANDARD
    composition_depth: int | None = None
    child_skill_hashes: list[str] = Field(default_factory=list)


class SkillBundleV04(BaseModel):
    bundle_hash: str
    bundle_url: str | None = None
    bundle_bytes: bytes | None = None
    metadata: BundleMetadataV04

    @field_validator("bundle_hash")
    @classmethod
    def _hash_shape(cls, v: str) -> str:
        if not v.startswith("sha256:") or len(v) != 71:
            raise ValueError("bundle_hash must be 'sha256:<64 hex chars>'")
        return v

    @field_serializer("bundle_bytes")
    def _ser_bundle_bytes(self, v: bytes | None) -> str | None:
        return base64.b64encode(v).decode("ascii") if v else None

    @field_validator("bundle_bytes", mode="before")
    @classmethod
    def _val_bundle_bytes(cls, v: Any) -> bytes | None:
        if v is None or isinstance(v, bytes):
            return v
        if isinstance(v, str):
            return base64.b64decode(v)
        raise TypeError(f"bundle_bytes must be bytes, base64 str, or None (got {type(v).__name__})")


class TaskMetadataV04(BaseModel):
    task_id: str
    task_type: TaskType
    deadline_s: int = Field(ge=1)
    t_min_s: int = Field(ge=0)
    skill_type_version: str = SKILL_TYPE_VERSION


class InferenceConfig(BaseModel):
    proxy_url: str | None = None
    allowed_models: list[str] = Field(default_factory=list)
    max_tokens: int = 2000
    temperature: float = 0.0
    cost_limit_usd: float = 0.50
    allowed_uses: list[LLMAllowedUse] = Field(
        default_factory=lambda: [
            LLMAllowedUse.FINDING_ENRICHMENT,
            LLMAllowedUse.MITRE_OWASP_MAPPING,
            LLMAllowedUse.CVE_EXPLANATION,
        ]
    )
    forbidden_uses: list[str] = Field(
        default_factory=lambda: [
            "skill_content_analysis",
            "verdict_reasoning",
            "behavior_mismatch_detection",
            "prompt_injection_scoring",
            "tool_poisoning_scoring",
        ]
    )


class PhylaxSynapseV04(bt.Synapse):
    skill_bundle: SkillBundleV04
    nonce: str = ""
    task_metadata: TaskMetadataV04
    inference_config: InferenceConfig | None = None

    attestation: dict | None = None
    error: str | None = None

    def get_sssa(self) -> SSSAV04 | None:
        if self.attestation is None:
            return None
        return SSSAV04(**self.attestation)

    def is_valid_response(self) -> bool:
        if self.error or self.attestation is None:
            return False
        try:
            sssa = self.get_sssa()
            return sssa is not None and sssa.attestation is not None
        except Exception:  # noqa: BLE001
            return False


def detect_sssa_version(payload: dict[str, Any]) -> str:
    attestation = payload.get("attestation") or {}
    return attestation.get("schema_version") or payload.get("schema_version") or "0.3"


def parse_sssa(payload: dict[str, Any]) -> SSSA | SSSAV04:
    version = detect_sssa_version(payload)
    if version == SCHEMA_VERSION_V04:
        return SSSAV04(**payload)
    return SSSA(**payload)

