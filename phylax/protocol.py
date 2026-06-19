from __future__ import annotations

import base64
import hashlib
import json
from enum import Enum
from typing import Any

import bittensor as bt
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

SCHEMA_VERSION = "1.0"
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


class TestProfile(str, Enum):
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


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


class FindingSeverity(str, Enum):
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


class SkillIdentity(BaseModel):
    name: str
    bundle_hash: str
    skill_type: SkillType
    profile: TestProfile
    schema_version: str = SCHEMA_VERSION


class VerdictBlock(BaseModel):
    decision: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    verdict_sources: list[str] = Field(default_factory=list)


class FilesystemCapabilities(BaseModel):
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)


class NetworkCapabilities(BaseModel):
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)


class Capabilities(BaseModel):
    filesystem: FilesystemCapabilities = Field(default_factory=FilesystemCapabilities)
    network: NetworkCapabilities = Field(default_factory=NetworkCapabilities)
    process_spawns: list[str] = Field(default_factory=list)
    secrets_access: list[str] = Field(default_factory=list)
    shell_commands: list[str] = Field(default_factory=list)
    tool_calls: list[str] = Field(default_factory=list)
    child_skills: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str
    severity: FindingSeverity
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


class Dependencies(BaseModel):
    sbom_hash: str | None = None
    high_risk_packages: list[str] = Field(default_factory=list)
    known_cves: list[str] = Field(default_factory=list)
    install_hooks: list[str] = Field(default_factory=list)
    mcp_manifest_hash: str | None = None
    child_skill_verdicts: list[ChildSkillVerdict] = Field(default_factory=list)


class RecommendedPolicy(BaseModel):
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


class EvidenceBase(BaseModel):
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


class DeclarativeEvidence(BaseModel):
    canary_id_found: bool
    findings_count: int = Field(ge=0)
    skill_md_fingerprint: str
    prompt_injection_ml_score: float = Field(ge=0.0, le=1.0)
    unicode_anomaly_detected: bool
    layer0_sync_hash: str


class ExecutablePythonEvidence(BaseModel):
    # Per-type hashes are populated by the miner at submission time from real
    # sandbox execution. They are nullable on the validator side so that
    # task_definitions rows ingested under the legacy v1 schema (where these
    # fields did not exist) can still be parsed into the ground-truth model
    # without exploding bundle preparation. Scoring already null-guards.
    imports_trace_hash: str | None = None


class ExecutableScriptEvidence(BaseModel):
    shell_commands_hash: str | None = None


class MCPServerEvidence(BaseModel):
    tool_calls_hash: str | None = None
    mcp_manifest_hash: str | None = None
    tool_poisoning_score: float = Field(default=0.0, ge=0.0, le=1.0)
    tool_shadowing_detected: bool = False
    rug_pull_risk: bool = False


class AgentCompositionEvidence(BaseModel):
    agent_calls_hash: str | None = None
    dependency_graph_hash: str | None = None
    transitive_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    composition_depth_observed: int = Field(default=0, ge=0)


class TypeSpecificEvidence(BaseModel):
    rag_knowledge: RAGKnowledgeEvidence | None = None
    declarative: DeclarativeEvidence | None = None
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


class EvidencePack(BaseModel):
    base: EvidenceBase = Field(default_factory=EvidenceBase)
    type_specific: TypeSpecificEvidence = Field(default_factory=TypeSpecificEvidence)
    llm_evidence: LLMEvidence | None = None


class AttestationBlock(BaseModel):
    miner_hotkey: str
    supported_types_declared: list[SkillType]
    ed25519_signature: str
    timestamp: str
    schema_version: str = SCHEMA_VERSION
    skill_type_version: str = SKILL_TYPE_VERSION


class SSSA(BaseModel):
    model_config = ConfigDict(extra="forbid")

    skill: SkillIdentity
    verdict: VerdictBlock
    capabilities: Capabilities = Field(default_factory=Capabilities)
    findings: list[Finding] = Field(default_factory=list)
    dependencies: Dependencies = Field(default_factory=Dependencies)
    recommended_policy: RecommendedPolicy = Field(default_factory=RecommendedPolicy)
    evidence: EvidencePack = Field(default_factory=EvidencePack)
    attestation: AttestationBlock | None = None

    def canonical_json(self) -> str:
        data = self.model_dump(mode="json")
        if data.get("attestation") is not None:
            data["attestation"].pop("ed25519_signature", None)
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def signing_hash(self) -> bytes:
        return hashlib.sha256(self.canonical_json().encode()).digest()


class BundleMetadata(BaseModel):
    # Defaults make this default-constructible so bittensor's Synapse.from_headers()
    # can build a placeholder from an empty header dict (the actual data arrives
    # later via the request body). Validators below still enforce the contract
    # whenever a non-default value is supplied.
    skill_name: str = ""
    skill_version: str = "unknown"
    skill_type: SkillType = SkillType.DECLARATIVE
    profile: TestProfile = TestProfile.STANDARD
    composition_depth: int | None = None
    child_skill_hashes: list[str] = Field(default_factory=list)


class SkillBundle(BaseModel):
    # Same reason as BundleMetadata: all input fields need defaults so the
    # bittensor axon can `from_headers({})` without exploding before the body
    # parser fills in the real data.
    bundle_hash: str = ""
    bundle_url: str | None = None
    bundle_bytes: bytes | None = None
    metadata: BundleMetadata = Field(default_factory=BundleMetadata)

    @field_validator("bundle_hash")
    @classmethod
    def _hash_shape(cls, v: str) -> str:
        # Empty string is the placeholder used by from_headers; only validate
        # the format when an actual value is supplied.
        if v == "":
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


class TaskMetadata(BaseModel):
    # Defaults make this default-constructible (see BundleMetadata).
    # deadline_s used to enforce ge=1 unconditionally; we keep that bound
    # but seed a placeholder of 1 so an empty-dict init still passes. The
    # actual deadline arrives via the request body and overrides this.
    task_id: str = ""
    task_type: TaskType = TaskType.SERVER_CURATED
    deadline_s: int = Field(default=1, ge=1)
    t_min_s: int = Field(default=0, ge=0)
    skill_type_version: str = SKILL_TYPE_VERSION
    role: str = "primary"


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


class SandboxManifest(BaseModel):
    image: str
    digest: str
    tracer_version: str
    tracer_hash: str | None = None
    kernel: str | None = None
    cpu_arch: str | None = None
    extras: dict[str, str] = Field(default_factory=dict)


REQUIRED_TRACE_FILES: dict[SkillType, tuple[str, ...]] = {
    SkillType.RAG_KNOWLEDGE: (),
    SkillType.DECLARATIVE: (),
    SkillType.EXECUTABLE_PYTHON: (
        "network.jsonl.gz", "fs.jsonl.gz", "process.jsonl.gz",
        "secrets.jsonl.gz", "imports.jsonl.gz",
    ),
    SkillType.EXECUTABLE_SCRIPT: (
        "network.jsonl.gz", "fs.jsonl.gz", "process.jsonl.gz",
        "secrets.jsonl.gz", "shell_commands.jsonl.gz",
    ),
    SkillType.MCP_SERVER: (
        "network.jsonl.gz", "fs.jsonl.gz", "process.jsonl.gz",
        "secrets.jsonl.gz", "tool_calls.jsonl.gz",
    ),
    SkillType.AGENT_COMPOSITION: (
        "network.jsonl.gz", "fs.jsonl.gz", "process.jsonl.gz",
        "secrets.jsonl.gz", "agent_calls.jsonl.gz",
    ),
}


class MinerRole(str, Enum):
    PRIMARY = "primary"
    AUDITOR = "auditor"


class PhylaxSynapse(bt.Synapse):
    skill_bundle: SkillBundle
    nonce: str = ""
    task_metadata: TaskMetadata
    inference_config: InferenceConfig | None = None

    attestation: dict | None = None
    trace_bundle: dict[str, str] | None = None
    sandbox_manifest: dict | None = None
    probe_evidence: dict | None = None
    analysis_proof: dict | None = None
    error: str | None = None
    latency_ms: int | None = None

    def get_sssa(self) -> SSSA | None:
        if self.attestation is None:
            return None
        return SSSA(**self.attestation)

    def is_valid_response(self) -> bool:
        if self.error or self.attestation is None:
            return False
        try:
            sssa = self.get_sssa()
            if sssa is None or sssa.attestation is None:
                return False
            skill_type = sssa.skill.skill_type
            if REQUIRED_TRACE_FILES.get(skill_type):
                if not self.trace_bundle or not isinstance(self.trace_bundle, dict):
                    return False
                if not self.sandbox_manifest or not isinstance(self.sandbox_manifest, dict):
                    return False
            return True
        except Exception:  # noqa: BLE001
            return False


class ClassifySynapse(bt.Synapse):
    skill_id: str = ""
    slug: str = ""
    source_url: str = ""
    pinned_commit: str = ""
    deadline_s: int = Field(default=1, ge=1)

    bundle_hash: str | None = None
    skill_type: str | None = None
    bundle_b64: str | None = None
    error: str | None = None
    latency_ms: int | None = None

    def is_valid_response(self) -> bool:
        if self.error or not self.bundle_hash or not self.skill_type:
            return False
        try:
            SkillType(self.skill_type)
        except ValueError:
            return False
        h = self.bundle_hash.removeprefix("sha256:")
        return len(h) == 64 and all(c in "0123456789abcdef" for c in h)
