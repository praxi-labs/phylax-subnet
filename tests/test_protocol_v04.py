from __future__ import annotations

import json
import uuid

import pytest

from phylax.protocol import (
    SCHEMA_VERSION,
    SCHEMA_VERSION_V04,
    SKILL_TYPE_VERSION,
    SSSA,
    SSSAV04,
    AgentCompositionEvidence,
    AttestationBlock,
    AttestationBlockV04,
    BundleMetadataV04,
    ChildSkillVerdict,
    ChildVerdict,
    DeclarativeEvidenceV04,
    DependenciesV04,
    EvidenceBaseV04,
    EvidencePack,
    EvidencePackV04,
    ExecutablePythonEvidence,
    ExecutableScriptEvidence,
    FindingLayer,
    FindingSeverityV04,
    FindingType,
    FindingV04,
    InferenceConfig,
    LLMAllowedUse,
    MCPServerEvidence,
    RAGKnowledgeEvidence,
    RecommendedPolicyV04,
    SkillBundleV04,
    SkillIdentity,
    SkillIdentityV04,
    SkillType,
    TaskMetadataV04,
    TaskType,
    TestProfile,
    TypeSpecificEvidence,
    Verdict,
    VerdictBlock,
    VerdictBlockV04,
    detect_sssa_version,
    parse_sssa,
)


def _v03_sssa() -> SSSA:
    return SSSA(
        skill=SkillIdentity(name="legacy", bundle_hash="sha256:" + "a" * 64),
        verdict=VerdictBlock(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
        evidence=EvidencePack(),
        attestation=AttestationBlock(
            miner_hotkey="5LEGACY",
            signature="deadbeef",
            timestamp="2026-01-01T00:00:00Z",
        ),
    )


def _v04_evidence_python() -> EvidencePackV04:
    return EvidencePackV04(
        base=EvidenceBaseV04(
            network_trace_hash="sha256:" + "0" * 64,
            fs_trace_hash="sha256:" + "1" * 64,
            process_trace_hash="sha256:" + "2" * 64,
            secrets_trace_hash="sha256:" + "3" * 64,
        ),
        type_specific=TypeSpecificEvidence(
            executable_python=ExecutablePythonEvidence(
                imports_trace_hash="sha256:" + "4" * 64,
            ),
        ),
    )


def _v04_sssa(skill_type: SkillType = SkillType.EXECUTABLE_PYTHON) -> SSSAV04:
    return SSSAV04(
        skill=SkillIdentityV04(
            name="x",
            bundle_hash="sha256:" + "b" * 64,
            skill_type=skill_type,
            profile=TestProfile.STANDARD,
        ),
        verdict=VerdictBlockV04(
            decision=Verdict.ALLOW,
            risk_score=10,
            confidence=0.9,
            verdict_sources=["L1_taint"],
        ),
        evidence=_v04_evidence_python(),
        attestation=AttestationBlockV04(
            miner_hotkey="5DLAsR",
            supported_types_declared=[SkillType.EXECUTABLE_PYTHON, SkillType.DECLARATIVE],
            ed25519_signature="cafebabe",
            timestamp="2026-05-30T12:00:00Z",
        ),
    )


class TestSchemaVersionConstants:
    def test_v04_constants_match_spec(self):
        assert SCHEMA_VERSION_V04 == "0.4"
        assert SKILL_TYPE_VERSION == "1.0"

    def test_v03_constant_untouched(self):
        assert SCHEMA_VERSION == "1.1.0"


class TestSkillTypeEnum:
    def test_all_six_values(self):
        assert {t.value for t in SkillType} == {
            "rag_knowledge",
            "declarative",
            "executable_python",
            "executable_script",
            "mcp_server",
            "agent_composition",
        }


class TestRoundtrip:
    def test_v04_sssa_roundtrips(self):
        original = _v04_sssa()
        as_dict = original.model_dump(mode="json")
        reconstructed = SSSAV04(**as_dict)
        assert reconstructed.model_dump(mode="json") == as_dict

    def test_rag_knowledge_evidence_roundtrip(self):
        pack = EvidencePackV04(
            type_specific=TypeSpecificEvidence(
                rag_knowledge=RAGKnowledgeEvidence(
                    rag_content_fingerprint="sha256:" + "f" * 64,
                    hidden_instruction_score=0.42,
                    embedded_urls=["https://example.com"],
                    document_count=12,
                    canary_id_found=True,
                ),
            ),
        )
        data = pack.model_dump(mode="json")
        EvidencePackV04(**data)

    def test_declarative_evidence_roundtrip(self):
        pack = EvidencePackV04(
            type_specific=TypeSpecificEvidence(
                declarative=DeclarativeEvidenceV04(
                    canary_id_found=True,
                    findings_count=3,
                    skill_md_fingerprint="sha256:" + "a" * 64,
                    prompt_injection_ml_score=0.85,
                    unicode_anomaly_detected=False,
                    layer0_sync_hash="sha256:" + "b" * 64,
                ),
            ),
        )
        EvidencePackV04(**pack.model_dump(mode="json"))

    def test_executable_script_evidence_roundtrip(self):
        pack = EvidencePackV04(
            base=EvidenceBaseV04(fs_trace_hash="sha256:" + "1" * 64),
            type_specific=TypeSpecificEvidence(
                executable_script=ExecutableScriptEvidence(
                    shell_commands_hash="sha256:" + "5" * 64,
                ),
            ),
        )
        EvidencePackV04(**pack.model_dump(mode="json"))

    def test_mcp_server_evidence_roundtrip(self):
        pack = EvidencePackV04(
            type_specific=TypeSpecificEvidence(
                mcp_server=MCPServerEvidence(
                    tool_calls_hash="sha256:" + "6" * 64,
                    mcp_manifest_hash="sha512:" + "7" * 128,
                    tool_poisoning_score=0.7,
                    tool_shadowing_detected=False,
                    rug_pull_risk=False,
                ),
            ),
        )
        EvidencePackV04(**pack.model_dump(mode="json"))

    def test_agent_composition_evidence_roundtrip(self):
        pack = EvidencePackV04(
            type_specific=TypeSpecificEvidence(
                agent_composition=AgentCompositionEvidence(
                    agent_calls_hash="sha256:" + "8" * 64,
                    dependency_graph_hash="sha256:" + "9" * 64,
                    transitive_risk_score=0.55,
                    composition_depth_observed=3,
                ),
            ),
        )
        EvidencePackV04(**pack.model_dump(mode="json"))

    def test_finding_v04_roundtrip(self):
        f = FindingV04(
            finding_id=str(uuid.uuid4()),
            severity=FindingSeverityV04.HIGH,
            title="exec of untrusted input",
            description="bandit-B102 hit",
            owasp_ref="A03",
            mitre_ref="T1059",
            evidence_snippet="exec(user_input)",
            layer_source=FindingLayer.L1,
            finding_type=FindingType.STATIC,
        )
        assert FindingV04(**f.model_dump(mode="json")) == f


class TestCanonicalJSON:
    def test_canonical_keys_sorted_at_every_level(self):
        sssa = _v04_sssa()
        canon = sssa.canonical_json()
        loaded = json.loads(canon)

        def check_sorted(obj):
            if isinstance(obj, dict):
                keys = list(obj.keys())
                assert keys == sorted(keys), f"unsorted: {keys}"
                for v in obj.values():
                    check_sorted(v)
            elif isinstance(obj, list):
                for v in obj:
                    check_sorted(v)

        check_sorted(loaded)

    def test_canonical_no_whitespace(self):
        sssa = _v04_sssa()
        canon = sssa.canonical_json()
        assert ", " not in canon
        assert ": " not in canon

    def test_canonical_excludes_signature(self):
        sssa = _v04_sssa()
        canon = sssa.canonical_json()
        assert "cafebabe" not in canon

    def test_canonical_bytewise_stable_across_field_reorderings(self):
        sssa1 = _v04_sssa()
        as_dict = sssa1.model_dump(mode="json")
        reordered = {k: as_dict[k] for k in reversed(list(as_dict.keys()))}
        sssa2 = SSSAV04(**reordered)
        assert sssa1.canonical_json() == sssa2.canonical_json()

    def test_signing_hash_is_sha256_of_canonical(self):
        import hashlib

        sssa = _v04_sssa()
        canon = sssa.canonical_json()
        assert sssa.signing_hash() == hashlib.sha256(canon.encode()).digest()


class TestVersionDetectionAndDispatch:
    def test_detect_v04(self):
        payload = _v04_sssa().model_dump(mode="json")
        assert detect_sssa_version(payload) == SCHEMA_VERSION_V04

    def test_detect_v03_default(self):
        payload = _v03_sssa().model_dump(mode="json")
        assert detect_sssa_version(payload) != SCHEMA_VERSION_V04

    def test_parse_returns_v04_for_v04_payload(self):
        payload = _v04_sssa().model_dump(mode="json")
        result = parse_sssa(payload)
        assert isinstance(result, SSSAV04)

    def test_parse_returns_v03_for_v03_payload(self):
        payload = _v03_sssa().model_dump(mode="json")
        result = parse_sssa(payload)
        assert isinstance(result, SSSA)


class TestBackwardCompatibility:
    def test_v03_sssa_still_instantiable(self):
        sssa = _v03_sssa()
        assert sssa.attestation is not None
        assert sssa.skill.name == "legacy"

    def test_v03_evidence_pack_still_works(self):
        pack = EvidencePack(network_trace_hash="sha256:" + "0" * 64)
        assert pack.network_trace_hash.startswith("sha256:")

    def test_v03_verdict_block_still_works(self):
        v = VerdictBlock(decision=Verdict.BLOCK, risk_score=99, confidence=0.95)
        assert v.decision == Verdict.BLOCK


class TestRecommendedPolicyV04:
    def test_defaults_match_spec(self):
        p = RecommendedPolicyV04()
        assert p.max_memory_mb == 512
        assert p.timeout_s == 30
        assert p.shell_access is False
        assert p.egress_allow == []
        assert p.tool_allowlist == []
        assert p.child_skill_allowlist == []


class TestInferenceConfig:
    def test_default_allowed_uses_match_spec(self):
        cfg = InferenceConfig()
        assert set(cfg.allowed_uses) == {
            LLMAllowedUse.FINDING_ENRICHMENT,
            LLMAllowedUse.MITRE_OWASP_MAPPING,
            LLMAllowedUse.CVE_EXPLANATION,
        }

    def test_forbidden_uses_present(self):
        cfg = InferenceConfig()
        assert "skill_content_analysis" in cfg.forbidden_uses
        assert "verdict_reasoning" in cfg.forbidden_uses


class TestBundleAndTaskMetadata:
    def test_bundle_hash_validation(self):
        with pytest.raises(ValueError, match="sha256:"):
            SkillBundleV04(
                bundle_hash="not-a-hash",
                metadata=BundleMetadataV04(
                    skill_name="x",
                    skill_type=SkillType.DECLARATIVE,
                ),
            )

    def test_task_metadata_requires_positive_deadline(self):
        with pytest.raises(ValueError):
            TaskMetadataV04(
                task_id="t1",
                task_type=TaskType.SERVER_CURATED,
                deadline_s=0,
                t_min_s=0,
            )

    def test_bundle_bytes_base64_roundtrip(self):
        raw = b"hello phylax"
        bundle = SkillBundleV04(
            bundle_hash="sha256:" + "a" * 64,
            bundle_bytes=raw,
            metadata=BundleMetadataV04(
                skill_name="x",
                skill_type=SkillType.DECLARATIVE,
            ),
        )
        serialized = bundle.model_dump(mode="json")
        reconstructed = SkillBundleV04(**serialized)
        assert reconstructed.bundle_bytes == raw


class TestAttestationBlockV04:
    def test_supported_types_declared_required(self):
        ab = AttestationBlockV04(
            miner_hotkey="5DLAsR",
            supported_types_declared=[SkillType.MCP_SERVER],
            ed25519_signature="00",
            timestamp="2026-05-30T12:00:00Z",
        )
        assert ab.schema_version == SCHEMA_VERSION_V04
        assert ab.skill_type_version == SKILL_TYPE_VERSION


class TestDependenciesV04:
    def test_child_skill_verdicts(self):
        deps = DependenciesV04(
            child_skill_verdicts=[
                ChildSkillVerdict(
                    skill_name="child-a",
                    bundle_hash="sha256:" + "c" * 64,
                    verdict=ChildVerdict.WARN,
                ),
            ],
        )
        assert deps.child_skill_verdicts[0].verdict == ChildVerdict.WARN
