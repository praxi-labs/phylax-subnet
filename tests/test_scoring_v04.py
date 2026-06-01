from __future__ import annotations

import pytest

from phylax.protocol import (
    SCHEMA_VERSION_V04,
    SSSAV04,
    AgentCompositionEvidence,
    AttestationBlockV04,
    DeclarativeEvidenceV04,
    EvidenceBaseV04,
    EvidencePackV04,
    ExecutablePythonEvidence,
    MCPServerEvidence,
    RAGKnowledgeEvidence,
    RecommendedPolicyV04,
    SkillIdentityV04,
    SkillType,
    TestProfile,
    TypeSpecificEvidence,
    Verdict,
    VerdictBlockV04,
)
from phylax.scoring.metrics_v04 import (
    BASE_WEIGHTS,
    EVIDENCE_GATE,
    REFERENCE_BASELINES,
    TIER_MULTIPLIERS,
    AxesV04,
    TaskContext,
    Tier,
    classify_tier,
    compute_Q,
    compute_task_emissions_score,
    recalibrate_novel_threshold,
    score_all_axes,
    score_alpha,
    score_chi,
    score_epsilon,
    score_eta,
    score_mu,
    score_pi,
    score_psi,
    score_rho,
    score_sigma,
    score_tau,
)

HASH64 = "sha256:" + "0" * 64
HASH512 = "sha512:" + "1" * 128


def _attestation(types: list[SkillType]) -> AttestationBlockV04:
    return AttestationBlockV04(
        miner_hotkey="5DLAsR",
        supported_types_declared=types,
        ed25519_signature="cafebabe",
        timestamp="2026-05-30T12:00:00Z",
    )


def _python_sssa(
    decision: Verdict = Verdict.ALLOW,
    risk: int = 10,
    fs_hash: str = HASH64,
    imports_hash: str = HASH64,
    policy: RecommendedPolicyV04 | None = None,
) -> SSSAV04:
    return SSSAV04(
        skill=SkillIdentityV04(
            name="p",
            bundle_hash="sha256:" + "b" * 64,
            skill_type=SkillType.EXECUTABLE_PYTHON,
            profile=TestProfile.STANDARD,
        ),
        verdict=VerdictBlockV04(decision=decision, risk_score=risk, confidence=0.9),
        recommended_policy=policy or RecommendedPolicyV04(),
        evidence=EvidencePackV04(
            base=EvidenceBaseV04(
                network_trace_hash=HASH64,
                fs_trace_hash=fs_hash,
                process_trace_hash=HASH64,
                secrets_trace_hash=HASH64,
            ),
            type_specific=TypeSpecificEvidence(
                executable_python=ExecutablePythonEvidence(imports_trace_hash=imports_hash),
            ),
        ),
        attestation=_attestation([SkillType.EXECUTABLE_PYTHON]),
    )


class TestAlphaAsymmetricLoss:
    def test_correct_verdict_full_credit(self):
        sssa = _python_sssa(Verdict.BLOCK)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON, expected_verdict=Verdict.BLOCK
        )
        assert score_alpha(sssa, ctx) == pytest.approx(1.0)

    def test_false_negative_penalised_harder_than_false_positive(self):
        ctx_fn = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON, expected_verdict=Verdict.BLOCK
        )
        ctx_fp = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON, expected_verdict=Verdict.ALLOW
        )
        sssa_fn = _python_sssa(Verdict.ALLOW)
        sssa_fp = _python_sssa(Verdict.BLOCK)
        fn_score = score_alpha(sssa_fn, ctx_fn)
        fp_score = score_alpha(sssa_fp, ctx_fp)
        assert fn_score < fp_score

    def test_distance_one_fp(self):
        sssa = _python_sssa(Verdict.WARN)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON, expected_verdict=Verdict.ALLOW
        )
        assert score_alpha(sssa, ctx) == pytest.approx(1.0 - 0.4 * 1 / 2.0)

    def test_distance_one_fn(self):
        sssa = _python_sssa(Verdict.WARN)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON, expected_verdict=Verdict.BLOCK
        )
        assert score_alpha(sssa, ctx) == pytest.approx(1.0 - 1.0 * 1 / 2.0)

    def test_provenance_consensus_weight(self):
        sssa = _python_sssa(Verdict.BLOCK)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_verdict=Verdict.BLOCK,
            annotated_by="consensus",
        )
        assert score_alpha(sssa, ctx) == pytest.approx(0.7)

    def test_unknown_provenance_raises(self):
        sssa = _python_sssa(Verdict.BLOCK)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_verdict=Verdict.BLOCK,
            annotated_by="frenkenstein",
        )
        with pytest.raises(ValueError, match="annotated_by"):
            score_alpha(sssa, ctx)


class TestEpsilonPerType:
    def test_python_hard_fail_on_fs_mismatch(self):
        sssa = _python_sssa(fs_hash=HASH64)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_evidence={"fs_trace_hash": "sha256:" + "9" * 64},
        )
        assert score_epsilon(sssa, ctx) == 0.0

    def test_python_full_match_with_imports_bonus(self):
        sssa = _python_sssa(fs_hash=HASH64, imports_hash=HASH64)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_evidence={
                "network_trace_hash": HASH64,
                "fs_trace_hash": HASH64,
                "process_trace_hash": HASH64,
                "secrets_trace_hash": HASH64,
                "imports_trace_hash": HASH64,
            },
        )
        assert score_epsilon(sssa, ctx) == pytest.approx(1.0)

    def test_declarative_requires_canary(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="d",
                bundle_hash="sha256:" + "c" * 64,
                skill_type=SkillType.DECLARATIVE,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    declarative=DeclarativeEvidenceV04(
                        canary_id_found=False,
                        findings_count=0,
                        skill_md_fingerprint=HASH64,
                        prompt_injection_ml_score=0.1,
                        unicode_anomaly_detected=False,
                        layer0_sync_hash=HASH64,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.DECLARATIVE]),
        )
        ctx = TaskContext(skill_type=SkillType.DECLARATIVE)
        assert score_epsilon(sssa, ctx) == 0.0

    def test_declarative_canary_plus_ml_plus_unicode_caps_at_one(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="d",
                bundle_hash="sha256:" + "c" * 64,
                skill_type=SkillType.DECLARATIVE,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    declarative=DeclarativeEvidenceV04(
                        canary_id_found=True,
                        findings_count=2,
                        skill_md_fingerprint=HASH64,
                        prompt_injection_ml_score=0.5,
                        unicode_anomaly_detected=True,
                        layer0_sync_hash=HASH64,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.DECLARATIVE]),
        )
        ctx = TaskContext(skill_type=SkillType.DECLARATIVE)
        assert score_epsilon(sssa, ctx) == pytest.approx(1.0)

    def test_rag_fingerprint_mismatch_zeroes(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="r",
                bundle_hash="sha256:" + "d" * 64,
                skill_type=SkillType.RAG_KNOWLEDGE,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    rag_knowledge=RAGKnowledgeEvidence(
                        rag_content_fingerprint=HASH64,
                        hidden_instruction_score=0.2,
                        embedded_urls=[],
                        document_count=10,
                        canary_id_found=True,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.RAG_KNOWLEDGE]),
        )
        ctx = TaskContext(
            skill_type=SkillType.RAG_KNOWLEDGE,
            ground_truth={"rag_content_fingerprint": "sha256:" + "e" * 64},
        )
        assert score_epsilon(sssa, ctx) == 0.0

    def test_mcp_tool_calls_mismatch_zeroes(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="m",
                bundle_hash="sha256:" + "e" * 64,
                skill_type=SkillType.MCP_SERVER,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                base=EvidenceBaseV04(
                    network_trace_hash=HASH64,
                    fs_trace_hash=HASH64,
                    process_trace_hash=HASH64,
                    secrets_trace_hash=HASH64,
                ),
                type_specific=TypeSpecificEvidence(
                    mcp_server=MCPServerEvidence(
                        tool_calls_hash=HASH64,
                        mcp_manifest_hash=HASH512,
                        tool_poisoning_score=0.1,
                        tool_shadowing_detected=False,
                        rug_pull_risk=False,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.MCP_SERVER]),
        )
        ctx = TaskContext(
            skill_type=SkillType.MCP_SERVER,
            expected_evidence={"tool_calls_hash": "sha256:" + "f" * 64},
        )
        assert score_epsilon(sssa, ctx) == 0.0

    def test_agent_composition_calls_mismatch_zeroes(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="a",
                bundle_hash="sha256:" + "f" * 64,
                skill_type=SkillType.AGENT_COMPOSITION,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                base=EvidenceBaseV04(
                    network_trace_hash=HASH64,
                    fs_trace_hash=HASH64,
                    process_trace_hash=HASH64,
                    secrets_trace_hash=HASH64,
                ),
                type_specific=TypeSpecificEvidence(
                    agent_composition=AgentCompositionEvidence(
                        agent_calls_hash=HASH64,
                        dependency_graph_hash=HASH64,
                        transitive_risk_score=0.3,
                        composition_depth_observed=2,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.AGENT_COMPOSITION]),
        )
        ctx = TaskContext(
            skill_type=SkillType.AGENT_COMPOSITION,
            expected_evidence={"agent_calls_hash": "sha256:" + "1" * 64},
        )
        assert score_epsilon(sssa, ctx) == 0.0


class TestPi:
    def test_empty_both_returns_one(self):
        sssa = _python_sssa(policy=RecommendedPolicyV04())
        ctx = TaskContext(skill_type=SkillType.EXECUTABLE_PYTHON, expected_policy={})
        assert score_pi(sssa, ctx) == pytest.approx(1.0)

    def test_perfect_match_returns_one(self):
        policy = RecommendedPolicyV04(
            egress_allow=["api.example.com"],
            fs_read=["/etc/passwd"],
            max_memory_mb=256,
            timeout_s=30,
        )
        sssa = _python_sssa(policy=policy)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_policy={
                "egress_allow": ["api.example.com"],
                "fs_read": ["/etc/passwd"],
                "max_memory_mb": 256,
                "timeout_s": 30,
                "shell_access": False,
            },
        )
        assert score_pi(sssa, ctx) == pytest.approx(1.0)

    def test_disjoint_returns_zero(self):
        policy = RecommendedPolicyV04(egress_allow=["good.com"])
        sssa = _python_sssa(policy=policy)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_policy={"egress_allow": ["bad.com"]},
        )
        s = score_pi(sssa, ctx)
        assert 0.0 <= s < 0.5


class TestEta:
    def test_zero_if_too_fast(self):
        sssa = _python_sssa()
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            submission_latency_ms=1000,
            deadline_s=150,
            t_min_s=15,
        )
        assert score_eta(sssa, ctx) == 0.0

    def test_sweet_spot_high(self):
        sssa = _python_sssa()
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            submission_latency_ms=int((15 + 0.25 * (150 - 15)) * 1000),
            deadline_s=150,
            t_min_s=15,
        )
        assert score_eta(sssa, ctx) == pytest.approx(1.0, abs=1e-3)

    def test_decays_toward_deadline(self):
        sssa = _python_sssa()
        ctx_sweet = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            submission_latency_ms=int((15 + 0.25 * (150 - 15)) * 1000),
            deadline_s=150,
            t_min_s=15,
        )
        ctx_late = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            submission_latency_ms=int((150 - 1) * 1000),
            deadline_s=150,
            t_min_s=15,
        )
        assert score_eta(sssa, ctx_late) < score_eta(sssa, ctx_sweet)

    def test_zero_when_no_minimum_evidence(self):
        sssa = _python_sssa(imports_hash="")
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            submission_latency_ms=30000,
            deadline_s=150,
            t_min_s=15,
        )
        assert score_eta(sssa, ctx) == 0.0


class TestTypeSpecificAxes:
    def test_mu_returns_zero_without_truth(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="d",
                bundle_hash="sha256:" + "c" * 64,
                skill_type=SkillType.DECLARATIVE,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    declarative=DeclarativeEvidenceV04(
                        canary_id_found=True,
                        findings_count=0,
                        skill_md_fingerprint=HASH64,
                        prompt_injection_ml_score=0.5,
                        unicode_anomaly_detected=False,
                        layer0_sync_hash=HASH64,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.DECLARATIVE]),
        )
        ctx = TaskContext(skill_type=SkillType.DECLARATIVE)
        assert score_mu(sssa, ctx) == 0.0

    def test_mu_high_when_close_to_truth(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="d",
                bundle_hash="sha256:" + "c" * 64,
                skill_type=SkillType.DECLARATIVE,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    declarative=DeclarativeEvidenceV04(
                        canary_id_found=True,
                        findings_count=0,
                        skill_md_fingerprint=HASH64,
                        prompt_injection_ml_score=0.7,
                        unicode_anomaly_detected=False,
                        layer0_sync_hash=HASH64,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.DECLARATIVE]),
        )
        ctx = TaskContext(
            skill_type=SkillType.DECLARATIVE,
            ground_truth={"prompt_injection_ml_score": 0.75},
        )
        assert score_mu(sssa, ctx) == pytest.approx(0.95, abs=1e-3)

    def test_sigma_no_observed_returns_half(self):
        sssa = _python_sssa()
        ctx = TaskContext(skill_type=SkillType.EXECUTABLE_SCRIPT)
        assert score_sigma(sssa, ctx) == 0.5

    def test_psi_matches_truth_hash(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="m",
                bundle_hash="sha256:" + "e" * 64,
                skill_type=SkillType.MCP_SERVER,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    mcp_server=MCPServerEvidence(
                        tool_calls_hash=HASH64,
                        mcp_manifest_hash=HASH512,
                        tool_poisoning_score=0.0,
                        tool_shadowing_detected=False,
                        rug_pull_risk=False,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.MCP_SERVER]),
        )
        ctx_match = TaskContext(
            skill_type=SkillType.MCP_SERVER,
            ground_truth={"mcp_manifest_hash": HASH512},
        )
        ctx_no_match = TaskContext(
            skill_type=SkillType.MCP_SERVER,
            ground_truth={"mcp_manifest_hash": "sha512:" + "2" * 128},
        )
        assert score_psi(sssa, ctx_match) == 1.0
        assert score_psi(sssa, ctx_no_match) == 0.0

    def test_tau_recall_no_known(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="m",
                bundle_hash="sha256:" + "e" * 64,
                skill_type=SkillType.MCP_SERVER,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            findings=[],
            attestation=_attestation([SkillType.MCP_SERVER]),
        )
        ctx = TaskContext(skill_type=SkillType.MCP_SERVER, ground_truth={})
        assert score_tau(sssa, ctx) == 1.0

    def test_chi_full_credit_when_exact(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="a",
                bundle_hash="sha256:" + "f" * 64,
                skill_type=SkillType.AGENT_COMPOSITION,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    agent_composition=AgentCompositionEvidence(
                        agent_calls_hash=HASH64,
                        dependency_graph_hash=HASH64,
                        transitive_risk_score=0.7,
                        composition_depth_observed=2,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.AGENT_COMPOSITION]),
        )
        ctx = TaskContext(
            skill_type=SkillType.AGENT_COMPOSITION,
            ground_truth={"transitive_risk_score": 0.7},
        )
        assert score_chi(sssa, ctx) == pytest.approx(1.0)

    def test_rho_no_injections_low_score_full_credit(self):
        sssa = SSSAV04(
            skill=SkillIdentityV04(
                name="r",
                bundle_hash="sha256:" + "d" * 64,
                skill_type=SkillType.RAG_KNOWLEDGE,
                profile=TestProfile.STANDARD,
            ),
            verdict=VerdictBlockV04(decision=Verdict.ALLOW, risk_score=0, confidence=1.0),
            evidence=EvidencePackV04(
                type_specific=TypeSpecificEvidence(
                    rag_knowledge=RAGKnowledgeEvidence(
                        rag_content_fingerprint=HASH64,
                        hidden_instruction_score=0.05,
                        embedded_urls=[],
                        document_count=5,
                        canary_id_found=True,
                    ),
                ),
            ),
            attestation=_attestation([SkillType.RAG_KNOWLEDGE]),
        )
        ctx = TaskContext(skill_type=SkillType.RAG_KNOWLEDGE, ground_truth={})
        assert score_rho(sssa, ctx) == 1.0


class TestCompositeQ:
    def test_evidence_gate_zeroes(self):
        axes = AxesV04(alpha=1.0, epsilon=0.05, pi=1.0, eta=1.0)
        assert compute_Q(axes, SkillType.EXECUTABLE_PYTHON) == 0.0

    def test_python_perfect_axes_max_one(self):
        axes = AxesV04(alpha=1.0, epsilon=1.0, pi=1.0, eta=1.0)
        q = compute_Q(axes, SkillType.EXECUTABLE_PYTHON)
        assert q == pytest.approx(1.0)

    def test_rag_includes_rho(self):
        axes = AxesV04(alpha=1.0, epsilon=1.0, pi=1.0, eta=1.0, rho=1.0)
        q = compute_Q(axes, SkillType.RAG_KNOWLEDGE)
        assert q == pytest.approx(1.0)

    def test_declarative_includes_mu(self):
        axes = AxesV04(alpha=1.0, epsilon=1.0, pi=1.0, eta=1.0, mu=1.0)
        q = compute_Q(axes, SkillType.DECLARATIVE)
        assert q == pytest.approx(1.0)

    def test_mcp_includes_psi_and_tau(self):
        axes = AxesV04(alpha=1.0, epsilon=1.0, pi=1.0, eta=1.0, psi=1.0, tau=1.0)
        q = compute_Q(axes, SkillType.MCP_SERVER)
        assert q == pytest.approx(1.0)

    def test_agent_composition_includes_chi(self):
        axes = AxesV04(alpha=1.0, epsilon=1.0, pi=1.0, eta=1.0, chi=1.0)
        q = compute_Q(axes, SkillType.AGENT_COMPOSITION)
        assert q == pytest.approx(1.0)

    def test_evidence_scales_q_linearly(self):
        axes_high = AxesV04(alpha=1.0, epsilon=1.0, pi=1.0, eta=1.0)
        axes_low = AxesV04(alpha=1.0, epsilon=0.5, pi=1.0, eta=1.0)
        q_high = compute_Q(axes_high, SkillType.EXECUTABLE_PYTHON)
        q_low = compute_Q(axes_low, SkillType.EXECUTABLE_PYTHON)
        assert q_low == pytest.approx(q_high * 0.5)


class TestTierClassification:
    def test_below_reference(self):
        novel = {SkillType.EXECUTABLE_PYTHON: 0.9}
        assert classify_tier(0.10, SkillType.EXECUTABLE_PYTHON, novel) == Tier.BELOW_REFERENCE

    def test_tier_1(self):
        novel = {SkillType.EXECUTABLE_PYTHON: 0.9}
        assert classify_tier(0.55, SkillType.EXECUTABLE_PYTHON, novel) == Tier.TIER_1_REFERENCE

    def test_tier_2(self):
        novel = {SkillType.EXECUTABLE_PYTHON: 0.9}
        assert classify_tier(0.80, SkillType.EXECUTABLE_PYTHON, novel) == Tier.TIER_2_OPTIMISED

    def test_tier_3(self):
        novel = {SkillType.EXECUTABLE_PYTHON: 0.9}
        assert classify_tier(0.95, SkillType.EXECUTABLE_PYTHON, novel) == Tier.TIER_3_NOVEL


class TestEmissionsMatrix:
    def test_python_tier1_at_q_one_equals_one(self):
        score = compute_task_emissions_score(1.0, SkillType.EXECUTABLE_PYTHON, Tier.TIER_1_REFERENCE)
        assert score == pytest.approx(1.0)

    def test_agent_composition_tier3_at_q_one_equals_four(self):
        score = compute_task_emissions_score(1.0, SkillType.AGENT_COMPOSITION, Tier.TIER_3_NOVEL)
        assert score == pytest.approx(4.0)

    def test_rag_below_reference_at_q_one_equals_quarter(self):
        score = compute_task_emissions_score(1.0, SkillType.RAG_KNOWLEDGE, Tier.BELOW_REFERENCE)
        assert score == pytest.approx(0.25)

    def test_max_spread_is_16x(self):
        max_score = compute_task_emissions_score(1.0, SkillType.AGENT_COMPOSITION, Tier.TIER_3_NOVEL)
        min_score = compute_task_emissions_score(1.0, SkillType.RAG_KNOWLEDGE, Tier.BELOW_REFERENCE)
        assert max_score / min_score == pytest.approx(16.0)


class TestRecalibration:
    def test_keeps_current_when_few_scores(self):
        new = recalibrate_novel_threshold(SkillType.MCP_SERVER, [0.9, 0.8], 0.6)
        assert new == 0.6

    def test_floors_at_baseline_times_1_5(self):
        new = recalibrate_novel_threshold(
            SkillType.EXECUTABLE_PYTHON,
            [0.0, 0.0, 0.0, 0.0, 0.0],
            0.0,
        )
        assert new == pytest.approx(REFERENCE_BASELINES[SkillType.EXECUTABLE_PYTHON] * 1.5)

    def test_smoothed_blend(self):
        current = 0.7
        scores = [1.0, 1.0, 1.0, 1.0, 1.0]
        new = recalibrate_novel_threshold(SkillType.MCP_SERVER, scores, current)
        assert new == pytest.approx(0.30 * 1.0 + 0.70 * 0.7)


class TestScoreAllAxes:
    def test_routes_by_skill_type(self):
        sssa = _python_sssa(Verdict.ALLOW)
        ctx = TaskContext(
            skill_type=SkillType.EXECUTABLE_PYTHON,
            expected_verdict=Verdict.ALLOW,
            submission_latency_ms=30000,
            deadline_s=150,
            t_min_s=15,
            expected_evidence={"fs_trace_hash": HASH64, "imports_trace_hash": HASH64},
        )
        axes = score_all_axes(sssa, ctx)
        assert axes.alpha > 0
        assert axes.epsilon > 0
        assert axes.mu == 0.0
        assert axes.sigma == 0.0
        assert axes.psi == 0.0
        assert axes.rho == 0.0
        assert axes.chi == 0.0


class TestConstants:
    def test_base_weights_match_spec(self):
        assert BASE_WEIGHTS[SkillType.RAG_KNOWLEDGE] == 0.5
        assert BASE_WEIGHTS[SkillType.DECLARATIVE] == 0.7
        assert BASE_WEIGHTS[SkillType.EXECUTABLE_PYTHON] == 1.0
        assert BASE_WEIGHTS[SkillType.EXECUTABLE_SCRIPT] == 1.2
        assert BASE_WEIGHTS[SkillType.MCP_SERVER] == 1.6
        assert BASE_WEIGHTS[SkillType.AGENT_COMPOSITION] == 2.0

    def test_tier_multipliers_match_spec(self):
        assert TIER_MULTIPLIERS[Tier.BELOW_REFERENCE] == 0.5
        assert TIER_MULTIPLIERS[Tier.TIER_1_REFERENCE] == 1.0
        assert TIER_MULTIPLIERS[Tier.TIER_2_OPTIMISED] == 1.4
        assert TIER_MULTIPLIERS[Tier.TIER_3_NOVEL] == 2.0

    def test_evidence_gate(self):
        assert EVIDENCE_GATE == 0.10

    def test_schema_version(self):
        assert SCHEMA_VERSION_V04 == "0.4"
