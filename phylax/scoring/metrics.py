from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from statistics import median
from typing import Any

from phylax.protocol import SSSA, SkillType, Verdict

LAMBDA_FALSE_NEGATIVE = 1.0
LAMBDA_FALSE_POSITIVE = 0.4

EVIDENCE_GATE = 0.10

POLICY_BETA = 0.5

_PROVENANCE_WEIGHT_DEFAULTS = {
    "human": 1.0,
    "consensus": 0.7,
    "consensus_expired": 0.4,
}

_VERDICT_RANK = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}

BASE_WEIGHTS: dict[SkillType, float] = {
    SkillType.RAG_KNOWLEDGE: 0.5,
    SkillType.DECLARATIVE: 0.7,
    SkillType.EXECUTABLE_PYTHON: 1.0,
    SkillType.EXECUTABLE_SCRIPT: 1.2,
    SkillType.MCP_SERVER: 1.6,
    SkillType.AGENT_COMPOSITION: 2.0,
}

REFERENCE_BASELINES: dict[SkillType, float] = {
    SkillType.RAG_KNOWLEDGE: 0.35,
    SkillType.DECLARATIVE: 0.40,
    SkillType.EXECUTABLE_PYTHON: 0.50,
    SkillType.EXECUTABLE_SCRIPT: 0.48,
    SkillType.MCP_SERVER: 0.45,
    SkillType.AGENT_COMPOSITION: 0.40,
}


class Tier(str, Enum):
    BELOW_REFERENCE = "below_reference"
    TIER_1_REFERENCE = "tier_1_reference"
    TIER_2_OPTIMISED = "tier_2_optimised"
    TIER_3_NOVEL = "tier_3_novel"


TIER_MULTIPLIERS: dict[Tier, float] = {
    Tier.BELOW_REFERENCE: 0.5,
    Tier.TIER_1_REFERENCE: 1.0,
    Tier.TIER_2_OPTIMISED: 1.4,
    Tier.TIER_3_NOVEL: 2.0,
}


@dataclass
class Axes:
    alpha: float = 0.0
    epsilon: float = 0.0
    pi: float = 0.0
    eta: float = 0.0
    mu: float = 0.0
    sigma: float = 0.0
    psi: float = 0.0
    tau: float = 0.0
    chi: float = 0.0
    rho: float = 0.0


@dataclass
class TaskContext:
    skill_type: SkillType
    expected_verdict: Verdict | None = None
    expected_risk: int | None = None
    annotated_by: str | None = None
    expected_evidence: dict[str, Any] = field(default_factory=dict)
    expected_policy: dict[str, Any] = field(default_factory=dict)
    ground_truth: dict[str, Any] = field(default_factory=dict)
    submission_latency_ms: int | None = None
    deadline_s: int = 150
    t_min_s: int = 15
    median_latency_ms: int | None = None


def _clip01(x: float) -> float:
    if x != x:
        return 0.0
    return max(0.0, min(1.0, float(x)))


def _provenance_weight(ctx: TaskContext) -> float:
    if ctx.annotated_by is None:
        return 1.0
    w = _PROVENANCE_WEIGHT_DEFAULTS.get(ctx.annotated_by)
    if w is None:
        raise ValueError(f"unknown annotated_by={ctx.annotated_by!r}")
    return float(w)


def score_alpha(sssa: SSSA, ctx: TaskContext) -> float:
    if ctx.expected_verdict is None:
        return 0.0
    predicted = _VERDICT_RANK[sssa.verdict.decision]
    truth = _VERDICT_RANK[ctx.expected_verdict]
    distance = abs(predicted - truth)
    if distance == 0:
        base = 1.0
    elif predicted > truth:
        base = max(0.0, 1.0 - LAMBDA_FALSE_POSITIVE * distance / 2.0)
    else:
        base = max(0.0, 1.0 - LAMBDA_FALSE_NEGATIVE * distance / 2.0)
    if distance == 0 and ctx.expected_risk is not None:
        delta = abs(sssa.verdict.risk_score - ctx.expected_risk) / 100.0
        base *= max(0.9, 1.0 - 0.1 * delta)
    return _clip01(base * _provenance_weight(ctx))


def _rag_evidence_score(sssa: SSSA, ctx: TaskContext) -> float:
    block = sssa.evidence.type_specific.rag_knowledge
    if block is None or not block.rag_content_fingerprint:
        return 0.0
    truth_fp = ctx.ground_truth.get("rag_content_fingerprint")
    if truth_fp and block.rag_content_fingerprint != truth_fp:
        return 0.0
    if block.canary_id_found and block.hidden_instruction_score is not None:
        return 1.0
    if block.hidden_instruction_score is not None:
        return 0.5
    return 0.2


def _declarative_evidence_score(sssa: SSSA, ctx: TaskContext) -> float:
    block = sssa.evidence.type_specific.declarative
    if block is None or not block.canary_id_found:
        return 0.0
    score = 0.6
    if block.prompt_injection_ml_score is not None:
        score += 0.3
    if block.unicode_anomaly_detected is not None:
        score += 0.1
    return _clip01(score)


def _base_trace_matches(sssa: SSSA, ctx: TaskContext) -> float:
    miner = sssa.evidence.base
    truth = ctx.expected_evidence
    keys = ("network_trace_hash", "fs_trace_hash", "process_trace_hash", "secrets_trace_hash")
    matches = sum(1 for k in keys if getattr(miner, k) == truth.get(k))
    return matches / 4.0


def _executable_python_evidence_score(sssa: SSSA, ctx: TaskContext) -> float:
    truth = ctx.expected_evidence
    miner = sssa.evidence
    if truth.get("fs_trace_hash") and miner.base.fs_trace_hash != truth["fs_trace_hash"]:
        return 0.0
    base = _base_trace_matches(sssa, ctx)
    block = miner.type_specific.executable_python
    truth_imports = truth.get("imports_trace_hash")
    if block and truth_imports and block.imports_trace_hash == truth_imports:
        base = min(1.0, base + 0.2)
    return base


def _executable_script_evidence_score(sssa: SSSA, ctx: TaskContext) -> float:
    truth = ctx.expected_evidence
    miner = sssa.evidence
    if truth.get("fs_trace_hash") and miner.base.fs_trace_hash != truth["fs_trace_hash"]:
        return 0.0
    base = _base_trace_matches(sssa, ctx)
    block = miner.type_specific.executable_script
    truth_shell = truth.get("shell_commands_hash")
    if block and truth_shell and block.shell_commands_hash == truth_shell:
        base = min(1.0, base + 0.2)
    return base


def _mcp_server_evidence_score(sssa: SSSA, ctx: TaskContext) -> float:
    truth = ctx.expected_evidence
    block = sssa.evidence.type_specific.mcp_server
    if block is None:
        return 0.0
    if truth.get("tool_calls_hash") and block.tool_calls_hash != truth["tool_calls_hash"]:
        return 0.0
    if truth.get("mcp_manifest_hash") and block.mcp_manifest_hash != truth["mcp_manifest_hash"]:
        return 0.0
    base = _base_trace_matches(sssa, ctx)
    if block.tool_calls_hash and block.mcp_manifest_hash:
        base = min(1.0, base + 0.2)
    return base


def _agent_composition_evidence_score(sssa: SSSA, ctx: TaskContext) -> float:
    truth = ctx.expected_evidence
    block = sssa.evidence.type_specific.agent_composition
    if block is None:
        return 0.0
    if truth.get("agent_calls_hash") and block.agent_calls_hash != truth["agent_calls_hash"]:
        return 0.0
    base = _base_trace_matches(sssa, ctx)
    if (
        truth.get("dependency_graph_hash")
        and block.dependency_graph_hash == truth["dependency_graph_hash"]
    ):
        base = min(1.0, base + 0.2)
    return base


_EVIDENCE_FNS = {
    SkillType.RAG_KNOWLEDGE: _rag_evidence_score,
    SkillType.DECLARATIVE: _declarative_evidence_score,
    SkillType.EXECUTABLE_PYTHON: _executable_python_evidence_score,
    SkillType.EXECUTABLE_SCRIPT: _executable_script_evidence_score,
    SkillType.MCP_SERVER: _mcp_server_evidence_score,
    SkillType.AGENT_COMPOSITION: _agent_composition_evidence_score,
}


def score_epsilon(sssa: SSSA, ctx: TaskContext) -> float:
    fn = _EVIDENCE_FNS[ctx.skill_type]
    return _clip01(fn(sssa, ctx))


def _policy_constraint_set(policy: Any) -> set[tuple[str, str]]:
    if hasattr(policy, "model_dump"):
        p = policy.model_dump()
    elif isinstance(policy, dict):
        p = policy
    else:
        p = {}
    out: set[tuple[str, str]] = set()
    for d in p.get("egress_allow", []) or []:
        out.add(("egress", d))
    for d in p.get("egress_deny", []) or []:
        out.add(("deny_egress", d))
    for v in p.get("env_allowlist", []) or []:
        out.add(("env", v))
    for v in p.get("fs_read", []) or []:
        out.add(("fs_read", v))
    for v in p.get("fs_write", []) or []:
        out.add(("fs_write", v))
    for v in p.get("tool_allowlist", []) or []:
        out.add(("tool", v))
    for v in p.get("child_skill_allowlist", []) or []:
        out.add(("child_skill", v))
    out.add(("shell_access", str(bool(p.get("shell_access", False)))))
    return out


def _envelope_factor(actual: int, expected: int) -> float:
    if expected <= 0:
        return 1.0
    ratio = max(actual, 1) / expected
    if 0.5 <= ratio <= 2.0:
        return 1.0
    return max(0.0, 1.0 - abs(math.log2(ratio)) / 4.0)


def score_pi(sssa: SSSA, ctx: TaskContext) -> float:
    miner = _policy_constraint_set(sssa.recommended_policy)
    expected = _policy_constraint_set(ctx.expected_policy)
    if not miner and not expected:
        return 1.0
    if not miner or not expected:
        return 0.0
    intersection = len(miner & expected)
    precision = intersection / len(miner) if miner else 0.0
    recall = intersection / len(expected) if expected else 0.0
    if precision == 0.0 and recall == 0.0:
        f_beta = 0.0
    else:
        b2 = POLICY_BETA * POLICY_BETA
        f_beta = (1 + b2) * precision * recall / (b2 * precision + recall + 1e-9)
    mem_factor = _envelope_factor(
        sssa.recommended_policy.max_memory_mb,
        int(ctx.expected_policy.get("max_memory_mb", 256)),
    )
    to_factor = _envelope_factor(
        sssa.recommended_policy.timeout_s,
        int(ctx.expected_policy.get("timeout_s", 30)),
    )
    envelope_penalty = (mem_factor + to_factor) / 2.0
    return _clip01(f_beta * (0.8 + 0.2 * envelope_penalty))


def score_eta(sssa: SSSA, ctx: TaskContext) -> float:
    if ctx.submission_latency_ms is None:
        return 0.0
    completion = ctx.submission_latency_ms / 1000.0
    if completion < ctx.t_min_s:
        return 0.0
    if ctx.deadline_s <= ctx.t_min_s:
        return 0.6
    fraction = (completion - ctx.t_min_s) / (ctx.deadline_s - ctx.t_min_s)
    fraction = min(1.0, max(0.0, fraction))
    if fraction <= 0.25:
        eta = fraction / 0.25
    else:
        eta = 1.0 - 0.4 * ((fraction - 0.25) / 0.75)
    if not _has_minimum_evidence(sssa, ctx.skill_type):
        return 0.0
    return _clip01(eta)


def _has_minimum_evidence(sssa: SSSA, skill_type: SkillType) -> bool:
    ts = sssa.evidence.type_specific
    if skill_type == SkillType.RAG_KNOWLEDGE:
        return ts.rag_knowledge is not None and bool(ts.rag_knowledge.rag_content_fingerprint)
    if skill_type == SkillType.DECLARATIVE:
        return ts.declarative is not None and ts.declarative.canary_id_found
    if skill_type == SkillType.EXECUTABLE_PYTHON:
        return ts.executable_python is not None and bool(ts.executable_python.imports_trace_hash)
    if skill_type == SkillType.EXECUTABLE_SCRIPT:
        return ts.executable_script is not None and bool(ts.executable_script.shell_commands_hash)
    if skill_type == SkillType.MCP_SERVER:
        return ts.mcp_server is not None and bool(ts.mcp_server.tool_calls_hash)
    if skill_type == SkillType.AGENT_COMPOSITION:
        return ts.agent_composition is not None and bool(ts.agent_composition.agent_calls_hash)
    return False


def score_mu(sssa: SSSA, ctx: TaskContext) -> float:
    block = sssa.evidence.type_specific.declarative
    if block is None or block.prompt_injection_ml_score is None:
        return 0.0
    truth = ctx.ground_truth.get("prompt_injection_ml_score")
    if truth is None:
        return 0.0
    return _clip01(1.0 - abs(block.prompt_injection_ml_score - float(truth)))


def score_sigma(sssa: SSSA, ctx: TaskContext) -> float:
    observed = ctx.ground_truth.get("observed_shell_commands")
    if observed is None:
        return 0.5
    observed_set = set(observed)
    if not observed_set:
        return 0.5
    predicted = {str(f.title) for f in sssa.findings if f.finding_type.value == "static"}
    matches = len(predicted & observed_set)
    return _clip01(matches / len(observed_set))


def score_psi(sssa: SSSA, ctx: TaskContext) -> float:
    block = sssa.evidence.type_specific.mcp_server
    if block is None or not block.mcp_manifest_hash:
        return 0.0
    truth = ctx.ground_truth.get("mcp_manifest_hash")
    if truth is None:
        return 0.0
    return 1.0 if block.mcp_manifest_hash == truth else 0.0


def score_tau(sssa: SSSA, ctx: TaskContext) -> float:
    known = ctx.ground_truth.get("poisoned_tool_names")
    if not known:
        return 1.0
    known_set = set(known)
    flagged = {f.title for f in sssa.findings}
    if not known_set:
        return 1.0
    return _clip01(len(known_set & flagged) / len(known_set))


def score_chi(sssa: SSSA, ctx: TaskContext) -> float:
    block = sssa.evidence.type_specific.agent_composition
    if block is None:
        return 0.0
    truth = ctx.ground_truth.get("transitive_risk_score")
    if truth is None:
        return 0.0
    error = abs(float(truth) - block.transitive_risk_score)
    return _clip01(1.0 - error * 2.0)


def score_rho(sssa: SSSA, ctx: TaskContext) -> float:
    block = sssa.evidence.type_specific.rag_knowledge
    if block is None:
        return 0.0
    miner_score = block.hidden_instruction_score
    known = ctx.ground_truth.get("hidden_instruction_locations")
    document_count = ctx.ground_truth.get("document_count", block.document_count)
    if not known:
        return 1.0 if miner_score < 0.3 else 0.8
    if document_count <= 0:
        return 0.0
    expected = len(known) / float(document_count)
    error = abs(miner_score - expected)
    return _clip01(1.0 - error * 3.0)


def score_all_axes(sssa: SSSA, ctx: TaskContext) -> Axes:
    axes = Axes(
        alpha=score_alpha(sssa, ctx),
        epsilon=score_epsilon(sssa, ctx),
        pi=score_pi(sssa, ctx),
        eta=score_eta(sssa, ctx),
    )
    if ctx.skill_type == SkillType.RAG_KNOWLEDGE:
        axes.rho = score_rho(sssa, ctx)
    elif ctx.skill_type == SkillType.DECLARATIVE:
        axes.mu = score_mu(sssa, ctx)
    elif ctx.skill_type == SkillType.EXECUTABLE_SCRIPT:
        axes.sigma = score_sigma(sssa, ctx)
    elif ctx.skill_type == SkillType.MCP_SERVER:
        axes.psi = score_psi(sssa, ctx)
        axes.tau = score_tau(sssa, ctx)
    elif ctx.skill_type == SkillType.AGENT_COMPOSITION:
        axes.chi = score_chi(sssa, ctx)
    return axes


def compute_Q(axes: Axes, skill_type: SkillType) -> float:
    if axes.epsilon < EVIDENCE_GATE:
        return 0.0
    if skill_type == SkillType.RAG_KNOWLEDGE:
        non_evidence = 0.45 * axes.alpha + 0.20 * axes.pi + 0.05 * axes.eta + 0.15 * axes.rho
        divisor = 0.85
    elif skill_type == SkillType.DECLARATIVE:
        non_evidence = 0.45 * axes.alpha + 0.20 * axes.pi + 0.05 * axes.eta + 0.10 * axes.mu
        divisor = 0.80
    elif skill_type == SkillType.EXECUTABLE_PYTHON:
        non_evidence = 0.45 * axes.alpha + 0.20 * axes.pi + 0.05 * axes.eta
        divisor = 0.70
    elif skill_type == SkillType.EXECUTABLE_SCRIPT:
        non_evidence = 0.40 * axes.alpha + 0.20 * axes.pi + 0.05 * axes.eta + 0.10 * axes.sigma
        divisor = 0.75
    elif skill_type == SkillType.MCP_SERVER:
        non_evidence = (
            0.35 * axes.alpha + 0.15 * axes.pi + 0.05 * axes.eta + 0.10 * axes.psi + 0.10 * axes.tau
        )
        divisor = 0.75
    elif skill_type == SkillType.AGENT_COMPOSITION:
        non_evidence = 0.35 * axes.alpha + 0.15 * axes.pi + 0.05 * axes.eta + 0.10 * axes.chi
        divisor = 0.65
    else:
        return 0.0
    return _clip01((non_evidence / divisor) * axes.epsilon)


def classify_tier(
    composite_q: float,
    skill_type: SkillType,
    novel_thresholds: dict[SkillType, float],
) -> Tier:
    baseline = REFERENCE_BASELINES[skill_type]
    novel = novel_thresholds.get(skill_type, baseline * 1.5)
    if composite_q < baseline:
        return Tier.BELOW_REFERENCE
    if composite_q < novel * 0.75:
        return Tier.TIER_1_REFERENCE
    if composite_q < novel:
        return Tier.TIER_2_OPTIMISED
    return Tier.TIER_3_NOVEL


def compute_task_emissions_score(
    composite_q: float,
    skill_type: SkillType,
    tier: Tier,
) -> float:
    return composite_q * BASE_WEIGHTS[skill_type] * TIER_MULTIPLIERS[tier]


def recalibrate_novel_threshold(
    skill_type: SkillType,
    epoch_q_scores: list[float],
    current_threshold: float,
) -> float:
    if len(epoch_q_scores) < 3:
        return current_threshold
    top = sorted(epoch_q_scores, reverse=True)[: min(5, len(epoch_q_scores))]
    new_threshold = float(median(top))
    smoothed = 0.30 * new_threshold + 0.70 * current_threshold
    floor = REFERENCE_BASELINES[skill_type] * 1.5
    return max(smoothed, floor)
