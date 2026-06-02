from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from phylax.protocol import SkillType, TaskType, TestProfile
from phylax.validator.canary import (
    build_minimal_agent_composition_bundle,
    build_minimal_declarative_bundle,
    build_minimal_executable_python_bundle,
    build_minimal_executable_script_bundle,
    build_minimal_mcp_bundle,
    build_minimal_rag_bundle,
)

LEGACY_SKILL_TYPE_MAP: dict[str, str] = {
    "executable": "executable_python",
    "mixed": "executable_python",
}

VALID_SKILL_TYPES: set[str] = {t.value for t in SkillType}

CORPUS_FALLBACK_ORDER: dict[SkillType, tuple[SkillType, ...]] = {
    SkillType.AGENT_COMPOSITION: (
        SkillType.MCP_SERVER, SkillType.EXECUTABLE_PYTHON, SkillType.EXECUTABLE_SCRIPT,
    ),
    SkillType.MCP_SERVER: (
        SkillType.EXECUTABLE_PYTHON, SkillType.EXECUTABLE_SCRIPT, SkillType.DECLARATIVE,
    ),
    SkillType.EXECUTABLE_SCRIPT: (
        SkillType.EXECUTABLE_PYTHON, SkillType.DECLARATIVE,
    ),
    SkillType.EXECUTABLE_PYTHON: (
        SkillType.EXECUTABLE_SCRIPT, SkillType.DECLARATIVE,
    ),
    SkillType.DECLARATIVE: (SkillType.RAG_KNOWLEDGE,),
    SkillType.RAG_KNOWLEDGE: (),
}

ROUND_COMPOSITION: dict[SkillType, tuple[TaskType, ...]] = {
    SkillType.RAG_KNOWLEDGE: (TaskType.SERVER_CURATED, TaskType.LOCAL_SYNTH),
    SkillType.DECLARATIVE: (TaskType.SERVER_CURATED, TaskType.CANARY),
    SkillType.EXECUTABLE_PYTHON: (TaskType.SERVER_CURATED, TaskType.LOCAL_SYNTH),
    SkillType.EXECUTABLE_SCRIPT: (TaskType.SERVER_CURATED, TaskType.LOCAL_SYNTH),
    SkillType.MCP_SERVER: (TaskType.SERVER_CURATED, TaskType.CANARY),
    SkillType.AGENT_COMPOSITION: (TaskType.SERVER_CURATED, TaskType.LOCAL_SYNTH),
}


@dataclass
class RoundTask:
    task_id: str
    skill_type: SkillType
    task_type: TaskType
    profile: TestProfile
    bundle_hash: str
    bundle_bytes: bytes | None = None
    bundle_url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    expected_verdict: str = "ALLOW"
    expected_risk_score: int | None = None
    expected_policy: dict[str, Any] = field(default_factory=dict)
    ground_truth: dict[str, Any] = field(default_factory=dict)
    ground_truth_evidence: dict[str, Any] = field(default_factory=dict)
    annotated_by: str | None = None
    is_bounty: bool = False


def normalise_skill_type_str(raw: str | None) -> str | None:
    if raw is None:
        return None
    return LEGACY_SKILL_TYPE_MAP.get(raw, raw)


def generate_canary_task(skill_type: SkillType) -> RoundTask:
    if skill_type == SkillType.DECLARATIVE:
        nonce = secrets.token_hex(16)
        injection = build_minimal_declarative_bundle(nonce)
        metadata = {
            "skill_name": "canary_declarative",
            "skill_version": "1.0.0",
            "skill_type": skill_type.value,
            "profile": TestProfile.STANDARD.value,
            "nonce": nonce,
        }
        return RoundTask(
            task_id=str(uuid.uuid4()),
            skill_type=skill_type,
            task_type=TaskType.CANARY,
            profile=TestProfile.STANDARD,
            bundle_hash=injection.bundle_hash,
            bundle_bytes=injection.bundle_bytes,
            metadata=metadata,
            expected_verdict="ALLOW",
            ground_truth=injection.ground_truth,
            annotated_by="canary",
        )
    if skill_type == SkillType.MCP_SERVER:
        nonce = secrets.token_hex(16)
        injection = build_minimal_mcp_bundle(nonce)
        metadata = {
            "skill_name": "canary_mcp",
            "skill_version": "1.0.0",
            "skill_type": skill_type.value,
            "profile": TestProfile.STANDARD.value,
            "nonce": nonce,
        }
        return RoundTask(
            task_id=str(uuid.uuid4()),
            skill_type=skill_type,
            task_type=TaskType.CANARY,
            profile=TestProfile.STANDARD,
            bundle_hash=injection.bundle_hash,
            bundle_bytes=injection.bundle_bytes,
            metadata=metadata,
            expected_verdict="ALLOW",
            ground_truth=injection.ground_truth,
            annotated_by="canary",
        )
    raise ValueError(f"no canary generator for skill_type={skill_type.value}")


_SYNTH_BUILDERS = {
    SkillType.RAG_KNOWLEDGE: ("synth_rag", build_minimal_rag_bundle),
    SkillType.DECLARATIVE: ("synth_declarative", build_minimal_declarative_bundle),
    SkillType.EXECUTABLE_PYTHON: ("synth_executable_python", build_minimal_executable_python_bundle),
    SkillType.EXECUTABLE_SCRIPT: ("synth_executable_script", build_minimal_executable_script_bundle),
    SkillType.MCP_SERVER: ("synth_mcp_server", build_minimal_mcp_bundle),
    SkillType.AGENT_COMPOSITION: ("synth_agent_composition", build_minimal_agent_composition_bundle),
}


def generate_local_synth_task(skill_type: SkillType) -> RoundTask | None:
    entry = _SYNTH_BUILDERS.get(skill_type)
    if entry is None:
        return None
    skill_name, builder = entry
    nonce = secrets.token_hex(16)
    injection = builder(nonce)
    metadata = {
        "skill_name": skill_name,
        "skill_version": "1.0.0",
        "skill_type": skill_type.value,
        "profile": TestProfile.STANDARD.value,
        "nonce": nonce,
    }
    if skill_type == SkillType.AGENT_COMPOSITION:
        metadata["composition_depth"] = 1
    return RoundTask(
        task_id=str(uuid.uuid4()),
        skill_type=skill_type,
        task_type=TaskType.LOCAL_SYNTH,
        profile=TestProfile.STANDARD,
        bundle_hash=injection.bundle_hash,
        bundle_bytes=injection.bundle_bytes,
        metadata=metadata,
        expected_verdict="ALLOW",
        ground_truth=injection.ground_truth,
        annotated_by="consensus",
    )


def task_from_server_dict(raw: dict) -> RoundTask | None:
    raw_type = raw.get("skill_type") or (raw.get("metadata") or {}).get("skill_type")
    normalised = normalise_skill_type_str(raw_type)
    if normalised not in VALID_SKILL_TYPES:
        return None
    skill_type = SkillType(normalised)
    metadata = dict(raw.get("metadata") or {})
    metadata.setdefault("skill_type", skill_type.value)
    profile_str = (metadata.get("profile") or raw.get("test_profile") or "standard").lower()
    try:
        profile = TestProfile(profile_str)
    except ValueError:
        profile = TestProfile.STANDARD
    bundle_bytes = None
    bundle_b64 = raw.get("bundle_bytes_b64") or raw.get("bundle_bytes")
    if bundle_b64:
        import base64
        try:
            bundle_bytes = base64.b64decode(bundle_b64) if isinstance(bundle_b64, str) else bytes(bundle_b64)
        except Exception:  # noqa: BLE001
            bundle_bytes = None
    task_type_str = raw.get("task_type") or "server_curated"
    try:
        task_type = TaskType(task_type_str)
    except ValueError:
        task_type = TaskType.SERVER_CURATED
    return RoundTask(
        task_id=raw.get("task_id") or raw.get("bundle_hash") or str(uuid.uuid4()),
        skill_type=skill_type,
        task_type=task_type,
        profile=profile,
        bundle_hash=raw["bundle_hash"],
        bundle_bytes=bundle_bytes,
        bundle_url=raw.get("bundle_url"),
        metadata=metadata,
        expected_verdict=raw.get("expected_verdict") or "ALLOW",
        expected_risk_score=raw.get("expected_risk_score"),
        expected_policy=raw.get("expected_policy") or {},
        ground_truth=raw.get("ground_truth") or {},
        ground_truth_evidence=raw.get("ground_truth_evidence") or {},
        annotated_by=raw.get("annotated_by") or metadata.get("annotated_by") or "human",
        is_bounty=bool(raw.get("is_bounty") or metadata.get("is_bounty") or False),
    )


def compose_round(server_tasks: list[dict]) -> list[RoundTask]:
    by_type: dict[SkillType, list[RoundTask]] = {st: [] for st in ROUND_COMPOSITION}
    for raw in server_tasks:
        task = task_from_server_dict(raw)
        if task is None:
            continue
        if task.task_type != TaskType.SERVER_CURATED:
            continue
        by_type[task.skill_type].append(task)

    out: list[RoundTask] = []
    for skill_type, slots in ROUND_COMPOSITION.items():
        pool = by_type.get(skill_type, [])
        for slot_type in slots:
            if slot_type == TaskType.SERVER_CURATED:
                if pool:
                    out.append(pool.pop(0))
                else:
                    fallback = _fallback_for(skill_type, by_type)
                    if fallback is not None:
                        out.append(fallback)
                continue
            if slot_type == TaskType.CANARY:
                out.append(generate_canary_task(skill_type))
                continue
            if slot_type == TaskType.LOCAL_SYNTH:
                synth = generate_local_synth_task(skill_type)
                if synth is not None:
                    out.append(synth)
                elif pool:
                    repurposed = pool.pop(0)
                    repurposed.task_type = TaskType.LOCAL_SYNTH
                    out.append(repurposed)
                continue
    return out


def _fallback_for(
    skill_type: SkillType, by_type: dict[SkillType, list[RoundTask]]
) -> RoundTask | None:
    for fallback in CORPUS_FALLBACK_ORDER.get(skill_type, ()):
        pool = by_type.get(fallback, [])
        if pool:
            task = pool.pop(0)
            return task
    return None
