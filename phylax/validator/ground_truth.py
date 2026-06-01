from __future__ import annotations

import hashlib
import secrets
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from phylax.harness import (
    AgentCompositionHarness,
    ExecutablePythonHarness,
    ExecutableScriptHarness,
    MCPServerHarness,
)
from phylax.protocol import SkillType
from phylax.validator.canary import (
    CanaryInjection,
    _derive_canary_pair,
    inject_declarative_canary,
    inject_rag_canary,
)


@dataclass
class BundlePreparation:
    bundle_bytes: bytes
    bundle_hash: str
    nonce: str
    canary_id: str
    canary_val: str
    ground_truth: dict[str, Any] = field(default_factory=dict)


def _new_nonce() -> str:
    return secrets.token_hex(16)


def _materialise(bundle_bytes: bytes) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="phylax-gt-"))
    if not bundle_bytes:
        return tmp
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(bundle_bytes)) as zf:
            zf.extractall(tmp)
    except zipfile.BadZipFile:
        (tmp / "skill.bin").write_bytes(bundle_bytes)
    return tmp


def _hash_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def prepare_rag(bundle_bytes: bytes, nonce: str | None = None) -> BundlePreparation:
    nonce = nonce or _new_nonce()
    cid, cval = _derive_canary_pair(nonce)
    injection: CanaryInjection = inject_rag_canary(bundle_bytes, nonce)
    return BundlePreparation(
        bundle_bytes=injection.bundle_bytes,
        bundle_hash=injection.bundle_hash,
        nonce=nonce,
        canary_id=cid,
        canary_val=cval,
        ground_truth=injection.ground_truth,
    )


def prepare_declarative(bundle_bytes: bytes, nonce: str | None = None) -> BundlePreparation:
    nonce = nonce or _new_nonce()
    cid, cval = _derive_canary_pair(nonce)
    injection: CanaryInjection = inject_declarative_canary(bundle_bytes, nonce)
    return BundlePreparation(
        bundle_bytes=injection.bundle_bytes,
        bundle_hash=injection.bundle_hash,
        nonce=nonce,
        canary_id=cid,
        canary_val=cval,
        ground_truth=injection.ground_truth,
    )


def prepare_executable_python(bundle_bytes: bytes, nonce: str | None = None) -> BundlePreparation:
    nonce = nonce or _new_nonce()
    cid, cval = _derive_canary_pair(nonce)
    bundle_dir = _materialise(bundle_bytes)
    harness = ExecutablePythonHarness()
    result = harness.run(bundle_dir, nonce=nonce, canary_id=cid, canary_val=cval)
    base = result.base_evidence
    type_ev = result.evidence
    return BundlePreparation(
        bundle_bytes=bundle_bytes,
        bundle_hash="sha256:" + hashlib.sha256(bundle_bytes or b"").hexdigest(),
        nonce=nonce,
        canary_id=cid,
        canary_val=cval,
        ground_truth={
            "canary_id": cid,
            "canary_val": cval,
            "network_trace_hash": base.network_trace_hash,
            "fs_trace_hash": base.fs_trace_hash,
            "process_trace_hash": base.process_trace_hash,
            "secrets_trace_hash": base.secrets_trace_hash,
            "imports_trace_hash": getattr(type_ev, "imports_trace_hash", None),
        },
    )


def prepare_executable_script(bundle_bytes: bytes, nonce: str | None = None) -> BundlePreparation:
    nonce = nonce or _new_nonce()
    cid, cval = _derive_canary_pair(nonce)
    bundle_dir = _materialise(bundle_bytes)
    harness = ExecutableScriptHarness()
    result = harness.run(bundle_dir, nonce=nonce, canary_id=cid, canary_val=cval)
    base = result.base_evidence
    type_ev = result.evidence
    return BundlePreparation(
        bundle_bytes=bundle_bytes,
        bundle_hash="sha256:" + hashlib.sha256(bundle_bytes or b"").hexdigest(),
        nonce=nonce,
        canary_id=cid,
        canary_val=cval,
        ground_truth={
            "canary_id": cid,
            "canary_val": cval,
            "network_trace_hash": base.network_trace_hash,
            "fs_trace_hash": base.fs_trace_hash,
            "process_trace_hash": base.process_trace_hash,
            "secrets_trace_hash": base.secrets_trace_hash,
            "shell_commands_hash": getattr(type_ev, "shell_commands_hash", None),
        },
    )


def prepare_mcp_server(bundle_bytes: bytes, nonce: str | None = None) -> BundlePreparation:
    nonce = nonce or _new_nonce()
    cid, cval = _derive_canary_pair(nonce)
    bundle_dir = _materialise(bundle_bytes)
    harness = MCPServerHarness()
    result = harness.run(bundle_dir, nonce=nonce, canary_id=cid, canary_val=cval)
    base = result.base_evidence
    type_ev = result.evidence
    return BundlePreparation(
        bundle_bytes=bundle_bytes,
        bundle_hash="sha256:" + hashlib.sha256(bundle_bytes or b"").hexdigest(),
        nonce=nonce,
        canary_id=cid,
        canary_val=cval,
        ground_truth={
            "canary_id": cid,
            "canary_val": cval,
            "network_trace_hash": base.network_trace_hash,
            "fs_trace_hash": base.fs_trace_hash,
            "process_trace_hash": base.process_trace_hash,
            "secrets_trace_hash": base.secrets_trace_hash,
            "tool_calls_hash": getattr(type_ev, "tool_calls_hash", None),
            "mcp_manifest_hash": getattr(type_ev, "mcp_manifest_hash", None),
        },
    )


def prepare_agent_composition(
    bundle_bytes: bytes, nonce: str | None = None, composition_depth: int = 5
) -> BundlePreparation:
    nonce = nonce or _new_nonce()
    cid, cval = _derive_canary_pair(nonce)
    bundle_dir = _materialise(bundle_bytes)
    harness = AgentCompositionHarness()
    result = harness.run(
        bundle_dir, nonce=nonce, canary_id=cid, canary_val=cval,
        composition_depth=composition_depth,
    )
    base = result.base_evidence
    type_ev = result.evidence
    return BundlePreparation(
        bundle_bytes=bundle_bytes,
        bundle_hash="sha256:" + hashlib.sha256(bundle_bytes or b"").hexdigest(),
        nonce=nonce,
        canary_id=cid,
        canary_val=cval,
        ground_truth={
            "canary_id": cid,
            "canary_val": cval,
            "network_trace_hash": base.network_trace_hash,
            "fs_trace_hash": base.fs_trace_hash,
            "process_trace_hash": base.process_trace_hash,
            "secrets_trace_hash": base.secrets_trace_hash,
            "agent_calls_hash": getattr(type_ev, "agent_calls_hash", None),
            "dependency_graph_hash": getattr(type_ev, "dependency_graph_hash", None),
            "transitive_risk_score": getattr(type_ev, "transitive_risk_score", None),
        },
    )


_PREPARERS = {
    SkillType.RAG_KNOWLEDGE: prepare_rag,
    SkillType.DECLARATIVE: prepare_declarative,
    SkillType.EXECUTABLE_PYTHON: prepare_executable_python,
    SkillType.EXECUTABLE_SCRIPT: prepare_executable_script,
    SkillType.MCP_SERVER: prepare_mcp_server,
    SkillType.AGENT_COMPOSITION: prepare_agent_composition,
}


def prepare_bundle(
    skill_type: SkillType,
    bundle_bytes: bytes,
    nonce: str | None = None,
    composition_depth: int = 5,
) -> BundlePreparation:
    if skill_type == SkillType.AGENT_COMPOSITION:
        return prepare_agent_composition(bundle_bytes, nonce, composition_depth)
    fn = _PREPARERS[skill_type]
    return fn(bundle_bytes, nonce)
