from __future__ import annotations

import base64
import gzip
import json
from dataclasses import dataclass, field

from phylax.harness.probe_spec import (
    ProbeSpec,
    derive_probe,
    verify_probe_evidence,
    verify_probe_in_traces,
)
from phylax.harness.trace_normalisation import hash_jsonl_bytes
from phylax.protocol import REQUIRED_TRACE_FILES, SkillType

_MAX_FILE_SIZES: dict[str, int] = {
    "network.jsonl.gz": 5 * 1024 * 1024,
    "fs.jsonl.gz": 10 * 1024 * 1024,
    "process.jsonl.gz": 5 * 1024 * 1024,
    "secrets.jsonl.gz": 1 * 1024 * 1024,
    "imports.jsonl.gz": 2 * 1024 * 1024,
    "shell_commands.jsonl.gz": 5 * 1024 * 1024,
    "tool_calls.jsonl.gz": 5 * 1024 * 1024,
    "agent_calls.jsonl.gz": 10 * 1024 * 1024,
}

MAX_TOTAL_BUNDLE_SIZE = 30 * 1024 * 1024

REQUIRED_MANIFEST_KEYS = ("image", "digest", "tracer_version")

CANARY_PATH = "/skill/.canary"

_BASE_FILES = ("network.jsonl.gz", "fs.jsonl.gz", "process.jsonl.gz", "secrets.jsonl.gz")
_BASE_HASH_FIELDS = {
    "network.jsonl.gz": "network_trace_hash",
    "fs.jsonl.gz": "fs_trace_hash",
    "process.jsonl.gz": "process_trace_hash",
    "secrets.jsonl.gz": "secrets_trace_hash",
}
_TYPE_SPECIFIC_HASH_FIELD: dict[SkillType, tuple[str, str]] = {
    SkillType.EXECUTABLE_PYTHON: ("imports.jsonl.gz", "imports_trace_hash"),
    SkillType.EXECUTABLE_SCRIPT: ("shell_commands.jsonl.gz", "shell_commands_hash"),
    SkillType.MCP_SERVER: ("tool_calls.jsonl.gz", "tool_calls_hash"),
    SkillType.AGENT_COMPOSITION: ("agent_calls.jsonl.gz", "agent_calls_hash"),
}


@dataclass
class TraceVerification:
    passed: bool
    reason: str = ""
    semantic_subset: float = 1.0
    depth_ratio: float = 1.0
    decoded_records: dict[str, list[dict]] = field(default_factory=dict)


def _decode(gz_b64: str) -> bytes | None:
    try:
        compressed = base64.b64decode(gz_b64.encode("ascii"), validate=True)
    except Exception:  # noqa: BLE001
        return None
    try:
        return gzip.decompress(compressed)
    except Exception:  # noqa: BLE001
        return None


def _parse_records(raw: bytes) -> list[dict]:
    out: list[dict] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                out.append(obj)
        except (ValueError, TypeError):
            continue
    return out


def _signatures_for(filename: str, records: list[dict]) -> set[tuple]:
    sigs: set[tuple] = set()
    if filename == "network.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("dst_ip", "")), int(r.get("dst_port", 0) or 0), str(r.get("proto", ""))))
    elif filename == "fs.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("op", "")), str(r.get("path", ""))))
    elif filename == "process.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("cmd", "")),))
    elif filename == "secrets.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("type", "")), str(r.get("pattern_matched", ""))))
    elif filename == "imports.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("module", "")),))
    elif filename == "shell_commands.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("cmd", "")),))
    elif filename == "tool_calls.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("tool_name", "")),))
    elif filename == "agent_calls.jsonl.gz":
        for r in records:
            sigs.add((str(r.get("caller_skill", "")), str(r.get("callee_skill", ""))))
    return sigs


def verify_probe(
    nonce: str,
    probe_evidence: dict | None,
    fs_records: list[dict] | None = None,
    network_records: list[dict] | None = None,
    process_records: list[dict] | None = None,
    runtime_type: bool = False,
) -> tuple[bool, str, ProbeSpec]:
    probe = derive_probe(nonce)
    ok, reason = verify_probe_evidence(probe_evidence, probe)
    if not ok:
        return False, reason, probe
    if runtime_type:
        ok, reason = verify_probe_in_traces(
            fs_records, network_records, process_records, probe,
        )
        if not ok:
            return False, reason, probe
    return True, "", probe


def verify_trace_bundle(
    skill_type: SkillType,
    trace_bundle_b64: dict[str, str] | None,
    sandbox_manifest: dict | None,
    submitted_evidence_hashes: dict[str, str | None],
    reference_records: dict[str, list[dict]],
) -> TraceVerification:
    required = REQUIRED_TRACE_FILES.get(skill_type, ())
    if not required:
        return TraceVerification(passed=True, reason="non-runtime type")

    if not sandbox_manifest or not isinstance(sandbox_manifest, dict):
        return TraceVerification(passed=False, reason="missing sandbox_manifest")
    for key in REQUIRED_MANIFEST_KEYS:
        if not sandbox_manifest.get(key):
            return TraceVerification(passed=False, reason=f"sandbox_manifest missing {key}")

    if not trace_bundle_b64 or not isinstance(trace_bundle_b64, dict):
        return TraceVerification(passed=False, reason="missing trace_bundle")

    total_compressed = 0
    for fname in required:
        gz_b64 = trace_bundle_b64.get(fname)
        if not gz_b64:
            return TraceVerification(passed=False, reason=f"trace bundle missing {fname}")
        try:
            compressed_len = (len(gz_b64) * 3) // 4
        except Exception:  # noqa: BLE001
            return TraceVerification(passed=False, reason=f"invalid base64 in {fname}")
        if compressed_len > _MAX_FILE_SIZES.get(fname, MAX_TOTAL_BUNDLE_SIZE):
            return TraceVerification(passed=False, reason=f"{fname} exceeds per-file cap")
        total_compressed += compressed_len
    if total_compressed > MAX_TOTAL_BUNDLE_SIZE:
        return TraceVerification(passed=False, reason="trace bundle exceeds total cap")

    decoded_records: dict[str, list[dict]] = {}
    for fname in required:
        raw = _decode(trace_bundle_b64[fname])
        if raw is None:
            return TraceVerification(passed=False, reason=f"{fname} decode failed")
        if not raw.strip():
            return TraceVerification(passed=False, reason=f"{fname} is empty after decode")
        computed = hash_jsonl_bytes(raw)
        if fname in _BASE_HASH_FIELDS:
            claimed = submitted_evidence_hashes.get(_BASE_HASH_FIELDS[fname])
        else:
            claimed_key = _TYPE_SPECIFIC_HASH_FIELD.get(skill_type, ("", ""))[1]
            claimed = submitted_evidence_hashes.get(claimed_key) if claimed_key else None
        if claimed != computed:
            return TraceVerification(
                passed=False,
                reason=f"{fname} hash mismatch (submitted={claimed}, computed={computed})",
            )
        decoded_records[fname] = _parse_records(raw)

    fs_records = decoded_records.get("fs.jsonl.gz", [])
    canary_seen = any(str(r.get("path", "")) == CANARY_PATH for r in fs_records)
    if not canary_seen:
        return TraceVerification(
            passed=False, reason=f"canary path {CANARY_PATH} not present in fs.jsonl",
        )

    subset_scores: list[float] = []
    for fname in _BASE_FILES:
        if fname not in decoded_records:
            continue
        miner_sigs = _signatures_for(fname, decoded_records[fname])
        ref_sigs = _signatures_for(fname, reference_records.get(fname, []))
        if not ref_sigs:
            subset_scores.append(1.0)
            continue
        present = len(ref_sigs & miner_sigs)
        subset_scores.append(present / len(ref_sigs))
    semantic_subset = sum(subset_scores) / len(subset_scores) if subset_scores else 1.0

    miner_event_total = sum(len(decoded_records[f]) for f in decoded_records)
    ref_event_total = sum(len(reference_records.get(f, [])) for f in required)
    if ref_event_total > 0:
        depth_ratio = miner_event_total / ref_event_total
    else:
        depth_ratio = 1.0 if miner_event_total > 0 else 0.0

    return TraceVerification(
        passed=True,
        semantic_subset=max(0.0, min(1.0, semantic_subset)),
        depth_ratio=max(0.0, min(3.0, depth_ratio)),
        decoded_records=decoded_records,
    )
