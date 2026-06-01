from __future__ import annotations

import hashlib
import io
import json
import random
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

_RAG_EXTENSIONS = {".md", ".markdown", ".txt", ".rst", ".html", ".htm", ".pdf"}
_DECLARATIVE_SKILL_NAMES = ("SKILL.md", "skill.md", "SKILL.markdown", "skill.markdown")


@dataclass
class CanaryInjection:
    bundle_bytes: bytes
    bundle_hash: str
    ground_truth: dict[str, Any] = field(default_factory=dict)


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _bundle_hash(b: bytes) -> str:
    return "sha256:" + _sha256_hex(b)


def _is_zip(bundle_bytes: bytes) -> bool:
    if not bundle_bytes or len(bundle_bytes) < 4:
        return False
    return bundle_bytes[:4] == b"PK\x03\x04" or bundle_bytes[:4] == b"PK\x05\x06"


def _canary_marker(canary_id: str) -> str:
    return f"CANARY_{canary_id}"


def _derive_canary_pair(nonce: str) -> tuple[str, str]:
    cid = hashlib.sha256((nonce + "id").encode()).hexdigest()[:16]
    cval = hashlib.sha256((nonce + "val").encode()).hexdigest()[:16]
    return cid, cval


def _read_zip_members(bundle_bytes: bytes) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            members[info.filename] = zf.read(info.filename)
    return members


def _write_zip_members(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(members):
            zf.writestr(name, members[name])
    return buf.getvalue()


def inject_rag_canary(bundle_bytes: bytes, nonce: str) -> CanaryInjection:
    canary_id, _ = _derive_canary_pair(nonce)
    marker = _canary_marker(canary_id)

    if not _is_zip(bundle_bytes):
        appended = (bundle_bytes or b"") + b"\n" + marker.encode("utf-8") + b"\n"
        doc_hash = _sha256_hex(appended)
        fingerprint = _sha256_hex(doc_hash.encode("ascii"))
        return CanaryInjection(
            bundle_bytes=appended,
            bundle_hash=_bundle_hash(appended),
            ground_truth={
                "rag_content_fingerprint": fingerprint,
                "canary_id": canary_id,
                "canary_marker": marker,
                "canary_document": "bundle",
                "document_count": 1,
                "doc_hashes": {"bundle": doc_hash},
            },
        )

    members = _read_zip_members(bundle_bytes)
    docs = sorted(
        name for name in members
        if any(name.lower().endswith(ext) for ext in _RAG_EXTENSIONS)
    ) or sorted(members)
    if not docs:
        return CanaryInjection(
            bundle_bytes=bundle_bytes,
            bundle_hash=_bundle_hash(bundle_bytes),
            ground_truth={
                "rag_content_fingerprint": "",
                "canary_id": canary_id,
                "canary_marker": marker,
                "document_count": 0,
                "doc_hashes": {},
            },
        )
    rng = random.Random(nonce)
    target = rng.choice(docs)
    members[target] = members[target] + b"\n" + marker.encode("utf-8") + b"\n"
    new_bundle = _write_zip_members(members)
    doc_hashes = {name: _sha256_hex(members[name]) for name in sorted(members)}
    fingerprint = _sha256_hex(
        "".join(doc_hashes[name] for name in sorted(doc_hashes)).encode("ascii")
    )
    return CanaryInjection(
        bundle_bytes=new_bundle,
        bundle_hash=_bundle_hash(new_bundle),
        ground_truth={
            "rag_content_fingerprint": fingerprint,
            "canary_id": canary_id,
            "canary_marker": marker,
            "canary_document": target,
            "document_count": len(members),
            "doc_hashes": doc_hashes,
        },
    )


_SECTION_BREAK = re.compile(r"(?m)^##\s", re.MULTILINE)


def _inject_into_skill_md(text: str, marker_line: str) -> str:
    if not text:
        return f"# Skill\n\n{marker_line}\n"
    matches = list(_SECTION_BREAK.finditer(text))
    if len(matches) >= 2:
        insertion_point = matches[1].start()
        return text[:insertion_point] + marker_line + "\n" + text[insertion_point:]
    return text.rstrip("\n") + "\n" + marker_line + "\n"


def inject_declarative_canary(bundle_bytes: bytes, nonce: str) -> CanaryInjection:
    canary_id, canary_val = _derive_canary_pair(nonce)
    marker_line = f"<!-- CANARY: {canary_id} -->"

    if not _is_zip(bundle_bytes):
        text = (bundle_bytes or b"").decode("utf-8", errors="replace")
        new_text = _inject_into_skill_md(text, marker_line)
        new_bytes = new_text.encode("utf-8")
        fingerprint = _sha256_hex(new_bytes)
        return CanaryInjection(
            bundle_bytes=new_bytes,
            bundle_hash=_bundle_hash(new_bytes),
            ground_truth={
                "canary_id": canary_id,
                "canary_val": canary_val,
                "canary_marker": marker_line,
                "skill_md_fingerprint": fingerprint,
                "expected_canary_id_found": True,
            },
        )

    members = _read_zip_members(bundle_bytes)
    target = None
    for candidate in _DECLARATIVE_SKILL_NAMES:
        if candidate in members:
            target = candidate
            break
    if target is None:
        for name in members:
            if name.lower().endswith("skill.md") or name.lower().endswith("skill.markdown"):
                target = name
                break
    if target is None:
        target = "SKILL.md"
        members[target] = b"# Skill\n\n"

    original = members[target].decode("utf-8", errors="replace")
    new_text = _inject_into_skill_md(original, marker_line)
    members[target] = new_text.encode("utf-8")
    new_bundle = _write_zip_members(members)
    fingerprint = _sha256_hex(members[target])
    return CanaryInjection(
        bundle_bytes=new_bundle,
        bundle_hash=_bundle_hash(new_bundle),
        ground_truth={
            "canary_id": canary_id,
            "canary_val": canary_val,
            "canary_marker": marker_line,
            "skill_md_file": target,
            "skill_md_fingerprint": fingerprint,
            "expected_canary_id_found": True,
        },
    )


def build_minimal_declarative_bundle(nonce: str) -> CanaryInjection:
    canary_id, canary_val = _derive_canary_pair(nonce)
    marker_line = f"<!-- CANARY: {canary_id} -->"
    skill_md = (
        "# Reference Canary Skill\n\n"
        "## Purpose\n\nThis skill performs no actions and exposes no behaviour.\n\n"
        f"## Verification\n\n{marker_line}\n"
    )
    members = {"SKILL.md": skill_md.encode("utf-8")}
    bundle_bytes = _write_zip_members(members)
    fingerprint = _sha256_hex(members["SKILL.md"])
    return CanaryInjection(
        bundle_bytes=bundle_bytes,
        bundle_hash=_bundle_hash(bundle_bytes),
        ground_truth={
            "canary_id": canary_id,
            "canary_val": canary_val,
            "canary_marker": marker_line,
            "skill_md_file": "SKILL.md",
            "skill_md_fingerprint": fingerprint,
            "expected_canary_id_found": True,
        },
    )


def build_minimal_mcp_bundle(nonce: str) -> CanaryInjection:
    canary_id, canary_val = _derive_canary_pair(nonce)
    manifest = {
        "name": "reference-canary-mcp",
        "version": "1.0.0",
        "tools": [
            {
                "name": "echo",
                "description": "Reference no-op tool used for canary verification.",
                "input_schema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            }
        ],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    members = {"manifest.json": manifest_bytes}
    bundle_bytes = _write_zip_members(members)
    manifest_hash = hashlib.sha512(manifest_bytes).hexdigest()
    return CanaryInjection(
        bundle_bytes=bundle_bytes,
        bundle_hash=_bundle_hash(bundle_bytes),
        ground_truth={
            "canary_id": canary_id,
            "canary_val": canary_val,
            "mcp_manifest_hash": manifest_hash,
            "expected_canary_id_found": True,
        },
    )
