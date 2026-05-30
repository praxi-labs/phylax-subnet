from __future__ import annotations

import io
import time
import zipfile
from dataclasses import dataclass, field

from phylax.layer0_declarative import (
    _CANARY_RE,  # noqa: PLC2701
    DeclarativeCapabilities,
    DeclarativeFinding,
    analyze_skill_md,
    compute_verdict_from_findings,
    derive_declarative_policy,
    layer0_sync_hash,
    skill_md_fingerprint,
)

_SKILL_MD_NAMES = ("skill.md", "skill.markdown", "readme.md")


@dataclass
class Layer0Result:
    verdict: str
    risk_score: int
    rationale: str
    findings: list[DeclarativeFinding] = field(default_factory=list)
    capabilities: DeclarativeCapabilities = field(default_factory=DeclarativeCapabilities)
    policy: dict | None = None
    skill_md_fingerprint: str | None = None
    server_canary_present: bool = False
    canary_id_in_bundle: str | None = None
    sync_hash: str = ""
    analysis_duration_ms: int = 0


def _extract_skill_md_from_bundle(content: bytes) -> str | None:
    if content[:2] != b"PK":
        return content.decode("utf-8", "replace")
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for name in zf.namelist():
                tail = name.lower().rsplit("/", 1)[-1]
                if tail in _SKILL_MD_NAMES:
                    try:
                        return zf.read(name).decode("utf-8", "replace")
                    except (KeyError, zipfile.BadZipFile):
                        continue
            md_parts: list[str] = []
            for name in zf.namelist():
                if name.lower().endswith((".md", ".markdown")):
                    try:
                        md_parts.append(zf.read(name).decode("utf-8", "replace"))
                    except (KeyError, zipfile.BadZipFile):
                        continue
            return "\n\n".join(md_parts) if md_parts else None
    except zipfile.BadZipFile:
        return None


def run_validator_layer0(
    bundle_bytes: bytes,
    *,
    task_skill_md: str | None = None,
    expected_canary_id: str | None = None,
) -> Layer0Result:
    start = time.time()
    text = task_skill_md or _extract_skill_md_from_bundle(bundle_bytes) or ""

    caps, findings = analyze_skill_md(text)
    verdict_block = compute_verdict_from_findings(findings)
    policy = derive_declarative_policy(caps, findings)

    canary_in_text = _CANARY_RE.search(text)
    canary_id_in_bundle = canary_in_text.group(1) if canary_in_text else None
    server_canary_present = (
        expected_canary_id is not None
        and canary_id_in_bundle == expected_canary_id
    )

    return Layer0Result(
        verdict=verdict_block["decision"],
        risk_score=int(verdict_block["risk_score"]),
        rationale=verdict_block["rationale"],
        findings=findings,
        capabilities=caps,
        policy=policy,
        skill_md_fingerprint=skill_md_fingerprint(text),
        server_canary_present=server_canary_present,
        canary_id_in_bundle=canary_id_in_bundle,
        sync_hash=layer0_sync_hash(),
        analysis_duration_ms=int((time.time() - start) * 1000),
    )
