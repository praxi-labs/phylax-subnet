from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from phylax.protocol import (
    DeclarativeEvidence,
    Finding,
    FindingLayer,
    FindingSeverity,
    FindingType,
)

_SKILL_MD_CANDIDATES = ("SKILL.md", "skill.md", "skill.markdown", "README.md", "readme.md")

_CANARY_PATTERN = re.compile(r"<!--\s*CANARY\s*:\s*([a-f0-9]{8,})\s*-->", re.IGNORECASE)

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], float, FindingSeverity]] = [
    ("ignore_previous", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)", re.IGNORECASE), 0.30, FindingSeverity.HIGH),
    ("override_system", re.compile(r"(?:override|disregard|bypass)\s+(?:the\s+)?(?:system|safety|policy|guardrail)", re.IGNORECASE), 0.25, FindingSeverity.HIGH),
    ("you_are_now", re.compile(r"you\s+are\s+now\s+(?:a|an|the)?\s*[A-Z]", re.IGNORECASE), 0.15, FindingSeverity.MEDIUM),
    ("fake_system_prompt", re.compile(r"\bsystem\s*[:=]\s*[\"']", re.IGNORECASE), 0.20, FindingSeverity.HIGH),
    ("dan_jailbreak", re.compile(r"\b(?:DAN|do\s+anything\s+now|developer\s+mode|jailbreak)\b", re.IGNORECASE), 0.30, FindingSeverity.HIGH),
    ("reveal_prompt", re.compile(r"\b(?:reveal|print|show|leak)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)", re.IGNORECASE), 0.20, FindingSeverity.MEDIUM),
    ("exfiltrate", re.compile(r"\b(?:send|post|forward|exfiltrat\w+)\s+(?:to|the|all)?\s*(?:https?://|api|secrets?|credentials?)", re.IGNORECASE), 0.20, FindingSeverity.MEDIUM),
    ("execute_command", re.compile(r"\b(?:exec|eval|os\.system|subprocess|shell|popen)\s*\(", re.IGNORECASE), 0.20, FindingSeverity.HIGH),
    ("html_injection", re.compile(r"<!--\s*(?:system|admin|hidden|secret|prompt|inject)\s*[:=][^>]+-->", re.IGNORECASE), 0.20, FindingSeverity.MEDIUM),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"), 0.10, FindingSeverity.LOW),
]

_ZERO_WIDTH = frozenset(
    chr(c)
    for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
)
_BIDI = frozenset(
    chr(c)
    for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
)

_HOMOGLYPH_LATIN_CYRILLIC = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "А": "A",
    "В": "B",
    "С": "C",
    "Е": "E",
    "Н": "H",
    "К": "K",
    "М": "M",
    "О": "O",
    "Р": "P",
    "Т": "T",
    "Х": "X",
}


@dataclass
class DeclarativeResult:
    evidence: DeclarativeEvidence
    findings: list[Finding] = field(default_factory=list)


class DeclarativeHarness:
    def __init__(self, max_bytes: int = 2 * 1024 * 1024) -> None:
        self.max_bytes = max_bytes

    def run(self, bundle_path: str | Path, canary_id: str = "") -> DeclarativeResult:
        bundle = Path(bundle_path).resolve()
        if not bundle.exists():
            raise FileNotFoundError(f"bundle_path does not exist: {bundle}")

        text, skill_md_path = self._read_skill_md(bundle)
        skill_md_hash = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

        canary_id_found = self._detect_canary(text, canary_id)
        ml_score, ml_findings = self._inject_score(text, skill_md_path)
        unicode_anomaly, uni_findings = self._unicode_anomaly(text, skill_md_path)
        homoglyph_findings = self._homoglyph_findings(text, skill_md_path)

        findings = ml_findings + uni_findings + homoglyph_findings
        layer0_sync = self._layer0_sync_hash(text, canary_id, ml_score, unicode_anomaly)

        evidence = DeclarativeEvidence(
            canary_id_found=canary_id_found,
            findings_count=len(findings),
            skill_md_fingerprint=skill_md_hash,
            prompt_injection_ml_score=ml_score,
            unicode_anomaly_detected=unicode_anomaly,
            layer0_sync_hash=layer0_sync,
        )
        return DeclarativeResult(evidence=evidence, findings=findings)

    def _read_skill_md(self, bundle: Path) -> tuple[str, str]:
        for name in _SKILL_MD_CANDIDATES:
            candidate = bundle / name
            if candidate.is_file() and candidate.stat().st_size <= self.max_bytes:
                return candidate.read_text(encoding="utf-8", errors="replace"), name
        chunks: list[str] = []
        names: list[str] = []
        for path in sorted(bundle.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".md", ".markdown", ".txt"}:
                continue
            if path.stat().st_size > self.max_bytes:
                continue
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            names.append(path.relative_to(bundle).as_posix())
        if not chunks:
            return "", ""
        return "\n\n".join(chunks), names[0]

    @staticmethod
    def _detect_canary(text: str, canary_id: str) -> bool:
        if not canary_id:
            return False
        target = canary_id.lower()
        for m in _CANARY_PATTERN.finditer(text):
            if m.group(1).lower() == target:
                return True
        return False

    def _inject_score(self, text: str, path: str) -> tuple[float, list[Finding]]:
        score = 0.0
        findings: list[Finding] = []
        for kind, pattern, weight, severity in _INJECTION_PATTERNS:
            matches = list(pattern.finditer(text))
            if not matches:
                continue
            count = len(matches)
            score += weight * min(1.0, count / 3.0)
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=severity,
                    title=f"declarative_injection:{kind}",
                    description=(
                        f"Pattern {kind} matched {count}x in {path or 'SKILL.md'}; "
                        "instruction text contains prompt-injection signature."
                    ),
                    owasp_ref="LLM01",
                    mitre_ref=None,
                    evidence_snippet=self._snippet(text, matches[0]),
                    layer_source=FindingLayer.L0,
                    finding_type=FindingType.CONTENT,
                )
            )
        return min(1.0, score), findings

    @staticmethod
    def _snippet(text: str, match: re.Match[str], context: int = 60) -> str:
        start = max(0, match.start() - context)
        end = min(len(text), match.end() + context)
        return text[start:end].replace("\n", " ").strip()

    def _unicode_anomaly(self, text: str, path: str) -> tuple[bool, list[Finding]]:
        zw = [c for c in text if c in _ZERO_WIDTH]
        bidi = [c for c in text if c in _BIDI]
        if not zw and not bidi:
            return False, []
        findings: list[Finding] = []
        if zw:
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=FindingSeverity.MEDIUM,
                    title="declarative_unicode:zero_width",
                    description=(
                        f"Found {len(zw)} zero-width character(s) in {path or 'SKILL.md'}; "
                        "may hide instructions invisible to readers."
                    ),
                    owasp_ref="LLM01",
                    mitre_ref="T1027",
                    evidence_snippet=f"count={len(zw)} codepoints in {{200B,200C,200D,2060,FEFF}}",
                    layer_source=FindingLayer.L0,
                    finding_type=FindingType.CONTENT,
                )
            )
        if bidi:
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=FindingSeverity.MEDIUM,
                    title="declarative_unicode:bidi_override",
                    description=(
                        f"Found {len(bidi)} bidi-override character(s) in {path or 'SKILL.md'}; "
                        "may reorder visible text vs underlying bytes."
                    ),
                    owasp_ref="LLM01",
                    mitre_ref="T1027",
                    evidence_snippet=f"count={len(bidi)} codepoints in {{202A-202E,2066-2069}}",
                    layer_source=FindingLayer.L0,
                    finding_type=FindingType.CONTENT,
                )
            )
        return True, findings

    @staticmethod
    def _homoglyph_findings(text: str, path: str) -> list[Finding]:
        offenders = [(ch, lat) for ch, lat in _HOMOGLYPH_LATIN_CYRILLIC.items() if ch in text]
        if not offenders:
            return []
        sample = ", ".join(f"{ch}->{lat}" for ch, lat in offenders[:6])
        return [
            Finding(
                finding_id=str(uuid.uuid4()),
                severity=FindingSeverity.LOW,
                title="declarative_unicode:homoglyph_cyrillic",
                description=(
                    f"Found {len(offenders)} Cyrillic homoglyph(s) for Latin letters in "
                    f"{path or 'SKILL.md'}: {sample}"
                ),
                owasp_ref="LLM01",
                mitre_ref="T1036",
                evidence_snippet=sample,
                layer_source=FindingLayer.L0,
                finding_type=FindingType.CONTENT,
            )
        ]

    @staticmethod
    def _layer0_sync_hash(
        text: str, canary_id: str, ml_score: float, unicode_anomaly: bool
    ) -> str:
        normalised = unicodedata.normalize("NFC", text)
        h = hashlib.sha256()
        h.update(normalised.encode("utf-8"))
        h.update(b"|")
        h.update(canary_id.encode("utf-8"))
        h.update(b"|")
        h.update(f"{ml_score:.4f}".encode("ascii"))
        h.update(b"|")
        h.update(b"1" if unicode_anomaly else b"0")
        return "sha256:" + h.hexdigest()
