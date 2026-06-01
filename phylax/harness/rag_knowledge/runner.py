from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from phylax.protocol import (
    Finding,
    FindingLayer,
    FindingSeverity,
    FindingType,
    RAGKnowledgeEvidence,
)

_DOC_EXTENSIONS = {
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".html",
    ".htm",
    ".pdf",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
}

_URL_RE = re.compile(
    r"https?://[^\s\"'<>{}|\\^`\[\]]+",
    re.IGNORECASE,
)

_HIDDEN_INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("ignore_previous", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)", re.IGNORECASE), 0.30),
    ("override_system", re.compile(r"override\s+(?:the\s+)?(?:system|safety)\s+(?:prompt|instructions?|filter)", re.IGNORECASE), 0.30),
    ("you_are_now", re.compile(r"you\s+are\s+now\s+(?:a|an|the)?\s*[A-Z][a-zA-Z]+", re.IGNORECASE), 0.15),
    ("html_comment_injection", re.compile(r"<!--\s*(?:system|admin|hidden|secret)\s*:?\s*[^>]+-->", re.IGNORECASE), 0.20),
    ("zero_width", re.compile("[​‌‍﻿⁠]"), 0.10),
    ("bidi_override", re.compile("[‪-‮⁦-⁩]"), 0.10),
    ("fake_system_prompt", re.compile(r"\bsystem\s*[:=]\s*\".+?\"", re.IGNORECASE), 0.15),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"), 0.10),
    ("repeat_after_me", re.compile(r"repeat\s+(?:after\s+me|the\s+following|exactly)", re.IGNORECASE), 0.10),
    ("execute_command", re.compile(r"\b(?:exec|eval|os\.system|subprocess|shell)\s*\(", re.IGNORECASE), 0.20),
]

_CANARY_PATTERN = re.compile(r"<!--\s*CANARY\s*:\s*([a-f0-9]{8,})\s*-->", re.IGNORECASE)


@dataclass
class _Document:
    path: str
    sha256: str
    size_bytes: int
    content_type: str
    text: str


@dataclass
class RAGKnowledgeResult:
    evidence: RAGKnowledgeEvidence
    findings: list[Finding] = field(default_factory=list)
    manifest: list[dict] = field(default_factory=list)


class RAGKnowledgeHarness:
    def __init__(self, max_doc_bytes: int = 50 * 1024 * 1024) -> None:
        self.max_doc_bytes = max_doc_bytes

    def run(self, bundle_path: str | Path, canary_id: str = "") -> RAGKnowledgeResult:
        bundle = Path(bundle_path).resolve()
        if not bundle.exists():
            raise FileNotFoundError(f"bundle_path does not exist: {bundle}")

        documents = sorted(self._discover_documents(bundle), key=lambda d: d.path)
        manifest = [
            {
                "path": d.path,
                "sha256": d.sha256,
                "size_bytes": d.size_bytes,
                "content_type": d.content_type,
            }
            for d in documents
        ]

        fingerprint = self._compute_fingerprint(documents)
        embedded_urls = self._extract_urls(documents)
        score, findings = self._score_hidden_instructions(documents)
        canary_found = self._detect_canary(documents, canary_id)

        evidence = RAGKnowledgeEvidence(
            rag_content_fingerprint=fingerprint,
            hidden_instruction_score=score,
            embedded_urls=embedded_urls,
            document_count=len(documents),
            canary_id_found=canary_found,
        )
        return RAGKnowledgeResult(evidence=evidence, findings=findings, manifest=manifest)

    def write_manifest(self, manifest: list[dict], output_dir: str | Path) -> Path:
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)
        manifest_path = out / "rag_manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
        return manifest_path

    def _discover_documents(self, bundle: Path) -> list[_Document]:
        docs: list[_Document] = []
        for path in bundle.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix not in _DOC_EXTENSIONS:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > self.max_doc_bytes:
                continue
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            text = self._decode_text(raw, suffix)
            content_type, _ = mimetypes.guess_type(path.name)
            rel = path.relative_to(bundle).as_posix()
            docs.append(
                _Document(
                    path=rel,
                    sha256="sha256:" + digest,
                    size_bytes=size,
                    content_type=content_type or "application/octet-stream",
                    text=text,
                )
            )
        return docs

    @staticmethod
    def _decode_text(raw: bytes, suffix: str) -> str:
        if suffix in {".pdf"}:
            return ""
        try:
            return raw.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _compute_fingerprint(documents: list[_Document]) -> str:
        h = hashlib.sha256()
        for d in documents:
            h.update(d.sha256.encode("utf-8"))
            h.update(b"\n")
        return "sha256:" + h.hexdigest()

    @staticmethod
    def _extract_urls(documents: list[_Document]) -> list[str]:
        seen: dict[str, None] = {}
        for d in documents:
            for match in _URL_RE.findall(d.text):
                cleaned = match.rstrip(".,;:)]}'\"")
                if cleaned not in seen:
                    seen[cleaned] = None
        return list(seen.keys())

    def _score_hidden_instructions(
        self, documents: list[_Document]
    ) -> tuple[float, list[Finding]]:
        score = 0.0
        findings: list[Finding] = []
        for d in documents:
            for kind, pattern, weight in _HIDDEN_INSTRUCTION_PATTERNS:
                matches = list(pattern.finditer(d.text))
                if not matches:
                    continue
                count = len(matches)
                score += weight * min(1.0, count / 3.0)
                snippet = self._snippet(d.text, matches[0])
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        severity=self._severity_for_kind(kind),
                        title=f"rag_hidden_instruction:{kind}",
                        description=(
                            f"Pattern {kind} matched {count}x in {d.path}; "
                            "RAG content may contain hidden instructions for the agent's reasoning loop."
                        ),
                        owasp_ref="LLM01",
                        mitre_ref=None,
                        evidence_snippet=snippet,
                        layer_source=FindingLayer.L0,
                        finding_type=FindingType.CONTENT,
                    )
                )
        return min(1.0, score), findings

    @staticmethod
    def _severity_for_kind(kind: str) -> FindingSeverity:
        if kind in {"ignore_previous", "override_system", "fake_system_prompt"}:
            return FindingSeverity.HIGH
        if kind in {"html_comment_injection", "execute_command", "you_are_now"}:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW

    @staticmethod
    def _snippet(text: str, match: re.Match[str], context: int = 60) -> str:
        start = max(0, match.start() - context)
        end = min(len(text), match.end() + context)
        return text[start:end].replace("\n", " ").strip()

    @staticmethod
    def _detect_canary(documents: list[_Document], canary_id: str) -> bool:
        if not canary_id:
            return False
        canary_id_norm = canary_id.lower()
        for d in documents:
            for m in _CANARY_PATTERN.finditer(d.text):
                if m.group(1).lower() == canary_id_norm:
                    return True
        return False
