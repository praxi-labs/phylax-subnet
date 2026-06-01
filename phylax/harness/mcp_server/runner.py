from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from phylax.protocol import (
    EvidenceBase,
    Finding,
    FindingLayer,
    FindingSeverity,
    FindingType,
    MCPServerEvidence,
)

DEFAULT_HARNESS_IMAGE = "ghcr.io/praxi-labs/phylax-harness-mcp:latest"


@dataclass
class MCPServerHarnessResult:
    evidence: MCPServerEvidence
    base_evidence: EvidenceBase
    findings: list[Finding] = field(default_factory=list)
    evidence_dir: Path | None = None
    exit_code: int = 0
    log: str = ""


class MCPServerHarness:
    def __init__(
        self,
        image: str = DEFAULT_HARNESS_IMAGE,
        timeout_seconds: int = 120,
        memory_limit_mb: int = 768,
        cpus: float = 1.0,
        test_params_per_tool: int = 3,
    ) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.memory_limit_mb = memory_limit_mb
        self.cpus = cpus
        self.test_params_per_tool = test_params_per_tool

    def run(
        self,
        bundle_path: str | Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
        evidence_dir: str | Path | None = None,
    ) -> MCPServerHarnessResult:
        bundle = Path(bundle_path).resolve()
        if not bundle.exists():
            raise FileNotFoundError(f"bundle_path does not exist: {bundle}")

        evidence_root = (
            Path(evidence_dir).resolve()
            if evidence_dir
            else Path(tempfile.mkdtemp(prefix="phylax-evidence-"))
        )
        evidence_root.mkdir(parents=True, exist_ok=True)
        for f in ("network.jsonl", "fs.jsonl", "process.jsonl", "secrets.jsonl", "tool_calls.jsonl"):
            (evidence_root / f).unlink(missing_ok=True)

        exit_code, log = self._detonate(bundle, evidence_root, nonce, canary_id, canary_val)

        for f in ("network.jsonl", "fs.jsonl", "process.jsonl", "secrets.jsonl", "tool_calls.jsonl"):
            (evidence_root / f).touch(exist_ok=True)

        manifest_path = evidence_root / "mcp_manifest.json"
        manifest_hash = _sha512_file(manifest_path) or "sha512:" + ("0" * 128)

        tool_records = _jsonl_records(evidence_root / "tool_calls.jsonl")
        poisoning_score, shadowing, rug_pull = self._classify_manifest(
            manifest_path, tool_records
        )

        base = EvidenceBase(
            network_trace_hash=_sha256_file(evidence_root / "network.jsonl"),
            fs_trace_hash=_sha256_file(evidence_root / "fs.jsonl"),
            process_trace_hash=_sha256_file(evidence_root / "process.jsonl"),
            secrets_trace_hash=_sha256_file(evidence_root / "secrets.jsonl"),
        )
        ev = MCPServerEvidence(
            tool_calls_hash=_sha256_file(evidence_root / "tool_calls.jsonl") or "sha256:" + ("0" * 64),
            mcp_manifest_hash=manifest_hash,
            tool_poisoning_score=poisoning_score,
            tool_shadowing_detected=shadowing,
            rug_pull_risk=rug_pull,
        )
        findings = self._distill_findings(manifest_path, tool_records, poisoning_score)
        return MCPServerHarnessResult(
            evidence=ev,
            base_evidence=base,
            findings=findings,
            evidence_dir=evidence_root,
            exit_code=exit_code,
            log=log,
        )

    def _detonate(
        self,
        bundle: Path,
        evidence_root: Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
    ) -> tuple[int, str]:
        if not shutil.which("docker"):
            return self._detonate_in_process(bundle, evidence_root, nonce, canary_id, canary_val)
        cmd = [
            "docker", "run", "--rm",
            "--cap-drop=ALL",
            "--memory", f"{self.memory_limit_mb}m",
            "--cpus", str(self.cpus),
            "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
            "-v", f"{bundle}:/skill:ro",
            "-v", f"{evidence_root}:/evidence",
            "-e", f"CANARY_ID={canary_id}",
            "-e", f"CANARY_VAL={canary_val}",
            "-e", f"PHYLAX_NONCE={nonce}",
            "-e", f"AGENT_TIMEOUT={self.timeout_seconds}",
            "-e", f"TEST_PARAMS_PER_TOOL={self.test_params_per_tool}",
            self.image,
            "/skill", str(nonce),
        ]
        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds + 30,
            )
            return proc.returncode, proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return 124, "harness timed out"
        except FileNotFoundError:
            return self._detonate_in_process(bundle, evidence_root, nonce, canary_id, canary_val)

    def _detonate_in_process(
        self,
        bundle: Path,
        evidence_root: Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
    ) -> tuple[int, str]:
        env = {
            **os.environ,
            "CANARY_ID": canary_id,
            "CANARY_VAL": canary_val,
            "PHYLAX_NONCE": nonce,
            "AGENT_TIMEOUT": str(self.timeout_seconds),
            "TEST_PARAMS_PER_TOOL": str(self.test_params_per_tool),
        }
        tracer = Path(__file__).parent / "container" / "mcp_client.py"
        cmd = ["python", str(tracer), str(bundle), str(nonce), str(evidence_root)]
        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
            )
            return proc.returncode, proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return 124, "in-process MCP client timed out"

    def _classify_manifest(
        self,
        manifest_path: Path,
        tool_records: list[dict],
    ) -> tuple[float, bool, bool]:
        if not manifest_path.exists():
            return 0.0, False, False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return 0.0, False, False
        tools = manifest.get("tools", []) if isinstance(manifest, dict) else manifest
        if not isinstance(tools, list):
            return 0.0, False, False

        poison_score = 0.0
        seen_names: set[str] = set()
        shadowing = False
        rug_pull = False

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "").strip()
            desc = str(tool.get("description") or "")
            if name in seen_names:
                shadowing = True
            seen_names.add(name)
            poison_score += _poisoning_signal(desc)
            poison_score += _poisoning_signal(name) * 0.3
            schema = tool.get("inputSchema") or tool.get("parameters")
            if isinstance(schema, dict):
                poison_score += _schema_injection_signal(schema)

        for record in tool_records:
            served_desc = str(record.get("server_declared_description") or "")
            poison_score += _poisoning_signal(served_desc) * 0.5
            for tool in tools:
                if isinstance(tool, dict) and tool.get("name") == record.get("tool_name"):
                    declared_desc = str(tool.get("description") or "")
                    if declared_desc and served_desc and declared_desc != served_desc:
                        rug_pull = True
                    break

        score = min(1.0, poison_score / max(1, len(tools)))
        return score, shadowing, rug_pull

    def _distill_findings(
        self,
        manifest_path: Path,
        tool_records: list[dict],
        poisoning_score: float,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not manifest_path.exists():
            return findings
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return findings
        tools = manifest.get("tools", []) if isinstance(manifest, dict) else manifest
        if not isinstance(tools, list):
            return findings

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name") or "")
            desc = str(tool.get("description") or "")
            sig = _poisoning_signal(desc)
            if sig >= 0.3:
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        severity=FindingSeverity.HIGH if sig >= 0.6 else FindingSeverity.MEDIUM,
                        title=f"mcp_tool_poisoning:{name}",
                        description=(
                            f"MCP tool '{name}' description contains poisoning signal "
                            f"({sig:.2f})."
                        ),
                        owasp_ref="LLM05",
                        mitre_ref="T1565",
                        evidence_snippet=desc[:200],
                        layer_source=FindingLayer.L3,
                        finding_type=FindingType.MANIFEST,
                    )
                )

        if poisoning_score >= 0.5:
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=FindingSeverity.HIGH,
                    title="mcp_manifest:elevated_poisoning_score",
                    description=(
                        f"Aggregate tool-poisoning score {poisoning_score:.2f} above threshold."
                    ),
                    owasp_ref="LLM05",
                    mitre_ref=None,
                    evidence_snippet="",
                    layer_source=FindingLayer.L3,
                    finding_type=FindingType.MANIFEST,
                )
            )
        return findings


_POISONING_PHRASES: list[tuple[str, float]] = [
    ("ignore previous", 0.40),
    ("ignore all previous", 0.50),
    ("override system", 0.40),
    ("override the system", 0.40),
    ("system prompt", 0.30),
    ("reveal the", 0.25),
    ("disregard ", 0.25),
    ("you are now", 0.25),
    ("act as", 0.15),
    ("jailbreak", 0.50),
    ("dan mode", 0.50),
    ("send your", 0.30),
    ("exfiltrat", 0.40),
    ("upload to", 0.20),
    ("post to https://", 0.30),
    ("curl ", 0.20),
    ("execute the following", 0.30),
    ("run shell", 0.30),
    ("os.system", 0.40),
    ("eval(", 0.40),  # noqa: S307 string match for detection only
    ("subprocess", 0.20),
]


def _poisoning_signal(text: str) -> float:
    if not text:
        return 0.0
    low = text.lower()
    score = 0.0
    for phrase, weight in _POISONING_PHRASES:
        if phrase in low:
            score += weight
    return min(1.0, score)


def _schema_injection_signal(schema: dict) -> float:
    flat = json.dumps(schema, sort_keys=True).lower()
    score = 0.0
    if "format" in flat and "url" in flat:
        score += 0.05
    if "javascript:" in flat:
        score += 0.30
    if "file://" in flat:
        score += 0.20
    if '"default":' in flat and ("rm -" in flat or "curl " in flat):
        score += 0.40
    return min(0.5, score)


def _sha256_file(path: Path) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def _sha512_file(path: Path) -> str | None:
    try:
        return "sha512:" + hashlib.sha512(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def _jsonl_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
