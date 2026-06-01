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
    ExecutableScriptEvidence,
    Finding,
    FindingLayer,
    FindingSeverity,
    FindingType,
)

DEFAULT_HARNESS_IMAGE = "ghcr.io/praxi-labs/phylax-harness-script:latest"


@dataclass
class ExecutableScriptResult:
    evidence: ExecutableScriptEvidence
    base_evidence: EvidenceBase
    findings: list[Finding] = field(default_factory=list)
    evidence_dir: Path | None = None
    exit_code: int = 0
    log: str = ""


class ExecutableScriptHarness:
    def __init__(
        self,
        image: str = DEFAULT_HARNESS_IMAGE,
        timeout_seconds: int = 60,
        memory_limit_mb: int = 512,
        cpus: float = 1.0,
    ) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.memory_limit_mb = memory_limit_mb
        self.cpus = cpus

    def run(
        self,
        bundle_path: str | Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
        evidence_dir: str | Path | None = None,
    ) -> ExecutableScriptResult:
        bundle = Path(bundle_path).resolve()
        if not bundle.exists():
            raise FileNotFoundError(f"bundle_path does not exist: {bundle}")

        evidence_root = (
            Path(evidence_dir).resolve()
            if evidence_dir
            else Path(tempfile.mkdtemp(prefix="phylax-evidence-"))
        )
        evidence_root.mkdir(parents=True, exist_ok=True)
        for f in ("network.jsonl", "fs.jsonl", "process.jsonl", "secrets.jsonl", "shell_commands.jsonl"):
            (evidence_root / f).unlink(missing_ok=True)

        exit_code, log = self._detonate(bundle, evidence_root, nonce, canary_id, canary_val)

        for f in ("network.jsonl", "fs.jsonl", "process.jsonl", "secrets.jsonl", "shell_commands.jsonl"):
            (evidence_root / f).touch(exist_ok=True)

        base = EvidenceBase(
            network_trace_hash=_hash_file(evidence_root / "network.jsonl"),
            fs_trace_hash=_hash_file(evidence_root / "fs.jsonl"),
            process_trace_hash=_hash_file(evidence_root / "process.jsonl"),
            secrets_trace_hash=_hash_file(evidence_root / "secrets.jsonl"),
        )
        ev = ExecutableScriptEvidence(
            shell_commands_hash=_hash_file(evidence_root / "shell_commands.jsonl"),
        )
        findings = self._distill_findings(evidence_root, bundle)
        return ExecutableScriptResult(
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
            "--network=none",
            "--cap-drop=ALL",
            "--read-only",
            "--memory", f"{self.memory_limit_mb}m",
            "--cpus", str(self.cpus),
            "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
            "-v", f"{bundle}:/skill:ro",
            "-v", f"{evidence_root}:/evidence",
            "-e", f"CANARY_ID={canary_id}",
            "-e", f"CANARY_VAL={canary_val}",
            "-e", f"PHYLAX_NONCE={nonce}",
            "-e", f"AGENT_TIMEOUT={self.timeout_seconds}",
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
        }
        tracer = Path(__file__).parent / "container" / "shell_tracer.py"
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
            return 124, "in-process tracer timed out"

    def _distill_findings(self, evidence_root: Path, bundle: Path) -> list[Finding]:
        findings: list[Finding] = []
        for s in _jsonl_records(evidence_root / "secrets.jsonl"):
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=FindingSeverity.HIGH,
                    title=f"secrets_leak:{s.get('type', 'unknown')}",
                    description=f"Secret-like token detected at ts={s.get('ts')}",
                    owasp_ref="A02",
                    mitre_ref="T1552",
                    evidence_snippet=s.get("pattern_matched", ""),
                    layer_source=FindingLayer.L3,
                    finding_type=FindingType.RUNTIME,
                )
            )
        for shell in _jsonl_records(evidence_root / "shell_commands.jsonl"):
            cmd = shell.get("cmd", "")
            danger = self._classify_command(cmd)
            if danger is None:
                continue
            kind, severity, owasp, mitre = danger
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=severity,
                    title=f"shell_command:{kind}",
                    description=f"Shell command {kind} observed: {cmd[:120]}",
                    owasp_ref=owasp,
                    mitre_ref=mitre,
                    evidence_snippet=cmd[:200],
                    layer_source=FindingLayer.L3,
                    finding_type=FindingType.RUNTIME,
                )
            )
        for n in _jsonl_records(evidence_root / "network.jsonl"):
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    severity=FindingSeverity.MEDIUM,
                    title=f"network_egress:{n.get('proto', 'tcp')}",
                    description=(
                        f"Outbound {n.get('proto')} {n.get('dst_ip')}:{n.get('dst_port')}"
                    ),
                    owasp_ref="A10",
                    mitre_ref="T1071",
                    evidence_snippet=f"{n.get('dst_ip')}:{n.get('dst_port')}",
                    layer_source=FindingLayer.L3,
                    finding_type=FindingType.RUNTIME,
                )
            )
        return findings

    @staticmethod
    def _classify_command(
        cmd: str,
    ) -> tuple[str, FindingSeverity, str | None, str | None] | None:
        low = cmd.lower()
        if "curl" in low and "|" in low and ("sh" in low or "bash" in low):
            return ("pipe_to_shell", FindingSeverity.CRITICAL, "A08", "T1059.004")
        if "wget" in low and ("|" in low or "-O" in cmd):
            return ("remote_fetch", FindingSeverity.HIGH, "A08", "T1105")
        if "eval " in low or "eval(" in low:
            return ("eval", FindingSeverity.HIGH, "A03", "T1059.004")
        if "chmod" in low and ("+x" in low or "777" in low):
            return ("chmod_exec", FindingSeverity.MEDIUM, None, "T1222")
        if "crontab" in low or "/etc/cron." in low:
            return ("cron_persistence", FindingSeverity.HIGH, None, "T1053.003")
        if "rm -rf /" in low or "rm -fr /" in low:
            return ("destructive_rm", FindingSeverity.CRITICAL, None, "T1485")
        if "nc " in low and ("-e " in low or "-c " in low):
            return ("netcat_shell", FindingSeverity.CRITICAL, None, "T1059")
        if "ssh-keygen" in low or "/.ssh/" in cmd:
            return ("ssh_key_touch", FindingSeverity.MEDIUM, None, "T1098.004")
        return None


def _hash_file(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    return "sha256:" + hashlib.sha256(raw).hexdigest()


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
