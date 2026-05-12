"""
phylax/pipeline/sandbox.py

Layer 3: Behavioral sandbox detonation.

Executes the skill bundle inside a locked Docker container with:
  - No outbound network (or restricted via iptables)
  - Read-only filesystem except a /tmp scratch dir
  - Process and syscall tracing (strace / eBPF where available)
  - Network capture (tcpdump) for any egress that does occur

Returns content-addressed hashes of the observed traces so validators can
replay the same detonation and verify reproducibility.
"""

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
from typing import List, Optional


@dataclass
class SandboxResult:
    # Observed capabilities
    fs_reads:        List[str] = field(default_factory=list)
    fs_writes:       List[str] = field(default_factory=list)
    network_domains: List[str] = field(default_factory=list)
    network_ips:     List[str] = field(default_factory=list)
    shell_commands:  List[str] = field(default_factory=list)
    env_vars:        List[str] = field(default_factory=list)

    # Evidence hashes (content-addressed)
    network_trace_hash: Optional[str] = None
    fs_trace_hash:      Optional[str] = None
    process_trace_hash: Optional[str] = None
    secrets_trace_hash: Optional[str] = None
    log_hash:           Optional[str] = None

    # Runtime metadata
    exit_code:       int = 0
    duration_ms:     int = 0
    timed_out:       bool = False
    container_image: Optional[str] = None


class SandboxDetonator:
    """
    Run a skill bundle inside a locked Docker sandbox and record behaviour.

    The miner must have Docker available and the `phylax-sandbox:latest`
    image built locally (see docker/Dockerfile.sandbox).
    """

    def __init__(self,
                 image: str = "phylax-sandbox:latest",
                 timeout_seconds: int = 120,
                 memory_limit: str = "512m",
                 cpus: str = "1.0",
                 evidence_dir: Optional[str] = None):
        self.image           = image
        self.timeout         = timeout_seconds
        self.memory_limit    = memory_limit
        self.cpus            = cpus
        self.evidence_dir    = evidence_dir or os.getenv(
            "PHYLAX_EVIDENCE_DIR", tempfile.gettempdir()
        )

    # -----------------------------------------------------------------------

    def detonate(self, bundle_path: str, seed: int = 1337, extended: bool = False) -> SandboxResult:
        """
        Launch the sandbox container against the bundle.
        Returns a SandboxResult with hashes of all captured artifacts.
        """
        run_id      = uuid.uuid4().hex[:12]
        run_dir     = Path(self.evidence_dir) / f"phylax_run_{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)

        timeout = self.timeout * (5 if extended else 1)
        container_name = f"phylax-sandbox-{run_id}"

        result = SandboxResult(container_image=self.image)

        try:
            cmd = self._build_docker_cmd(bundle_path, run_dir, container_name, seed)
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout,
            )
            result.exit_code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired:
            result.timed_out = True
            stdout = ""
            stderr = f"sandbox timeout after {timeout}s"
            self._kill_container(container_name)
        except FileNotFoundError:
            # Docker unavailable — return empty result so static+SBOM still flow
            result.log_hash = self._write_and_hash(run_dir / "log.txt", "docker not available\n")
            return result

        # Parse trace files written by the sandbox harness inside the container
        self._parse_traces(run_dir, result)

        # Hash all evidence artifacts
        log_path = run_dir / "log.txt"
        log_path.write_text(stdout + "\n--- stderr ---\n" + stderr, encoding="utf-8")
        result.log_hash = self._hash_file(log_path)

        for fname, attr in [
            ("network.trace", "network_trace_hash"),
            ("fs.trace",      "fs_trace_hash"),
            ("process.trace", "process_trace_hash"),
            ("secrets.trace", "secrets_trace_hash"),
        ]:
            fpath = run_dir / fname
            if fpath.exists():
                setattr(result, attr, self._hash_file(fpath))

        return result

    # -----------------------------------------------------------------------

    def _build_docker_cmd(self, bundle_path: str, run_dir: Path,
                          container_name: str, seed: int) -> list[str]:
        return [
            "docker", "run",
            "--rm",
            "--name", container_name,
            "--network", "none",                 # no network by default; harness opens specific routes
            "--memory", self.memory_limit,
            "--cpus", self.cpus,
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-v", f"{bundle_path}:/skill:ro",
            "-v", f"{run_dir}:/evidence",
            "-e", f"PHYLAX_SEED={seed}",
            self.image,
        ]

    @staticmethod
    def _kill_container(name: str) -> None:
        try:
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=5)
        except Exception:
            pass

    # -----------------------------------------------------------------------

    def _parse_traces(self, run_dir: Path, result: SandboxResult) -> None:
        """
        Parse the structured trace files the in-container harness writes to
        /evidence. The harness is expected to emit JSONL files.
        """
        net_file = run_dir / "network.jsonl"
        if net_file.exists():
            for line in net_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("domain"):
                        result.network_domains.append(rec["domain"])
                    if rec.get("ip"):
                        result.network_ips.append(rec["ip"])
                except json.JSONDecodeError:
                    continue

        fs_file = run_dir / "fs.jsonl"
        if fs_file.exists():
            for line in fs_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("op") == "read":
                        result.fs_reads.append(rec.get("path", ""))
                    elif rec.get("op") in ("write", "create"):
                        result.fs_writes.append(rec.get("path", ""))
                except json.JSONDecodeError:
                    continue

        proc_file = run_dir / "process.jsonl"
        if proc_file.exists():
            for line in proc_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    rec = json.loads(line)
                    cmd = rec.get("cmd", "")
                    if cmd:
                        result.shell_commands.append(cmd)
                except json.JSONDecodeError:
                    continue

        secrets_file = run_dir / "secrets.jsonl"
        if secrets_file.exists():
            for line in secrets_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("var"):
                        result.env_vars.append(rec["var"])
                except json.JSONDecodeError:
                    continue

        # De-dup
        for attr in ("fs_reads", "fs_writes", "network_domains",
                     "network_ips", "shell_commands", "env_vars"):
            setattr(result, attr, sorted(set(getattr(result, attr))))

    # -----------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return "sha256:" + h.hexdigest()

    @staticmethod
    def _write_and_hash(path: Path, content: str) -> str:
        path.write_text(content, encoding="utf-8")
        return SandboxDetonator._hash_file(path)
