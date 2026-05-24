from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SandboxResult:
    # Observed capabilities
    fs_reads:        list[str] = field(default_factory=list)
    fs_writes:       list[str] = field(default_factory=list)
    network_domains: list[str] = field(default_factory=list)
    network_ips:     list[str] = field(default_factory=list)
    shell_commands:  list[str] = field(default_factory=list)
    env_vars:        list[str] = field(default_factory=list)

    # Evidence hashes (content-addressed)
    network_trace_hash: str | None = None
    fs_trace_hash:      str | None = None
    process_trace_hash: str | None = None
    secrets_trace_hash: str | None = None
    log_hash:           str | None = None

    # Runtime metadata
    exit_code:       int = 0
    duration_ms:     int = 0
    timed_out:       bool = False
    container_image: str | None = None


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
                 evidence_dir: str | None = None):
        self.image           = image
        self.timeout         = timeout_seconds
        self.memory_limit    = memory_limit
        self.cpus            = cpus
        self.evidence_dir    = evidence_dir or os.getenv(
            "PHYLAX_EVIDENCE_DIR", tempfile.gettempdir()
        )

    # -----------------------------------------------------------------------

    def detonate(self, bundle_path: str, seed: int, extended: bool = False) -> SandboxResult:
        """Launch the sandbox container against the bundle.

        ``seed`` is the per-task determinism nonce; it is exported to the
        in-container harness as ``PHYLAX_SEED`` so randomness and trace
        ordering are reproducible. Callers must pass a real seed — a
        hardcoded default would break the anti-copy property.
        """
        if seed is None or seed < 0:
            raise ValueError("SandboxDetonator.detonate requires a non-negative seed")
        run_id = uuid.uuid4().hex[:12]
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

        # Hash the full container log (stdout + stderr).
        log_path = run_dir / "log.txt"
        log_path.write_text(stdout + "\n--- stderr ---\n" + stderr, encoding="utf-8")
        result.log_hash = self._hash_file(log_path)

        # Hash the normalized record set (sorted, volatile fields stripped),
        # not the raw JSONL bytes, so two honest miners on the same nonce
        # produce byte-equal hashes regardless of hook firing order.
        result.network_trace_hash = self._canonical_hash(run_dir / "network.jsonl", _NORM_NET)
        result.fs_trace_hash = self._canonical_hash(run_dir / "fs.jsonl", _NORM_FS)
        result.process_trace_hash = self._canonical_hash(run_dir / "process.jsonl", _NORM_PROC)
        result.secrets_trace_hash = self._canonical_hash(run_dir / "secrets.jsonl", _NORM_SECRETS)

        return result

    # -----------------------------------------------------------------------

    def _build_docker_cmd(self, bundle_path: str, run_dir: Path,
                          container_name: str, seed: int) -> list[str]:
        # Run the container as the host user so the harness can write to
        # the bind-mounted /evidence directory. Without this override the
        # image's baked-in 'sandbox' user (UID ~999) can't write to a host
        # dir owned by the operator (UID 1000), the harness errors out
        # silently, and the evidence trace files are never produced —
        # which makes score_evidence return 0 forever.
        return [
            "docker", "run",
            "--rm",
            "--name", container_name,
            "--user", f"{os.getuid()}:{os.getgid()}",
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

    @staticmethod
    def _canonical_hash(path: Path, normaliser) -> str | None:
        """
        Hash the canonical (normalised + sorted) form of a JSONL trace.

        Two miners running the same skill under the same nonce should
        produce byte-equal hashes here. The validator's replay engine
        applies the identical pipeline to compute its ground-truth hash.
        Returns None when the trace file doesn't exist (so the SSSA carries
        an explicit null rather than a fake hash of empty bytes).
        """
        if not path.exists():
            return None
        records: list[dict] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            norm = normaliser(rec)
            if norm is not None:
                records.append(norm)
        # Canonical ordering: sort by stable JSON representation of each record.
        records.sort(key=lambda r: json.dumps(r, sort_keys=True, separators=(",", ":")))
        canon = json.dumps(records, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


# Per-component normalisers drop nondeterministic fields (timestamps, pids)
# and keep only the behavioural facts that go into the canonical hash.

def _NORM_NET(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    out = {
        "domain": rec.get("domain"),
        "ip": rec.get("ip"),
        "port": rec.get("port"),
        "bytes": rec.get("bytes"),
    }
    if not any(out.values()):
        return None
    return out


def _NORM_FS(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    op = rec.get("op")
    path = rec.get("path")
    if not op or not path:
        return None
    return {"op": op, "path": path}


def _NORM_PROC(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    cmd = rec.get("cmd")
    if not cmd:
        return None
    return {"cmd": cmd, "uid": rec.get("uid")}


def _NORM_SECRETS(rec: dict) -> dict | None:
    if not isinstance(rec, dict):
        return None
    var = rec.get("var") or rec.get("key")
    if not var:
        return None
    return {"var": var}
