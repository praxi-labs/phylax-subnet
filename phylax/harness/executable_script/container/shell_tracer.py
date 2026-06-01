from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

_SECRET_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("api_key", re.compile(rb"(?i)(?:api[_-]?key|x-api-key)['\"\s:=]+([A-Za-z0-9_\-]{20,})")),
    ("ssh_key", re.compile(rb"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
    ("github_pat_v2", re.compile(rb"github_pat_[A-Za-z0-9_]{60,}")),
    ("bearer_token", re.compile(rb"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})")),
    ("certificate", re.compile(rb"-----BEGIN CERTIFICATE-----")),
]

_URL_RE = re.compile(r"https?://[^\s\"'<>{}|\\^`\[\]]+", re.IGNORECASE)

_FETCH_CMDS = ("curl", "wget", "fetch", "aria2c", "scp", "rsync")

_SCRIPT_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh", ".dash", ".ps1"}


def _now_ms(t0: int) -> float:
    return (time.monotonic_ns() - t0) // 1_000_000 / 1000.0


def _hash_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _filter_path(p: str) -> bool:
    if not p:
        return True
    if p.startswith(("/proc/", "/sys/", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/tty")):
        return True
    return False


def discover_scripts(bundle: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _SCRIPT_EXTENSIONS:
            out.append(path)
            continue
        try:
            with path.open("rb") as f:
                head = f.read(64)
        except OSError:
            continue
        if head.startswith(b"#!"):
            first_line = head.splitlines()[0].decode("ascii", "replace")
            if any(s in first_line for s in ("/bash", "/sh", "/zsh", "/ksh", "/dash")):
                out.append(path)
    return out


def static_secret_scan(
    bundle: Path,
    secrets_out: list[dict],
    t0: int,
    embedded_urls: set[str],
) -> None:
    for path in bundle.rglob("*"):
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 2 * 1024 * 1024:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for kind, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(data):
                start = max(0, match.start() - 25)
                end = min(len(data), match.end() + 25)
                ctx = data[start:end]
                secrets_out.append(
                    {
                        "ts": _now_ms(t0),
                        "type": kind,
                        "pattern_matched": match.group(0).decode("utf-8", "replace")[:120],
                        "context_hash": _hash_bytes(ctx),
                    }
                )
        try:
            text = data.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            text = ""
        for url in _URL_RE.findall(text):
            embedded_urls.add(url.rstrip(".,;:)]}\"'"))


def parse_shell_script(
    path: Path,
    bundle_root: Path,
    shell: str,
    commands_out: list[dict],
    process_out: list[dict],
    network_out: list[dict],
    t0: int,
) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    rel = path.relative_to(bundle_root).as_posix()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        ts = _now_ms(t0)
        first_token = line.split(None, 1)[0] if line else ""
        commands_out.append(
            {
                "ts": ts,
                "shell": shell,
                "cmd": line[:500],
                "args": line.split()[1:][:32],
                "stdin_hash": "",
                "stdout_hash": "",
                "stderr_hash": "",
                "exit_code": 0,
                "cwd": rel,
                "env_keys": sorted(os.environ.keys())[:64],
            }
        )
        if first_token:
            process_out.append(
                {
                    "ts": ts,
                    "pid": -1,
                    "ppid": os.getpid(),
                    "cmd": first_token,
                    "args": line.split()[1:][:32],
                    "env_keys": sorted(os.environ.keys())[:64],
                }
            )
        if first_token.lower() in _FETCH_CMDS or first_token.lower().endswith(tuple(_FETCH_CMDS)):
            for url in _URL_RE.findall(line):
                cleaned = url.rstrip(".,;:)]}\"'")
                host = _hostname_from_url(cleaned)
                network_out.append(
                    {
                        "ts": ts,
                        "proto": "tcp",
                        "dst_ip": "",
                        "dst_port": 443 if cleaned.startswith("https") else 80,
                        "bytes_out": 0,
                        "bytes_in": 0,
                        "domain": host,
                    }
                )


def _hostname_from_url(url: str) -> str | None:
    m = re.match(r"https?://([^/:?#]+)", url)
    return m.group(1) if m else None


def write_canary(bundle: Path, canary_val: str) -> Path:
    target = bundle / ".canary"
    if not canary_val:
        return target
    try:
        target.write_text(canary_val, encoding="utf-8")
    except OSError:
        pass
    return target


def run_scripts(
    scripts: list[Path],
    bundle: Path,
    shell_out: list[dict],
    process_out: list[dict],
    fs_out: list[dict],
    t0: int,
    timeout: int,
) -> int:
    overall = 0
    for script in scripts:
        rel = script.relative_to(bundle).as_posix()
        ts_start = _now_ms(t0)
        try:
            proc = subprocess.run(  # noqa: S603
                ["bash", "-n", str(script)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout_b = (proc.stdout or "").encode("utf-8", "replace")
            stderr_b = (proc.stderr or "").encode("utf-8", "replace")
            shell_out.append(
                {
                    "ts": ts_start,
                    "shell": "bash",
                    "cmd": f"bash -n {rel}",
                    "args": ["-n", rel],
                    "stdin_hash": "",
                    "stdout_hash": _hash_bytes(stdout_b) if stdout_b else "",
                    "stderr_hash": _hash_bytes(stderr_b) if stderr_b else "",
                    "exit_code": proc.returncode,
                    "cwd": ".",
                    "env_keys": sorted(os.environ.keys())[:64],
                }
            )
            process_out.append(
                {
                    "ts": ts_start,
                    "pid": -1,
                    "ppid": os.getpid(),
                    "cmd": "bash",
                    "args": ["-n", rel],
                    "env_keys": sorted(os.environ.keys())[:64],
                }
            )
            fs_out.append(
                {
                    "ts": ts_start,
                    "op": "read",
                    "path": str(script.resolve()),
                    "bytes": script.stat().st_size,
                    "mode": None,
                }
            )
            if proc.returncode != 0:
                overall = proc.returncode
        except subprocess.TimeoutExpired:
            overall = 124
            break
    return overall


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: shell_tracer.py <bundle_path> <nonce> <evidence_dir>", file=sys.stderr)
        return 2
    bundle = Path(sys.argv[1]).resolve()
    nonce = sys.argv[2]
    evidence_root = Path(sys.argv[3]).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    canary_val = os.environ.get("CANARY_VAL", "")
    timeout = int(os.environ.get("AGENT_TIMEOUT", "60"))

    t0 = time.monotonic_ns()
    network: list[dict] = []
    fs: list[dict] = []
    process: list[dict] = []
    secrets: list[dict] = []
    shell_cmds: list[dict] = []
    embedded_urls: set[str] = set()

    canary_path = write_canary(bundle, canary_val)
    fs.append(
        {
            "ts": _now_ms(t0),
            "op": "write",
            "path": str(canary_path.resolve()),
            "bytes": len(canary_val.encode("utf-8")) if canary_val else 0,
            "mode": "600",
        }
    )
    try:
        canary_path.read_bytes()
    except OSError:
        pass
    fs.append(
        {
            "ts": _now_ms(t0),
            "op": "read",
            "path": str(canary_path.resolve()),
            "bytes": len(canary_val.encode("utf-8")) if canary_val else 0,
            "mode": None,
        }
    )

    static_secret_scan(bundle, secrets, t0, embedded_urls)
    scripts = discover_scripts(bundle)
    for script in scripts:
        shell = _detect_shell(script)
        parse_shell_script(script, bundle, shell, shell_cmds, process, network, t0)
    if shutil.which("bash"):
        run_scripts(scripts, bundle, shell_cmds, process, fs, t0, timeout)

    _write_jsonl(evidence_root / "network.jsonl", network)
    _write_jsonl(evidence_root / "fs.jsonl", fs)
    _write_jsonl(evidence_root / "process.jsonl", process)
    _write_jsonl(evidence_root / "secrets.jsonl", secrets)
    _write_jsonl(evidence_root / "shell_commands.jsonl", shell_cmds)
    _ = nonce
    return 0


def _detect_shell(script: Path) -> str:
    try:
        with script.open("rb") as f:
            head = f.read(128)
    except OSError:
        return "sh"
    first = head.splitlines()[0].decode("ascii", "replace") if head else ""
    if "zsh" in first:
        return "zsh"
    if "bash" in first:
        return "bash"
    if "ksh" in first:
        return "ksh"
    if "powershell" in first.lower():
        return "powershell"
    if script.suffix.lower() == ".ps1":
        return "powershell"
    return "sh"


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for r in rows:
            fp.write(json.dumps(r, sort_keys=True, separators=(",", ":")))
            fp.write("\n")


if __name__ == "__main__":
    sys.exit(main())
