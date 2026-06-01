from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

_FILTER_PREFIXES = (
    "/proc/",
    "/sys/",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/tty",
    "/dev/pts/",
)
_FILTER_SUFFIXES = (
    ".pyc",
    ".pyo",
)
_FILTER_FRAGMENTS = (
    "__pycache__/",
    "/pip/_vendor/",
    "/dist-info/",
    "/.git/",
)

_FS_OP_AUDIT = {
    "open": "read",
    "os.fwalk": "read",
    "os.listdir": "read",
    "os.scandir": "read",
    "os.mkdir": "mkdir",
    "os.makedirs": "mkdir",
    "os.remove": "delete",
    "os.unlink": "delete",
    "os.rmdir": "delete",
    "os.rename": "write",
    "os.replace": "write",
    "os.chmod": "chmod",
    "os.symlink": "symlink",
    "os.link": "symlink",
    "shutil.copy": "write",
    "shutil.copy2": "write",
    "shutil.copyfile": "write",
    "shutil.copytree": "write",
    "shutil.move": "write",
}

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("api_key", re.compile(rb"(?i)(?:api[_-]?key|x-api-key)['\"\s:=]+([A-Za-z0-9_\-]{20,})")),
    ("ssh_key", re.compile(rb"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----")),
    ("password", re.compile(rb"(?i)password['\"\s:=]+([^\s'\"]{8,})")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
    ("github_pat_v2", re.compile(rb"github_pat_[A-Za-z0-9_]{60,}")),
    ("bearer_token", re.compile(rb"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})")),
    ("certificate", re.compile(rb"-----BEGIN CERTIFICATE-----")),
]


class Sink:
    def __init__(self, evidence_root: Path) -> None:
        self.root = evidence_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.t0 = time.monotonic_ns()
        self._lock = threading.Lock()
        self._buffers: dict[str, list[dict]] = {
            "network": [],
            "fs": [],
            "process": [],
            "secrets": [],
            "imports": [],
        }
        self._seen_imports: set[str] = set()

    def now_ms(self) -> int:
        return (time.monotonic_ns() - self.t0) // 1_000_000

    def record(self, stream: str, record: dict) -> None:
        with self._lock:
            self._buffers[stream].append(record)

    def flush(self) -> None:
        with self._lock:
            for stream, records in self._buffers.items():
                path = self.root / f"{stream}.jsonl"
                with path.open("a", encoding="utf-8") as fp:
                    for r in records:
                        fp.write(json.dumps(r, sort_keys=True, separators=(",", ":")))
                        fp.write("\n")
                self._buffers[stream] = []


def _filtered(path: str) -> bool:
    if not path:
        return True
    if path.startswith(_FILTER_PREFIXES):
        return True
    if path.endswith(_FILTER_SUFFIXES):
        return True
    return any(frag in path for frag in _FILTER_FRAGMENTS)


def _normalise(path: str) -> str:
    try:
        return os.path.normpath(os.fspath(path))
    except Exception:  # noqa: BLE001
        return str(path)


def _scan_secrets(path: Path, sink: Sink) -> None:
    if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        return
    try:
        data = path.read_bytes()
    except Exception:  # noqa: BLE001
        return
    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(data):
            start = max(0, match.start() - 25)
            end = min(len(data), match.end() + 25)
            ctx = data[start:end]
            sink.record(
                "secrets",
                {
                    "ts": sink.now_ms() / 1000.0,
                    "type": kind,
                    "pattern_matched": match.group(0).decode("utf-8", "replace")[:120],
                    "context_hash": "sha256:" + hashlib.sha256(ctx).hexdigest(),
                },
            )


def install_hooks(sink: Sink, bundle_root: Path) -> None:
    def audit(event: str, args: tuple) -> None:
        try:
            ts = sink.now_ms() / 1000.0
            if event in _FS_OP_AUDIT:
                if not args:
                    return
                first = args[0]
                if isinstance(first, bytes | bytearray):
                    try:
                        first = first.decode("utf-8", "replace")
                    except Exception:  # noqa: BLE001
                        return
                if isinstance(first, int):
                    return
                if not isinstance(first, str | os.PathLike):
                    return
                path = _normalise(str(first))
                if _filtered(path):
                    return
                op = _FS_OP_AUDIT[event]
                mode = None
                bytes_count = 0
                if event == "open" and len(args) >= 2:
                    mode_arg = args[1]
                    if isinstance(mode_arg, str) and any(c in mode_arg for c in ("w", "a", "x", "+")):
                        op = "write"
                if event == "os.chmod" and len(args) >= 2:
                    try:
                        mode = oct(int(args[1]))[-3:]
                    except Exception:  # noqa: BLE001
                        mode = None
                sink.record(
                    "fs",
                    {
                        "ts": ts,
                        "op": op,
                        "path": path,
                        "bytes": bytes_count,
                        "mode": mode,
                    },
                )
                if op == "read":
                    try:
                        candidate = Path(path)
                        if candidate.exists() and bundle_root in candidate.resolve().parents:
                            _scan_secrets(candidate, sink)
                    except Exception:  # noqa: BLE001, S110
                        pass
            elif event == "subprocess.Popen":
                if not args:
                    return
                argv = args[0]
                if isinstance(argv, list | tuple):
                    argv_list = [str(a) for a in argv]
                else:
                    argv_list = [str(argv)]
                cmd = argv_list[0] if argv_list else ""
                sink.record(
                    "process",
                    {
                        "ts": ts,
                        "pid": -1,
                        "ppid": os.getpid(),
                        "cmd": cmd,
                        "args": argv_list[1:],
                        "env_keys": sorted(os.environ.keys()),
                    },
                )
            elif event == "import":
                if not args:
                    return
                module = args[0] if isinstance(args[0], str) else ""
                if not module or module in sink._seen_imports:
                    return
                sink._seen_imports.add(module)
                try:
                    mod_obj = sys.modules.get(module)
                    file_attr = getattr(mod_obj, "__file__", None) if mod_obj else None
                    version = getattr(mod_obj, "__version__", None) if mod_obj else None
                except Exception:  # noqa: BLE001
                    file_attr = None
                    version = None
                is_stdlib = (
                    file_attr is None
                    or (isinstance(file_attr, str) and "/site-packages/" not in file_attr)
                )
                sink.record(
                    "imports",
                    {
                        "ts": ts,
                        "module": module,
                        "imported_from": file_attr or "",
                        "is_stdlib": bool(is_stdlib),
                        "version": str(version) if version else None,
                    },
                )
            elif event in ("socket.connect", "socket.bind"):
                if not args or len(args) < 2:
                    return
                sock = args[0]
                addr = args[1]
                proto = "tcp"
                try:
                    if hasattr(sock, "type") and sock.type == socket.SOCK_DGRAM:
                        proto = "udp"
                except Exception:  # noqa: BLE001, S110
                    pass
                dst_ip = None
                dst_port = 0
                if isinstance(addr, tuple) and len(addr) >= 2:
                    dst_ip = str(addr[0])
                    try:
                        dst_port = int(addr[1])
                    except Exception:  # noqa: BLE001
                        dst_port = 0
                sink.record(
                    "network",
                    {
                        "ts": ts,
                        "proto": proto,
                        "dst_ip": dst_ip or "",
                        "dst_port": dst_port,
                        "bytes_out": 0,
                        "bytes_in": 0,
                        "domain": None,
                    },
                )
            elif event in ("socket.gethostbyname", "socket.getaddrinfo"):
                if not args:
                    return
                host = args[0] if isinstance(args[0], str) else ""
                if host:
                    sink.record(
                        "network",
                        {
                            "ts": ts,
                            "proto": "dns",
                            "dst_ip": "",
                            "dst_port": 53,
                            "bytes_out": 0,
                            "bytes_in": 0,
                            "domain": host,
                        },
                    )
        except Exception:  # noqa: BLE001, S110
            return

    sys.addaudithook(audit)


def write_canary(bundle: Path, canary_val: str) -> Path:
    if not canary_val:
        return bundle / ".canary"
    target = bundle / ".canary"
    try:
        target.write_text(canary_val, encoding="utf-8")
    except Exception:  # noqa: BLE001, S110
        pass
    return target


def read_canary(target: Path) -> None:
    try:
        target.read_bytes()
    except Exception:  # noqa: BLE001, S110
        pass


def run_skill(bundle: Path, sink: Sink) -> int:
    entry = None
    for candidate in ("main.py", "skill.py", "__main__.py", "run.py"):
        p = bundle / candidate
        if p.is_file():
            entry = p
            break
    if entry is None:
        return 0
    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(entry)],
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("AGENT_TIMEOUT", "60")),
            cwd=str(bundle),
        )
        sink.record(
            "process",
            {
                "ts": sink.now_ms() / 1000.0,
                "pid": -1,
                "ppid": os.getpid(),
                "cmd": sys.executable,
                "args": [str(entry)],
                "env_keys": sorted(os.environ.keys()),
            },
        )
        return proc.returncode
    except subprocess.TimeoutExpired:
        return 124


def static_scan(bundle: Path, sink: Sink) -> None:
    for path in bundle.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle).as_posix()
        if _filtered(rel):
            continue
        if path.suffix.lower() in {".py", ".pyi", ".cfg", ".ini", ".toml", ".env", ".yaml", ".yml", ".json", ".txt", ".md"}:
            _scan_secrets(path, sink)
        if path.suffix.lower() == ".py":
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001, S112
                continue
            for module in re.findall(r"^(?:from\s+(\S+)|import\s+(\S+))", text, re.MULTILINE):
                mod = module[0] or module[1]
                mod = mod.split(".")[0].rstrip(",")
                if not mod or mod in sink._seen_imports:
                    continue
                sink._seen_imports.add(mod)
                sink.record(
                    "imports",
                    {
                        "ts": sink.now_ms() / 1000.0,
                        "module": mod,
                        "imported_from": rel,
                        "is_stdlib": True,
                        "version": None,
                    },
                )


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: tracer.py <bundle_path> <nonce> <evidence_dir>", file=sys.stderr)
        return 2
    bundle = Path(sys.argv[1]).resolve()
    nonce = sys.argv[2]
    evidence_root = Path(sys.argv[3]).resolve()
    canary_val = os.environ.get("CANARY_VAL", "")

    sink = Sink(evidence_root)
    canary_path = write_canary(bundle, canary_val)
    read_canary(canary_path)
    install_hooks(sink, bundle)
    static_scan(bundle, sink)
    code = run_skill(bundle, sink)
    sink.flush()
    _ = nonce
    return code


if __name__ == "__main__":
    sys.exit(main())
