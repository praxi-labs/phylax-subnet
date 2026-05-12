"""
docker/harness/run.py

In-sandbox harness. Runs INSIDE the phylax-sandbox container, NOT on the miner host.

Responsibilities:
  1. Find the skill's entry point (manifest.json or heuristic detection)
  2. Invoke it with synthetic inputs
  3. Record observed behaviour (filesystem, network, process, secrets) as JSONL
  4. Exit cleanly so the miner can read /evidence/*.jsonl

This is intentionally minimal — production deployments should add eBPF hooks
or syscall-level instrumentation for stronger evidence.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import traceback
from pathlib import Path

EVIDENCE_DIR = Path(os.getenv("PHYLAX_EVIDENCE_DIR", "/evidence"))
SKILL_DIR    = Path(os.getenv("PHYLAX_SKILL_DIR", "/skill"))


def emit(stream: str, record: dict) -> None:
    """Append a JSON record to /evidence/<stream>.jsonl."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE_DIR / f"{stream}.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def install_hooks() -> None:
    """Monkey-patch common APIs so we observe what the skill calls."""
    import builtins
    import http.client
    import urllib.request

    real_open = builtins.open

    def traced_open(file, mode="r", *args, **kwargs):
        op = "write" if any(m in mode for m in ("w", "a", "x")) else "read"
        emit("fs", {"op": op, "path": str(file), "mode": mode, "ts": time.time()})
        return real_open(file, mode, *args, **kwargs)

    builtins.open = traced_open

    real_connect = socket.socket.connect

    def traced_connect(self, addr):
        try:
            host, port = addr[0], addr[1]
        except Exception:
            host, port = str(addr), None
        emit("network", {"op": "connect", "ip": host, "port": port, "ts": time.time()})
        return real_connect(self, addr)

    socket.socket.connect = traced_connect

    real_getenv = os.environ.get

    def traced_getenv(name, default=None):
        emit("secrets", {"op": "env_get", "var": name, "ts": time.time()})
        return real_getenv(name, default)

    os.environ.get = traced_getenv  # type: ignore

    real_popen = subprocess.Popen.__init__

    def traced_popen(self, args, *a, **kw):
        cmd = args if isinstance(args, str) else " ".join(map(str, args))
        emit("process", {"op": "spawn", "cmd": cmd, "ts": time.time()})
        return real_popen(self, args, *a, **kw)

    subprocess.Popen.__init__ = traced_popen


def find_entrypoint() -> Path | None:
    """Prefer manifest.json's `entry`, else fall back to common defaults."""
    manifest = SKILL_DIR / "manifest.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            entry = data.get("entry") or data.get("main")
            if entry:
                p = SKILL_DIR / entry
                if p.exists():
                    return p
        except Exception:
            pass

    for candidate in ("main.py", "skill.py", "entry.py", "src/main.py", "src/skill.py"):
        p = SKILL_DIR / candidate
        if p.exists():
            return p
    return None


def main() -> int:
    install_hooks()
    sys.path.insert(0, str(SKILL_DIR))

    entry = find_entrypoint()
    if entry is None:
        emit("process", {"op": "no_entry", "ts": time.time()})
        return 0

    try:
        exec(compile(entry.read_text(encoding="utf-8"), str(entry), "exec"), {"__name__": "__main__"})
    except SystemExit:
        pass
    except Exception as e:
        emit("process", {"op": "error", "error": str(e), "trace": traceback.format_exc(), "ts": time.time()})
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
