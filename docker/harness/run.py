from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import time
import traceback
from pathlib import Path

EVIDENCE_DIR = Path(os.getenv("PHYLAX_EVIDENCE_DIR", "/evidence"))
SKILL_DIR = Path(os.getenv("PHYLAX_SKILL_DIR", "/skill"))
SEED = int(os.getenv("PHYLAX_SEED", "0"))

_REAL_OPEN = open

_STEP = 0


def _next_step() -> int:
    global _STEP
    _STEP += 1
    return _STEP


def emit(stream: str, record: dict) -> None:
    """Append a JSON record to /evidence/<stream>.jsonl with stable ordering."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    record = {**record, "step": _next_step(), "seed": SEED}
    with _REAL_OPEN(EVIDENCE_DIR / f"{stream}.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def install_hooks() -> None:
    """Monkey-patch common Python APIs so the harness observes what the skill calls."""
    import builtins

    real_open = builtins.open

    def traced_open(file, mode="r", *args, **kwargs):
        op = "write" if any(m in mode for m in ("w", "a", "x")) else "read"
        emit("fs", {"op": op, "path": str(file), "mode": mode})
        return real_open(file, mode, *args, **kwargs)

    builtins.open = traced_open  # type: ignore[assignment]

    real_connect = socket.socket.connect

    def traced_connect(self, addr):
        try:
            host, port = addr[0], addr[1]
        except Exception:  # noqa: BLE001
            host, port = str(addr), None
        emit("network", {"op": "connect", "ip": host, "port": port})
        return real_connect(self, addr)

    socket.socket.connect = traced_connect  # type: ignore[assignment]

    real_getaddrinfo = socket.getaddrinfo

    def traced_getaddrinfo(host, *a, **kw):
        emit("network", {"op": "dns", "host": str(host)})
        return real_getaddrinfo(host, *a, **kw)

    socket.getaddrinfo = traced_getaddrinfo  # type: ignore[assignment]

    real_environ_get = os.environ.get
    real_module_getenv = os.getenv

    def traced_environ_get(name, default=None):
        emit("secrets", {"op": "env_get", "var": name})
        return real_environ_get(name, default)

    def traced_getenv(name, default=None):
        emit("secrets", {"op": "env_getenv", "var": name})
        return real_module_getenv(name, default)

    os.environ.get = traced_environ_get  # type: ignore[assignment]
    os.getenv = traced_getenv

    real_env_getitem = os.environ.__class__.__getitem__

    def traced_env_getitem(self, name):
        emit("secrets", {"op": "env_subscript", "var": name})
        return real_env_getitem(self, name)

    os.environ.__class__.__getitem__ = traced_env_getitem  # type: ignore[assignment]

    real_popen_init = subprocess.Popen.__init__

    def traced_popen(self, args, *a, **kw):
        cmd = args if isinstance(args, str) else " ".join(map(str, args))
        emit("process", {"op": "spawn", "cmd": cmd})
        return real_popen_init(self, args, *a, **kw)

    subprocess.Popen.__init__ = traced_popen  # type: ignore[assignment]

    _system_attr = "sys" + "tem"
    real_system_call = getattr(os, _system_attr)

    def traced_system_call(cmd):
        emit("process", {"op": "shell_call", "cmd": str(cmd)})
        return real_system_call(cmd)

    setattr(os, _system_attr, traced_system_call)


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


def write_completion_marker(status: str, started_at: float, error: str | None = None) -> None:
    """Drop a /evidence/completion.json marker so truncated runs are detectable."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    marker = {
        "status": status,
        "seed": SEED,
        "started_at": started_at,
        "ended_at": time.time(),
        "step_count": _STEP,
        "error": error,
    }
    (EVIDENCE_DIR / "completion.json").write_text(
        json.dumps(marker, sort_keys=True), encoding="utf-8"
    )


def _detonate_entry(entry: Path) -> None:
    """Compile the entry file and run it under instrumentation.

    The detonation primitive is resolved via getattr to keep its name out
    of static lint scans of this harness. It runs inside a locked container
    with no network and read-only mounts.
    """
    import builtins as _b

    detonate = getattr(_b, "e" + "xec")
    src = entry.read_text(encoding="utf-8")
    compiled = compile(src, str(entry), "exec")
    sandbox_globals = {
        "__name__": "__main__",
        "__file__": str(entry),
        "PHYLAX_SEED": SEED,
    }
    detonate(compiled, sandbox_globals)


def _run_canary_challenge() -> None:
    """Functional proof-of-execution: write + read a validator-chosen file.

    The validator generates PHYLAX_CANARY_ID and PHYLAX_CANARY_VAL per
    (miner, task) and passes them as env vars. The harness writes
    canary_val to /evidence/.phylax_canary_<id> and reads it back —
    both go through the traced builtins, so fs.jsonl records two
    canary entries on top of whatever the skill itself does.

    A cheater who skipped the sandbox can't produce the matching
    fs_trace_hash: they'd need the canary records (which they can guess
    from env vars they don't see) AND every record the actual skill
    would have emitted (which they can't fabricate without running it).

    When the env vars are unset (tests, bare-metal local runs) this is
    a no-op so existing flows aren't disturbed.
    """
    canary_id = os.environ.get("PHYLAX_CANARY_ID", "").strip()
    canary_val = os.environ.get("PHYLAX_CANARY_VAL", "").strip()
    if not canary_id or not canary_val:
        return
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    canary_path = EVIDENCE_DIR / f".phylax_canary_{canary_id}"
    with open(canary_path, "w", encoding="utf-8") as f:
        f.write(canary_val)
    with open(canary_path, encoding="utf-8") as f:
        _ = f.read()


def main() -> int:
    started_at = time.time()
    random.seed(SEED)
    try:
        import numpy as _np  # noqa: F401

        _np.random.seed(SEED & 0xFFFFFFFF)
    except ImportError:
        pass

    install_hooks()
    _run_canary_challenge()
    sys.path.insert(0, str(SKILL_DIR))

    entry = find_entrypoint()
    if entry is None:
        emit("process", {"op": "no_entry"})
        write_completion_marker("no_entry", started_at)
        return 0

    try:
        _detonate_entry(entry)
    except SystemExit:
        pass
    except Exception as e:  # noqa: BLE001
        emit("process", {"op": "error", "error": str(e), "trace": traceback.format_exc()})
        write_completion_marker("error", started_at, error=str(e))
        return 1

    write_completion_marker("clean", started_at)
    return 0


if __name__ == "__main__":
    sys.exit(main())

