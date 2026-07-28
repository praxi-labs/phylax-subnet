from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from phylax.rounds import WALL_BACKSTOP_FACTOR

JAIL_NETWORK = os.getenv("PHYLAX_JAIL_NETWORK", "phylax-jail")
_MEMORY = "2g"
_CPUS = "1.0"
_PIDS = "256"

_INFRA_ERRORS = (
    "image pull failed",
    "container create failed",
    "container start failed",
    "task copy-in failed",
)


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def ensure_jail_network() -> None:
    inspect = _docker("network", "inspect", JAIL_NETWORK, timeout=15)
    if inspect.returncode == 0:
        return
    _docker("network", "create", "--internal", JAIL_NETWORK, timeout=30)


_PULLED: set[str] = set()


def _ensure_image(ref: str, timeout: int = 300) -> str:
    if ref in _PULLED:
        return ""
    pull = _docker("pull", ref, timeout=timeout)
    if pull.returncode != 0:
        return pull.stderr[-400:]
    _PULLED.add(ref)
    return ""


def _pin(image: str, digest: str) -> str:
    if not digest:
        return image
    base = image.split("@", 1)[0]
    if ":" in base.rsplit("/", 1)[-1]:
        base = base.rsplit(":", 1)[0]
    return f"{base}@{digest}"


def _observed_probe(cid: str, context: dict, work: Path) -> bool | None:
    probe = context.get("probe") or {}
    path = str(probe.get("file_path", "") or "")
    if not path.startswith("/task/"):
        return None
    target = work / "probe_file"
    cp = _docker("cp", f"{cid}:{path}", str(target), timeout=15)
    if cp.returncode != 0 or not target.exists():
        return False
    try:
        return target.read_text(encoding="utf-8") == str(probe.get("file_content", ""))
    except OSError:
        return False


def _running(cid: str) -> bool:
    r = _docker("inspect", "-f", "{{.State.Running}}", cid, timeout=10)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _exit_code(cid: str) -> str:
    r = _docker("inspect", "-f", "{{.State.ExitCode}}", cid, timeout=10)
    return r.stdout.strip() if r.returncode == 0 else "?"


def _cpu_seconds(cid: str) -> float | None:
    r = _docker("exec", cid, "cat", "/sys/fs/cgroup/cpu.stat", timeout=10)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("usage_usec"):
            try:
                return int(line.split()[1]) / 1_000_000
            except (IndexError, ValueError):
                return None
    return None


def _await_exit(cid: str, cpu_budget_s: int, wall_budget_s: float | None = None) -> dict | None:
    wall = WALL_BACKSTOP_FACTOR * cpu_budget_s
    if wall_budget_s is not None:
        wall = min(wall, max(1.0, wall_budget_s))
    deadline = time.monotonic() + wall
    interval = max(0.5, min(2.0, cpu_budget_s / 4))
    base: float | None = None
    while True:
        if not _running(cid):
            return None
        cpu = _cpu_seconds(cid)
        if cpu is not None:
            if base is None:
                base = cpu
            elif cpu - base > cpu_budget_s:
                _docker("kill", cid, timeout=15)
                return {"success": False, "error": "cpu budget exceeded"}
        if time.monotonic() > deadline:
            _docker("kill", cid, timeout=15)
            return {"success": False, "error": "wall backstop exceeded"}
        time.sleep(interval)


_DETONATE_DRIVER = (
    "import json,sys;"
    "from phylax.harness.detonate import detonate;"
    "json.dump(detonate(sys.argv[1], sys.argv[2], int(sys.argv[3])),"
    "open('/task/detonation.json','w'))"
)


def detonate_in_docker(
    artifact_dir: str,
    track: str,
    *,
    image: str,
    digest: str = "",
    cpu_budget_s: int = 30,
) -> dict:
    ensure_jail_network()
    ref = _pin(image, digest)
    pull_err = _ensure_image(ref)
    if pull_err:
        return {"capabilities": [], "phases": {}, "detonated": False,
                "error": f"image pull failed: {pull_err[-200:]}"}

    work = Path(tempfile.mkdtemp(prefix="phylax-det-"))
    task_dir = work / "task"
    task_dir.mkdir(parents=True)
    cid = None
    try:
        shutil.copytree(artifact_dir, task_dir / "artifact", dirs_exist_ok=True)
        create = _docker(
            "create",
            "--network", JAIL_NETWORK,
            "--cgroupns", "private",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
            "--memory", _MEMORY,
            "--memory-swap", _MEMORY,
            "--cpus", _CPUS,
            "--pids-limit", _PIDS,
            "--entrypoint", "python",
            ref,
            "-c", _DETONATE_DRIVER, track, "/task/artifact", str(cpu_budget_s),
            timeout=30,
        )
        if create.returncode != 0:
            return {"capabilities": [], "phases": {}, "detonated": False,
                    "error": f"container create failed: {create.stderr[-200:]}"}
        cid = create.stdout.strip()
        cp_in = _docker("cp", f"{task_dir}/.", f"{cid}:/task", timeout=60)
        if cp_in.returncode != 0:
            return {"capabilities": [], "phases": {}, "detonated": False,
                    "error": f"artifact copy-in failed: {cp_in.stderr[-200:]}"}
        start = _docker("start", cid, timeout=30)
        if start.returncode != 0:
            return {"capabilities": [], "phases": {}, "detonated": False,
                    "error": f"container start failed: {start.stderr[-200:]}"}
        outcome = _await_exit(cid, cpu_budget_s)
        if outcome is not None:
            return {"capabilities": [], "phases": {}, "detonated": False,
                    "error": outcome.get("error", "detonation halted")}
        out = work / "detonation.json"
        cp_out = _docker("cp", f"{cid}:/task/detonation.json", str(out), timeout=30)
        if cp_out.returncode != 0 or not out.exists():
            return {"capabilities": [], "phases": {}, "detonated": False,
                    "error": "detonation produced no result"}
        try:
            result = json.loads(out.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {"capabilities": [], "phases": {}, "detonated": False,
                    "error": "detonation result unreadable"}
        result["detonated"] = True
        return result
    except subprocess.TimeoutExpired:
        return {"capabilities": [], "phases": {}, "detonated": False,
                "error": "docker command timed out"}
    finally:
        if cid:
            _docker("rm", "-f", cid, timeout=30)
        shutil.rmtree(work, ignore_errors=True)


def run_agent_in_docker(
    agent_code: str,
    context: dict,
    *,
    image: str,
    digest: str = "",
    entrypoint: str = "agent_main",
    cpu_budget_s: int = 120,
    artifact_dir: str | None = None,
    wall_budget_s: float | None = None,
) -> dict:
    began = time.monotonic()

    def left(cap: int) -> int:
        if wall_budget_s is None:
            return cap
        return int(min(float(cap), wall_budget_s - (time.monotonic() - began)))

    if left(1) <= 0:
        return {"success": False, "error": "wall budget exhausted"}
    ensure_jail_network()
    ref = _pin(image, digest)

    pull_err = _ensure_image(ref, timeout=max(1, left(300)))
    if pull_err:
        return {"success": False, "error": f"image pull failed: {pull_err}"}

    work = Path(tempfile.mkdtemp(prefix="phylax-exec-"))
    task_dir = work / "task"
    task_dir.mkdir(parents=True)
    cid = None
    try:
        ctx = dict(context)
        ctx["entrypoint"] = entrypoint
        if artifact_dir and Path(artifact_dir).exists():
            shutil.copytree(artifact_dir, task_dir / "artifact", dirs_exist_ok=True)
            ctx["artifact_dir"] = "/task/artifact"
        workspace = task_dir / "workspace"
        workspace.mkdir()
        workspace.chmod(0o777)
        task_dir.chmod(0o777)
        (task_dir / "agent.py").write_text(agent_code, encoding="utf-8")
        (task_dir / "context.json").write_text(json.dumps(ctx), encoding="utf-8")

        proxy_url = os.getenv("PHYLAX_INFERENCE_PROXY_URL", "")
        create = _docker(
            "create",
            "--network", JAIL_NETWORK,
            "--cgroupns", "private",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
            "--memory", _MEMORY,
            "--memory-swap", _MEMORY,
            "--cpus", _CPUS,
            "--pids-limit", _PIDS,
            "-e", "PHYLAX_TASK_DIR=/task",
            "-e", "PHYLAX_AGENT_PATH=/task/agent.py",
            "-e", f"PHYLAX_INFERENCE_PROXY_URL={proxy_url}",
            ref,
            timeout=30,
        )
        if create.returncode != 0:
            return {"success": False, "error": f"container create failed: {create.stderr[-400:]}"}
        cid = create.stdout.strip()

        cp_in = _docker("cp", f"{task_dir}/.", f"{cid}:/task", timeout=max(1, left(60)))
        if cp_in.returncode != 0:
            return {"success": False, "error": f"task copy-in failed: {cp_in.stderr[-400:]}"}

        start = _docker("start", cid, timeout=max(1, left(30)))
        if start.returncode != 0:
            return {"success": False, "error": f"container start failed: {start.stderr[-400:]}"}

        outcome = _await_exit(cid, cpu_budget_s, left(10_000))
        if outcome is not None:
            return outcome

        out = work / "result.json"
        cp_out = _docker("cp", f"{cid}:/task/result.json", str(out), timeout=max(1, left(30)))
        if cp_out.returncode != 0 or not out.exists():
            logs = _docker("logs", "--tail", "50", cid, timeout=max(1, left(15)))
            return {
                "success": False,
                "error": f"no result.json (rc={_exit_code(cid)})",
                "stderr": (logs.stderr or logs.stdout)[-1500:],
            }
        try:
            report = json.loads(out.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {"success": False, "error": "malformed result.json"}
        if not isinstance(report, dict):
            return {"success": False, "error": "malformed result.json"}
        report["observed_probe_file"] = _observed_probe(cid, context, work)
        return report
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "docker command timed out"}
    finally:
        if cid:
            _docker("rm", "-f", cid, timeout=max(1, left(30)))
        shutil.rmtree(work, ignore_errors=True)
