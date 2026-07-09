from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

JAIL_NETWORK = os.getenv("PHYLAX_JAIL_NETWORK", "phylax-jail")
_MEMORY = os.getenv("PHYLAX_SANDBOX_MEMORY", "1g")
_CPUS = os.getenv("PHYLAX_SANDBOX_CPUS", "1.0")
_PIDS = os.getenv("PHYLAX_SANDBOX_PIDS", "256")


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


def run_agent_in_docker(
    agent_code: str,
    context: dict,
    *,
    image: str,
    digest: str = "",
    entrypoint: str = "agent_main",
    timeout: int = 120,
    artifact_dir: str | None = None,
) -> dict:
    ensure_jail_network()
    ref = _pin(image, digest)

    pull = _docker("pull", ref, timeout=300)
    if pull.returncode != 0:
        return {"success": False, "error": f"image pull failed: {pull.stderr[-400:]}"}

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
        (task_dir / "workspace").mkdir()
        (task_dir / "agent.py").write_text(agent_code, encoding="utf-8")
        (task_dir / "context.json").write_text(json.dumps(ctx), encoding="utf-8")

        create = _docker(
            "create",
            "--network", JAIL_NETWORK,
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
            "--memory", _MEMORY,
            "--memory-swap", _MEMORY,
            "--cpus", _CPUS,
            "--pids-limit", _PIDS,
            "-e", "PHYLAX_TASK_DIR=/task",
            ref,
            timeout=30,
        )
        if create.returncode != 0:
            return {"success": False, "error": f"container create failed: {create.stderr[-400:]}"}
        cid = create.stdout.strip()

        cp_in = _docker("cp", f"{task_dir}/.", f"{cid}:/task", timeout=60)
        if cp_in.returncode != 0:
            return {"success": False, "error": f"task copy-in failed: {cp_in.stderr[-400:]}"}

        try:
            run = _docker("start", "-a", cid, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "agent execution timed out"}

        out = work / "result.json"
        cp_out = _docker("cp", f"{cid}:/task/result.json", str(out), timeout=30)
        if cp_out.returncode != 0 or not out.exists():
            return {
                "success": False,
                "error": f"no result.json (rc={run.returncode})",
                "stderr": run.stderr[-1500:],
            }
        report = json.loads(out.read_text(encoding="utf-8"))
        report["observed_probe_file"] = _observed_probe(cid, context, work)
        return report
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "agent execution timed out"}
    finally:
        if cid:
            _docker("rm", "-f", cid, timeout=30)
        shutil.rmtree(work, ignore_errors=True)
