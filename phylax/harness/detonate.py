from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

_CHILD = Path(__file__).resolve().parent / "_detonate_child.py"
_DEFAULT_TIMEOUT_S = 20

_SELF_NOISE = frozenset({"READ_FILE", "EXECUTE_SOURCE_CODE", "LIST_DIRECTORY"})


def _notable(caps) -> bool:
    return bool(set(caps or []) - _SELF_NOISE)


def _isolated_env(home: str) -> dict:
    env = {
        "HOME": home,
        "USERPROFILE": home,
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "PHYLAX_DETONATION": "1",
    }
    return {k: v for k, v in env.items() if v}


def _run_child(spec: dict, timeout_s: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="phylax-det-") as tmp:
        out = Path(tmp) / "_phylax_events.json"
        home = Path(tmp) / "home"
        home.mkdir()
        spec = dict(spec, out=str(out))
        try:
            subprocess.run(
                [sys.executable, str(_CHILD), json.dumps(spec)],
                capture_output=True,
                timeout=timeout_s,
                check=False,
                env=_isolated_env(str(home)),
                cwd=tmp,
            )
        except subprocess.TimeoutExpired:
            return {"capabilities": [], "events": [], "error": "timeout"}
        if not out.is_file():
            return {"capabilities": [], "events": [], "error": "no output"}
        try:
            return json.loads(out.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {"capabilities": [], "events": [], "error": "unreadable output"}


def _detonate_skill(artifact_dir: Path, timeout_s: int) -> dict:
    phases: dict[str, dict] = {}
    caps: set[str] = set()
    for script in sorted(artifact_dir.rglob("*.py")):
        rel = script.relative_to(artifact_dir).as_posix()
        res = _run_child({"mode": "script", "path": str(script),
                          "artifact_root": str(artifact_dir)}, timeout_s)
        phases[rel] = res
        caps.update(res.get("capabilities", []))
    return {"capabilities": sorted(caps), "phases": phases}


def _package_module(artifact_dir: Path) -> str | None:
    src = artifact_dir / "src"
    root = src if src.is_dir() else artifact_dir
    for child in sorted(root.iterdir()) if root.is_dir() else []:
        if child.is_dir() and (child / "__init__.py").is_file():
            return child.name
    return None


_NPM_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
_SHELL_MARKERS = ("|", "&&", ";", "curl", "wget", "bash", "sh -c", "powershell", "iwr")
_SPAWN_MARKERS = ("node", "python", "npx", "sh", "bash", "cmd")


def _tree_snapshot(root: Path) -> dict[str, tuple[int, int]]:
    snapshot: dict[str, tuple[int, int]] = {}
    if not root.is_dir():
        return snapshot
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
            key = str(path.relative_to(root))
        except (OSError, ValueError):
            continue
        snapshot[key] = (stat.st_size, int(stat.st_mtime))
        if len(snapshot) >= 20000:
            break
    return snapshot


def npm_scripts(artifact_dir: Path) -> dict[str, str]:
    manifest = artifact_dir / "package.json"
    if not manifest.is_file():
        return {}
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}
    scripts = document.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {
        hook: scripts[hook]
        for hook in _NPM_HOOKS
        if isinstance(scripts.get(hook), str) and scripts[hook].strip()
    }


def hook_capabilities(hook: str, command: str, changed: bool, removed: bool) -> set[str]:
    caps = {"INSTALL_HOOK_EXEC"}
    if hook == "postinstall":
        caps.add("POSTINSTALL_SCRIPT")
    lowered = command.lower()
    if any(marker in lowered for marker in _SHELL_MARKERS):
        caps.add("EXEC_SHELL")
    if any(marker in lowered for marker in _SPAWN_MARKERS):
        caps.add("CREATE_PROCESS")
    if changed:
        caps.add("WRITE_FILE")
    if removed:
        caps.add("DELETE_FILE")
    return caps


def _run_npm_hook(artifact_dir: Path, hook: str, command: str, timeout_s: int) -> dict:
    home = tempfile.mkdtemp(prefix="phylax-npm-home-")
    before = _tree_snapshot(artifact_dir)
    outcome: dict = {"hook": hook, "command": command[:400]}

    try:
        completed = subprocess.run(
            command,
            shell=True,
            cwd=str(artifact_dir),
            env=_isolated_env(home),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        outcome["exit_code"] = completed.returncode
        outcome["stdout"] = (completed.stdout or "")[:2000]
        outcome["stderr"] = (completed.stderr or "")[:2000]
        outcome["timed_out"] = False
    except subprocess.TimeoutExpired:
        outcome["exit_code"] = None
        outcome["timed_out"] = True
    except OSError as exc:
        outcome["exit_code"] = None
        outcome["error"] = str(exc)[:300]

    after = _tree_snapshot(artifact_dir)
    created = sorted(set(after) - set(before))[:200]
    modified = sorted(k for k in set(after) & set(before) if after[k] != before[k])[:200]
    removed = sorted(set(before) - set(after))[:200]

    outcome["created"] = created
    outcome["modified"] = modified
    outcome["removed"] = removed
    outcome["capabilities"] = sorted(
        hook_capabilities(hook, command, bool(created or modified), bool(removed))
    )
    return outcome


def _detonate_npm(artifact_dir: Path, timeout_s: int) -> dict:
    scripts = npm_scripts(artifact_dir)
    if not scripts:
        return {"capabilities": [], "phases": {}}

    phases: dict[str, dict] = {}
    caps: set[str] = set()
    for hook, command in scripts.items():
        result = _run_npm_hook(artifact_dir, hook, command, timeout_s)
        phases[f"npm_{hook}"] = result
        caps.update(result.get("capabilities", []))
    return {"capabilities": sorted(caps), "phases": phases}


def _detonate_package(artifact_dir: Path, timeout_s: int) -> dict:
    phases: dict[str, dict] = {}
    caps: set[str] = set()

    npm = _detonate_npm(artifact_dir, timeout_s)
    if npm["phases"]:
        phases.update(npm["phases"])
        caps.update(npm["capabilities"])

    if (artifact_dir / "setup.py").is_file():
        res = _run_child(
            {"mode": "setup_install", "artifact_dir": str(artifact_dir),
             "artifact_root": str(artifact_dir)}, timeout_s
        )
        phases["install_time"] = res
        caps.update(res.get("capabilities", []))
        if _notable(res.get("capabilities")):
            caps.add("INSTALL_HOOK_EXEC")
    module = _package_module(artifact_dir)
    if module:
        res = _run_child(
            {"mode": "import", "artifact_dir": str(artifact_dir), "module": module,
             "artifact_root": str(artifact_dir)},
            timeout_s,
        )
        phases["import_time"] = res
        caps.update(res.get("capabilities", []))
        if _notable(res.get("capabilities")):
            caps.add("IMPORT_SIDE_EFFECT")
    return {"capabilities": sorted(caps), "phases": phases}


def _detonate_mcp(artifact_dir: Path, timeout_s: int) -> dict:
    surface: list[dict] = []
    manifest = artifact_dir / "manifest.json"
    if manifest.is_file():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            data = {}
        for tool in data.get("tools") or []:
            if isinstance(tool, dict):
                surface.append({
                    "name": str(tool.get("name", "")),
                    "description": str(tool.get("description", "")),
                })
    phases: dict[str, dict] = {}
    caps: set[str] = set()
    server = artifact_dir / "server.py"
    if server.is_file():
        res = _run_child({"mode": "script", "path": str(server),
                          "artifact_root": str(artifact_dir)}, timeout_s)
        phases["server_load"] = res
        caps.update(res.get("capabilities", []))
    if surface:
        caps.add("EXPOSE_TOOL")
    return {"capabilities": sorted(caps), "phases": phases, "tool_surface": surface}


def detonate_artifact_bytes(
    track: str, artifact_b64: str, timeout_s: int = _DEFAULT_TIMEOUT_S
) -> dict:
    if track == "repositories" or not artifact_b64:
        return {"capabilities": [], "phases": {}, "track": track, "detonated": False}
    with tempfile.TemporaryDirectory(prefix="phylax-art-") as tmp:
        work = Path(tmp)
        try:
            data = base64.b64decode(artifact_b64)
        except (ValueError, TypeError):
            return {"capabilities": [], "phases": {}, "track": track,
                    "detonated": False, "error": "artifact decode failed"}
        target = work / "artifact"
        target.mkdir()
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                root = target.resolve()
                for member in zf.infolist():
                    dest = (target / member.filename).resolve()
                    if dest != root and root not in dest.parents:
                        continue
                    zf.extract(member, target)
        except zipfile.BadZipFile:
            return {"capabilities": [], "phases": {}, "track": track,
                    "detonated": False, "error": "artifact not a zip"}

        image = os.getenv("PHYLAX_SANDBOX_IMAGE", "").strip()
        if image:
            from phylax.harness.executor import detonate_in_docker

            result = detonate_in_docker(
                str(target), track,
                image=image,
                digest=os.getenv("PHYLAX_SANDBOX_DIGEST", "").strip(),
                cpu_budget_s=timeout_s,
            )
            result.setdefault("track", track)
            return result
        if os.getenv("PHYLAX_DEV_UNSAFE_EXECUTOR") != "1":
            return {"capabilities": [], "phases": {}, "track": track,
                    "detonated": False,
                    "error": "PHYLAX_SANDBOX_IMAGE unset; refusing to detonate outside the jail"}
        result = detonate(track, str(target), timeout_s)
        result["detonated"] = True
        return result


def detonate(track: str, artifact_dir: str, timeout_s: int = _DEFAULT_TIMEOUT_S) -> dict:
    path = Path(artifact_dir).resolve()
    if not path.is_dir():
        return {"capabilities": [], "phases": {}, "error": "artifact dir missing"}
    if track == "skills":
        result = _detonate_skill(path, timeout_s)
    elif track == "packages":
        result = _detonate_package(path, timeout_s)
    elif track == "mcp_servers":
        result = _detonate_mcp(path, timeout_s)
    else:
        return {"capabilities": [], "phases": {}, "error": f"track {track} is static"}
    result["track"] = track
    return result
