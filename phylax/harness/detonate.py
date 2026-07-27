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


def _detonate_package(artifact_dir: Path, timeout_s: int) -> dict:
    phases: dict[str, dict] = {}
    caps: set[str] = set()
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
