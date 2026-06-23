from __future__ import annotations

import io
import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from phylax.harness.agent_sandbox import run_agent
from phylax.harness.executor import run_agent_in_docker

_MAX_ARTIFACT_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


def _download(url: str, log: Callable[[str], None] | None) -> bytes | None:
    import httpx

    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.content
    except Exception as exc:  # noqa: BLE001
        if log:
            log(f"artifact download failed {url}: {exc}")
        return None


def materialise_artifact(
    url: str | None, work_dir: Path, log: Callable[[str], None] | None = None
) -> Path:
    artifact_dir = work_dir / "artifact"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if not url:
        return artifact_dir
    data = _download(url, log)
    if not data:
        return artifact_dir
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if sum(m.file_size for m in zf.infolist()) > _MAX_ARTIFACT_UNCOMPRESSED_BYTES:
                if log:
                    log("artifact exceeds uncompressed cap; skipping extraction")
                return artifact_dir
            root = artifact_dir.resolve()
            for member in zf.infolist():
                target = (artifact_dir / member.filename).resolve()
                if target != root and root not in target.parents:
                    if log:
                        log(f"rejected unsafe artifact path: {member.filename}")
                    continue
                zf.extract(member, artifact_dir)
    except zipfile.BadZipFile:
        (artifact_dir / "artifact.bin").write_bytes(data)
    return artifact_dir


def run_task(
    dispatch: dict,
    runnable: dict,
    *,
    log: Callable[[str], None] | None = None,
) -> dict | None:
    work_dir = Path(tempfile.mkdtemp(prefix="phylax-run-"))
    try:
        artifact_dir = materialise_artifact(dispatch.get("artifact_url"), work_dir, log)
        agent_path = work_dir / "agent.py"
        agent_path.write_text(runnable.get("code", ""), encoding="utf-8")

        context = {
            "artifact_dir": str(artifact_dir),
            "track": dispatch.get("track", ""),
            "nonce": dispatch.get("nonce", ""),
            "probe": dispatch.get("probe", {}),
            "inference": {
                "api": os.getenv("PHYLAX_INFERENCE_PROXY_URL", ""),
                "api_key": runnable.get("execution_api_key", ""),
                "provider": runnable.get("inference_provider", ""),
                "model": runnable.get("inference_model", ""),
            },
            "sandbox": {
                "image": runnable.get("sandbox_image", ""),
                "digest": runnable.get("sandbox_digest", ""),
            },
        }

        entrypoint = runnable.get("entrypoint", "agent_main")
        image = context["sandbox"]["image"]
        timeout = int(os.getenv("PHYLAX_AGENT_TIMEOUT", "120"))
        if os.getenv("PHYLAX_EXECUTOR", "sandbox") == "docker" and image:
            report = run_agent_in_docker(
                runnable.get("code", ""),
                context,
                image=image,
                digest=context["sandbox"]["digest"],
                entrypoint=entrypoint,
                timeout=timeout,
                artifact_dir=str(artifact_dir),
            )
        else:
            report = run_agent(str(agent_path), context, entrypoint=entrypoint)

        if not report.get("success"):
            if log:
                log(f"agent run failed: {report.get('error')}")
            return None

        body = report.get("report") or {}
        verdict = body.get("verdict") or {}
        if isinstance(verdict, str):
            verdict = {"decision": verdict, "risk_score": 0}
        return {
            "verdict": verdict,
            "evidence": body.get("evidence") or {},
            "findings": body.get("findings") or [],
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
