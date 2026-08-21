"""The execution layer behind the customer engine.

The backend resolves champions and asks this service to run them. It fetches
each agent from the backend under its own signature, packs the submitted files
into an artifact, and runs the agent in the same jail validators use. Nothing
here trusts the agent: it is the identical sandbox, the identical pinned image,
and the identical budgets that a scored round applies.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import logging
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor

import bittensor as bt
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from phylax.harness.runner import InfraFailure, run_task
from phylax.server_client import PhylaxServerClient

log = logging.getLogger("phylax.sandbox")

MAX_FILES = 400
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024

CPU_BUDGET_S = int(os.getenv("PHYLAX_SANDBOX_CPU_BUDGET", "120"))
WALL_BUDGET_S = float(os.getenv("PHYLAX_SANDBOX_WALL_BUDGET", "180"))
WORKERS = max(1, int(os.getenv("PHYLAX_SANDBOX_WORKERS", "4")))

_pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="sandbox")


class RunRequest(BaseModel):
    track: str = Field(min_length=1, max_length=32)
    hotkey: str = Field(min_length=8, max_length=64)
    agent_hash: str = Field(default="", max_length=80)
    files: dict[str, str] = Field(min_length=1)


def _token_guard(x_phylax_sandbox_token: str = Header(default="")) -> None:
    expected = os.getenv("PHYLAX_SANDBOX_TOKEN", "")
    if not expected:
        return
    if not hmac.compare_digest(expected, x_phylax_sandbox_token or ""):
        raise HTTPException(status_code=401, detail="bad sandbox token")


def pack(files: dict[str, str]) -> bytes:
    """Zip the submitted files, refusing anything that escapes the root.

    The extractor on the other side rejects traversal too, but a path like
    ../../etc is a sign of a hostile submission and is worth refusing at the
    door rather than silently dropping later.
    """
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=413, detail=f"at most {MAX_FILES} files")
    total = 0
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, body in files.items():
            clean = path.replace("\\", "/").lstrip("/")
            if not clean or ".." in clean.split("/"):
                raise HTTPException(status_code=400, detail=f"unsafe path {path!r}")
            raw = body.encode("utf-8", "replace")
            if len(raw) > MAX_FILE_BYTES:
                raise HTTPException(status_code=413, detail=f"{path} is too large")
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise HTTPException(status_code=413, detail="artifact is too large")
            archive.writestr(clean, raw)
    return buffer.getvalue()


def create_app(server: PhylaxServerClient, hotkey_ss58: str) -> FastAPI:
    app = FastAPI(title="phylax-sandbox", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True, "hotkey": hotkey_ss58, "workers": WORKERS}

    @app.post("/v1/run", dependencies=[Depends(_token_guard)])
    async def run(payload: RunRequest) -> dict:
        blob = pack(payload.files)
        runnable = server.get_runnable_agent(payload.hotkey)
        if not runnable or not runnable.get("code"):
            raise HTTPException(status_code=404, detail="agent not runnable")
        if payload.agent_hash:
            got = hashlib.sha256(runnable["code"].encode("utf-8")).hexdigest()
            want = payload.agent_hash.split(":", 1)[-1]
            if got != want:
                raise HTTPException(
                    status_code=409, detail="agent code does not match the champion hash"
                )

        nonce = hashlib.sha256(blob).hexdigest()
        dispatch = {
            "track": payload.track,
            "artifact_b64": base64.b64encode(blob).decode("ascii"),
            "nonce": nonce,
            "probe": {},
            "observed": {},
        }

        import asyncio

        loop = asyncio.get_running_loop()
        try:
            report = await loop.run_in_executor(
                _pool,
                lambda: run_task(
                    dispatch,
                    runnable,
                    cpu_budget_s=CPU_BUDGET_S,
                    wall_budget_s=WALL_BUDGET_S,
                ),
            )
        except InfraFailure as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        if report is None:
            raise HTTPException(status_code=422, detail="agent produced no report")
        return {"report": report, "nonce": nonce}

    return app


def build(argv=None) -> FastAPI:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wallet.name", dest="wallet_name", default="default")
    parser.add_argument("--wallet.hotkey", dest="wallet_hotkey", default="default")
    args, _ = parser.parse_known_args(argv)

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)
    url = os.getenv("PHYLAX_SERVER_URL", "").strip()
    if not url:
        raise SystemExit("PHYLAX_SERVER_URL is required")
    server = PhylaxServerClient(
        base_url=url,
        wallet=wallet,
        expected_server_hotkey=os.getenv("PHYLAX_SERVER_HOTKEY", "").strip() or None,
    )
    return create_app(server, wallet.hotkey.ss58_address)


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=os.getenv("PHYLAX_LOG_LEVEL", "INFO"),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    if not os.getenv("PHYLAX_SANDBOX_IMAGE"):
        raise SystemExit("PHYLAX_SANDBOX_IMAGE is required; agents never run unjailed")
    uvicorn.run(
        build(),
        host=os.getenv("PHYLAX_SANDBOX_HOST", "0.0.0.0"),
        port=int(os.getenv("PHYLAX_SANDBOX_PORT", "8910")),
    )


if __name__ == "__main__":
    main()
