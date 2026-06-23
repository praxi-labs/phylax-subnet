from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import multiprocessing
import traceback

DEFAULT_TIMEOUT_SECONDS = 20 * 60
DEFAULT_ENTRYPOINT = "agent_main"
_LOG_TAIL = 8000


def _load_entrypoint(agent_path: str, entrypoint: str):
    spec = importlib.util.spec_from_file_location("phylax_agent", agent_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load agent from {agent_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, entrypoint, None)
    if not callable(fn):
        raise AttributeError(f"agent does not define a callable '{entrypoint}'")
    return fn


def _run(agent_path: str, entrypoint: str, context: dict, queue) -> None:
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            report = _load_entrypoint(agent_path, entrypoint)(context)
            json.dumps(report)
            resp = {"success": True, "report": report}
    except Exception as exc:  # noqa: BLE001
        resp = {"success": False, "error": str(exc), "traceback": traceback.format_exc()}
    resp["stdout"] = out.getvalue()[-_LOG_TAIL:]
    resp["stderr"] = err.getvalue()[-_LOG_TAIL:]
    queue.put(resp)


def run_agent(
    agent_path: str,
    context: dict,
    *,
    entrypoint: str = DEFAULT_ENTRYPOINT,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    queue: multiprocessing.Queue = multiprocessing.Queue()
    proc = multiprocessing.Process(
        target=_run, args=(agent_path, entrypoint, context, queue)
    )
    proc.start()
    proc.join(timeout_seconds)

    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join()
        return {"success": False, "error": "agent timeout", "stdout": "", "stderr": ""}

    try:
        return queue.get(timeout=5)
    except Exception:  # noqa: BLE001
        return {"success": False, "error": "no result returned", "stdout": "", "stderr": ""}
