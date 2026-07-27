from __future__ import annotations

import importlib.util
import json
import os
import sys
import traceback

_STREAM = [None]
_ARMED = [False]
_COUNT = [0]
_MAX_EVENTS = 4000


def _emit(kind: str, payload: dict) -> None:
    if not _ARMED[0] or _STREAM[0] is None or _COUNT[0] >= _MAX_EVENTS:
        return
    _COUNT[0] += 1
    try:
        _STREAM[0].write(json.dumps({"kind": kind, **payload}) + "\n")
        _STREAM[0].flush()
    except Exception:
        return


def _hook(event: str, args) -> None:
    if not _ARMED[0]:
        return
    try:
        if event == "open":
            _emit("fs", {"path": str(args[0])[:400], "mode": str(args[1] or "")})
        elif event == "socket.getaddrinfo":
            _emit("net", {"host": str(args[0])[:300]})
        elif event == "socket.connect":
            _emit("net", {"peer": str(args[1])[:300]})
        elif event == "urllib.Request":
            _emit("net", {"url": str(args[0])[:400]})
        elif event == "subprocess.Popen":
            _emit("proc", {"cmd": str(args[0])[:400], "args": str(args[1])[:400]})
        elif event == "os.system":
            _emit("proc", {"cmd": str(args[0])[:400]})
    except Exception:
        return


def _load(agent_path: str, entrypoint: str):
    spec = importlib.util.spec_from_file_location("phylax_agent", agent_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load agent at {agent_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, entrypoint)


def main() -> int:
    task_dir = os.getenv("PHYLAX_TASK_DIR", "/task")
    trace_path = os.environ["PHYLAX_TRACE_PATH"]
    agent_path = os.getenv("PHYLAX_AGENT_PATH", "/task/agent.py")
    with open(os.path.join(task_dir, "context.json"), encoding="utf-8") as fh:
        context = json.load(fh)
    entrypoint = context.get("entrypoint", "agent_main")

    stream = open(trace_path, "a", encoding="utf-8")
    _STREAM[0] = stream
    sys.addaudithook(_hook)
    _ARMED[0] = True
    try:
        report = _load(agent_path, entrypoint)(context)
        result = {"success": True, "report": report}
    except BaseException as exc:  # noqa: BLE001
        result = {
            "success": False,
            "error": str(exc)[:400],
            "trace": traceback.format_exc(limit=3)[-800:],
        }
    _ARMED[0] = False
    with open(os.path.join(task_dir, "_agent_report.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
