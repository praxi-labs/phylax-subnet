from __future__ import annotations

import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path

TASK_DIR = Path(os.getenv("PHYLAX_TASK_DIR", "/task"))


def _load_entrypoint(agent_path: str, entrypoint: str):
    spec = importlib.util.spec_from_file_location("phylax_agent", agent_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load agent at {agent_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, entrypoint)


def main() -> int:
    context = json.loads((TASK_DIR / "context.json").read_text(encoding="utf-8"))
    agent_path = os.getenv("PHYLAX_AGENT_PATH", "/task/agent.py")
    entrypoint = context.get("entrypoint", "agent_main")
    try:
        fn = _load_entrypoint(agent_path, entrypoint)
        report = fn(context)
        result = {"success": True, "report": report}
    except Exception as exc:  # noqa: BLE001
        result = {"success": False, "error": str(exc), "trace": traceback.format_exc()}
    (TASK_DIR / "result.json").write_text(json.dumps(result), encoding="utf-8")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
