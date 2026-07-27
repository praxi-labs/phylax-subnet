from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

TASK_DIR = Path(os.getenv("PHYLAX_TASK_DIR", "/task"))
RUNNER = Path(__file__).resolve().parent / "_agent_runner.py"
TRACE_PATH = TASK_DIR / "_validator_trace.jsonl"
REPORT_PATH = TASK_DIR / "_agent_report.json"


def _read_trace() -> list[dict]:
    events: list[dict] = []
    if not TRACE_PATH.is_file():
        return events
    with TRACE_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def main() -> int:
    env = dict(os.environ)
    env["PHYLAX_TRACE_PATH"] = str(TRACE_PATH)
    timeout = int(os.getenv("PHYLAX_AGENT_TIMEOUT", "0") or 0) or None
    error = ""
    try:
        subprocess.run(
            [sys.executable, str(RUNNER)], env=env, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        error = "agent exceeded its time budget"

    result = {"success": False, "error": error or "agent produced no report"}
    if REPORT_PATH.is_file():
        try:
            result = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        except ValueError:
            result = {"success": False, "error": "agent report was not valid json"}

    result["validator_trace"] = _read_trace()
    (TASK_DIR / "result.json").write_text(json.dumps(result), encoding="utf-8")
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
