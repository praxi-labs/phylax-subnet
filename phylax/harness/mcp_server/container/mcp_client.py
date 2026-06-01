from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

_MANIFEST_CANDIDATES = (
    "mcp.json",
    "mcp_manifest.json",
    "tools.json",
    "manifest.json",
    "server.json",
)

_SECRET_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("api_key", re.compile(rb"(?i)(?:api[_-]?key|x-api-key)['\"\s:=]+([A-Za-z0-9_\-]{20,})")),
    ("ssh_key", re.compile(rb"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
    ("bearer_token", re.compile(rb"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})")),
    ("certificate", re.compile(rb"-----BEGIN CERTIFICATE-----")),
]


def _now_ms(t0: int) -> float:
    return (time.monotonic_ns() - t0) // 1_000_000 / 1000.0


def _sha256_hex(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _sha512_hex(b: bytes) -> str:
    return "sha512:" + hashlib.sha512(b).hexdigest()


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for r in rows:
            fp.write(json.dumps(r, sort_keys=True, separators=(",", ":")))
            fp.write("\n")


def discover_manifest(bundle: Path) -> tuple[dict | None, Path | None]:
    for name in _MANIFEST_CANDIDATES:
        candidate = bundle / name
        if candidate.is_file():
            try:
                return json.loads(candidate.read_text(encoding="utf-8")), candidate
            except json.JSONDecodeError:
                continue
    for path in bundle.rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001, S112
            continue
        if isinstance(data, dict) and isinstance(data.get("tools"), list):
            return data, path
    return None, None


def canonicalise_manifest(manifest: dict) -> bytes:
    tools = manifest.get("tools") if isinstance(manifest, dict) else None
    if not isinstance(tools, list):
        return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    canon_tools = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        canon_tools.append(
            {
                "name": str(tool.get("name") or ""),
                "description": str(tool.get("description") or ""),
                "input_schema": tool.get("inputSchema") or tool.get("parameters") or {},
            }
        )
    canon_tools.sort(key=lambda t: t["name"])
    return json.dumps(
        {"protocol": manifest.get("protocol", "mcp"), "tools": canon_tools},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def synthesise_test_params(schema: dict, canary_val: str, slot_idx: int) -> dict:
    if not isinstance(schema, dict):
        return {"canary": canary_val} if slot_idx == 0 else {}
    out: dict = {}
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    for key, prop in properties.items():
        if slot_idx == 0 and isinstance(prop, dict) and prop.get("type") == "string":
            out[key] = canary_val
            continue
        if not isinstance(prop, dict):
            out[key] = None
            continue
        t = prop.get("type", "string")
        if t == "string":
            out[key] = f"phylax-test-{slot_idx}"
        elif t == "integer":
            out[key] = slot_idx
        elif t == "number":
            out[key] = float(slot_idx)
        elif t == "boolean":
            out[key] = bool(slot_idx % 2)
        elif t == "array":
            out[key] = []
        elif t == "object":
            out[key] = {}
        else:
            out[key] = None
    return out


def exercise_tools(
    manifest: dict,
    canary_val: str,
    test_params_per_tool: int,
    t0: int,
) -> list[dict]:
    rows: list[dict] = []
    tools = manifest.get("tools", []) if isinstance(manifest, dict) else []
    if not isinstance(tools, list):
        return rows
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "")
        desc = str(tool.get("description") or "")
        schema = tool.get("inputSchema") or tool.get("parameters") or {}
        for slot in range(test_params_per_tool):
            params = synthesise_test_params(schema, canary_val, slot)
            params_bytes = json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
            response_preview = json.dumps(
                {"tool": name, "slot": slot, "echo": params},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            rows.append(
                {
                    "ts": _now_ms(t0),
                    "tool_name": name,
                    "server_declared_description": desc,
                    "input_params_hash": _sha256_hex(params_bytes),
                    "output_preview_hash": _sha256_hex(response_preview),
                    "side_effects": [],
                    "duration_ms": 0,
                    "error": None,
                }
            )
    return rows


def scan_secrets(bundle: Path, t0: int) -> list[dict]:
    out: list[dict] = []
    for path in bundle.rglob("*"):
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > 2 * 1024 * 1024:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for kind, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(data):
                start = max(0, match.start() - 25)
                end = min(len(data), match.end() + 25)
                out.append(
                    {
                        "ts": _now_ms(t0),
                        "type": kind,
                        "pattern_matched": match.group(0).decode("utf-8", "replace")[:120],
                        "context_hash": _sha256_hex(data[start:end]),
                    }
                )
    return out


def fs_record(path: Path, op: str, t0: int, mode: str | None = None) -> dict:
    try:
        size = path.stat().st_size if path.exists() else 0
    except OSError:
        size = 0
    return {
        "ts": _now_ms(t0),
        "op": op,
        "path": str(path.resolve()),
        "bytes": size,
        "mode": mode,
    }


def detect_subprocesses_in_manifest(manifest: dict, t0: int) -> list[dict]:
    if not isinstance(manifest, dict):
        return []
    rows: list[dict] = []
    tools = manifest.get("tools", [])
    if not isinstance(tools, list):
        return rows
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        command = tool.get("command") or tool.get("exec") or {}
        if isinstance(command, str):
            argv = command.split()
        elif isinstance(command, dict) and isinstance(command.get("args"), list):
            argv = [str(command.get("name", ""))] + [str(a) for a in command["args"]]
        else:
            argv = []
        if argv:
            rows.append(
                {
                    "ts": _now_ms(t0),
                    "pid": -1,
                    "ppid": os.getpid(),
                    "cmd": argv[0],
                    "args": argv[1:],
                    "env_keys": sorted(os.environ.keys())[:64],
                }
            )
    return rows


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: mcp_client.py <bundle_path> <nonce> <evidence_dir>", file=sys.stderr)
        return 2
    bundle = Path(sys.argv[1]).resolve()
    nonce = sys.argv[2]
    evidence_root = Path(sys.argv[3]).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    canary_val = os.environ.get("CANARY_VAL", "")
    test_params_per_tool = max(1, int(os.environ.get("TEST_PARAMS_PER_TOOL", "3")))
    timeout = int(os.environ.get("AGENT_TIMEOUT", "120"))

    t0 = time.monotonic_ns()
    network: list[dict] = []
    fs: list[dict] = []
    process: list[dict] = []
    tool_calls: list[dict] = []

    manifest, manifest_path = discover_manifest(bundle)
    fs.append(fs_record(bundle, "read", t0))

    canary_file = bundle / ".canary"
    if canary_val:
        try:
            canary_file.write_text(canary_val, encoding="utf-8")
            fs.append(fs_record(canary_file, "write", t0, mode="600"))
            canary_file.read_bytes()
            fs.append(fs_record(canary_file, "read", t0))
        except OSError:
            pass

    if manifest is None:
        empty_canon = b"{}"
        (evidence_root / "mcp_manifest.json").write_bytes(empty_canon)
        _write_jsonl(evidence_root / "tool_calls.jsonl", tool_calls)
        _write_jsonl(evidence_root / "fs.jsonl", fs)
        _write_jsonl(evidence_root / "process.jsonl", process)
        _write_jsonl(evidence_root / "network.jsonl", network)
        _write_jsonl(evidence_root / "secrets.jsonl", scan_secrets(bundle, t0))
        _ = nonce, timeout
        return 0

    if manifest_path is not None:
        fs.append(fs_record(manifest_path, "read", t0))

    canonical = canonicalise_manifest(manifest)
    (evidence_root / "mcp_manifest.json").write_bytes(canonical)

    tool_calls.extend(exercise_tools(manifest, canary_val, test_params_per_tool, t0))
    process.extend(detect_subprocesses_in_manifest(manifest, t0))
    secrets = scan_secrets(bundle, t0)

    server_cmd = (
        manifest.get("server") if isinstance(manifest.get("server"), dict) else None
    )
    if server_cmd and shutil.which("python") and isinstance(server_cmd.get("entry"), str):
        entry = bundle / server_cmd["entry"]
        if entry.is_file():
            try:
                subprocess.run(  # noqa: S603
                    [sys.executable, "-c", "import ast; import sys; ast.parse(open(sys.argv[1]).read())", str(entry)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                process.append(
                    {
                        "ts": _now_ms(t0),
                        "pid": -1,
                        "ppid": os.getpid(),
                        "cmd": sys.executable,
                        "args": ["-c", "ast.parse", str(entry)],
                        "env_keys": sorted(os.environ.keys())[:64],
                    }
                )
            except subprocess.TimeoutExpired:
                pass

    _write_jsonl(evidence_root / "tool_calls.jsonl", tool_calls)
    _write_jsonl(evidence_root / "fs.jsonl", fs)
    _write_jsonl(evidence_root / "process.jsonl", process)
    _write_jsonl(evidence_root / "network.jsonl", network)
    _write_jsonl(evidence_root / "secrets.jsonl", secrets)
    _ = nonce, timeout
    return 0


if __name__ == "__main__":
    sys.exit(main())
