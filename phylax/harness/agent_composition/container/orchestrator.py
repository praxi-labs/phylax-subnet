from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

_MANIFEST_CANDIDATES = (
    "composition.json",
    "composition.yaml",
    "composition.yml",
    "manifest.json",
)


def _now_ms(t0: int) -> float:
    return (time.monotonic_ns() - t0) // 1_000_000 / 1000.0


def _sha256(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for r in rows:
            fp.write(json.dumps(r, sort_keys=True, separators=(",", ":")))
            fp.write("\n")


def load_composition(bundle: Path) -> dict | None:
    for name in _MANIFEST_CANDIDATES:
        candidate = bundle / name
        if candidate.is_file():
            try:
                if candidate.suffix in {".json"}:
                    return json.loads(candidate.read_text(encoding="utf-8"))
                if candidate.suffix in {".yaml", ".yml"}:
                    return _parse_simple_yaml(candidate.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001, S112
                continue
    return None


def _parse_simple_yaml(text: str) -> dict:
    out: dict = {}
    stack: list[tuple[int, dict | list]] = [(-1, out)]
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        content = line.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1] if stack else out
        if content.startswith("- "):
            value = content[2:].strip()
            if not isinstance(parent, list):
                continue
            if ":" in value:
                key, _, v = value.partition(":")
                item = {key.strip(): v.strip() or {}}
                parent.append(item)
                stack.append((indent + 2, item))
            else:
                parent.append(value)
            continue
        if ":" in content:
            key, _, value = content.partition(":")
            key = key.strip()
            value = value.strip()
            if isinstance(parent, dict):
                if not value:
                    new_container: dict | list = {}
                    parent[key] = new_container
                    stack.append((indent, new_container))
                else:
                    parent[key] = value
    return out


def build_dependency_graph(
    composition: dict,
    bundle: Path,
    depth_cap: int,
) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    root_name = str(composition.get("name") or composition.get("skill") or "root")
    seen.add(root_name)
    nodes.append(
        {
            "name": root_name,
            "verdict": str(composition.get("verdict") or "UNKNOWN").upper(),
            "bundle_hash": "",
        }
    )

    def walk(parent_name: str, node: dict, depth: int) -> None:
        if depth > depth_cap:
            return
        children = (
            node.get("children")
            or node.get("dependencies")
            or node.get("composition")
            or node.get("skills")
            or []
        )
        if not isinstance(children, list):
            return
        for child in children:
            if isinstance(child, str):
                child_name = child
                child_verdict = "UNKNOWN"
                child_obj: dict = {}
            elif isinstance(child, dict):
                child_name = str(child.get("name") or child.get("skill") or "anonymous")
                child_verdict = str(child.get("verdict") or "UNKNOWN").upper()
                child_obj = child
            else:
                continue
            if child_name not in seen:
                seen.add(child_name)
                nodes.append(
                    {
                        "name": child_name,
                        "verdict": child_verdict,
                        "bundle_hash": str(child_obj.get("bundle_hash") or ""),
                    }
                )
            edges.append({"from": parent_name, "to": child_name})
            if child_obj:
                walk(child_name, child_obj, depth + 1)

    walk(root_name, composition, 1)
    return {"protocol": "phylax_composition_v1", "nodes": nodes, "edges": edges}


def emit_agent_calls(
    graph: dict,
    canary_val: str,
    t0: int,
) -> list[dict]:
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    nodes = {
        n["name"]: n
        for n in (graph.get("nodes", []) if isinstance(graph, dict) else [])
        if isinstance(n, dict)
    }
    rows: list[dict] = []
    depth_map: dict[str, int] = {}

    def depth_of(name: str) -> int:
        if name in depth_map:
            return depth_map[name]
        depth_map[name] = 0
        return 0

    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            continue
        caller = str(edge.get("from") or "")
        callee = str(edge.get("to") or "")
        depth = depth_of(caller) + 1
        depth_map[callee] = depth
        params_payload = json.dumps({"canary": canary_val, "edge": idx}, sort_keys=True).encode("utf-8")
        response_payload = json.dumps({"ok": True, "edge": idx}, sort_keys=True).encode("utf-8")
        rows.append(
            {
                "ts": _now_ms(t0),
                "caller_skill": caller,
                "callee_skill": callee,
                "call_type": "invoke",
                "call_params_hash": _sha256(params_payload),
                "response_hash": _sha256(response_payload),
                "depth": depth,
                "duration_ms": 0,
                "callee_verdict": nodes.get(callee, {}).get("verdict", "UNKNOWN"),
            }
        )
    return rows


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: orchestrator.py <bundle_path> <nonce> <evidence_dir>", file=sys.stderr)
        return 2
    bundle = Path(sys.argv[1]).resolve()
    nonce = sys.argv[2]
    evidence_root = Path(sys.argv[3]).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    canary_val = os.environ.get("CANARY_VAL", "")
    depth_cap = max(1, int(os.environ.get("COMPOSITION_DEPTH", "5")))

    t0 = time.monotonic_ns()

    composition = load_composition(bundle) or {}
    graph = build_dependency_graph(composition, bundle, depth_cap)
    graph_path = evidence_root / "dependency_graph.json"
    graph_path.write_text(
        json.dumps(graph, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    fs: list[dict] = [
        {
            "ts": _now_ms(t0),
            "op": "read",
            "path": str(bundle.resolve()),
            "bytes": 0,
            "mode": None,
        }
    ]
    process: list[dict] = []
    network: list[dict] = []
    secrets: list[dict] = []
    agent_calls = emit_agent_calls(graph, canary_val, t0)

    if canary_val:
        canary_file = bundle / ".canary"
        try:
            canary_file.write_text(canary_val, encoding="utf-8")
            fs.append(
                {
                    "ts": _now_ms(t0),
                    "op": "write",
                    "path": str(canary_file.resolve()),
                    "bytes": len(canary_val.encode("utf-8")),
                    "mode": "600",
                }
            )
            canary_file.read_bytes()
            fs.append(
                {
                    "ts": _now_ms(t0),
                    "op": "read",
                    "path": str(canary_file.resolve()),
                    "bytes": len(canary_val.encode("utf-8")),
                    "mode": None,
                }
            )
        except OSError:
            pass

    _write_jsonl(evidence_root / "network.jsonl", network)
    _write_jsonl(evidence_root / "fs.jsonl", fs)
    _write_jsonl(evidence_root / "process.jsonl", process)
    _write_jsonl(evidence_root / "secrets.jsonl", secrets)
    _write_jsonl(evidence_root / "agent_calls.jsonl", agent_calls)
    _ = nonce, depth_cap
    return 0


if __name__ == "__main__":
    sys.exit(main())
