from __future__ import annotations

import base64
import io
import json
import os
import random
import zipfile
from pathlib import Path

_LABEL_DIRS = ("known-good", "known-bad")

_SIDECAR_FILES = frozenset(
    {"label.json", "ground_truth.json", "_label.example.json", "observed.json"}
)

_FINDING_BUCKETS = {
    "vulnerability": "vulnerabilities",
    "vulnerabilities": "vulnerabilities",
    "supply_chain": "supply_chain",
    "dependency": "supply_chain",
    "secret": "secrets",
    "secrets": "secrets",
    "leaked_secret": "secrets",
}


def _repo_root() -> Path | None:
    override = os.getenv("PHYLAX_CORPUS_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if os.getenv("PHYLAX_DEV_CORPUS") == "1":
        return Path(__file__).resolve().parents[2] / "corpora"
    return None


def _zip_dir_b64(directory: Path) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in sorted(directory.rglob("*")):
            if not entry.is_file():
                continue
            rel = entry.relative_to(directory).as_posix()
            if rel.rsplit("/", 1)[-1] in _SIDECAR_FILES:
                continue
            zf.write(entry, rel)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _load_label(directory: Path) -> dict | None:
    for name in ("label.json", "ground_truth.json"):
        path = directory / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None
        return data if isinstance(data, dict) else None
    return None


def _ground_truth(track: str, label_doc: dict | None) -> dict | None:
    if not label_doc:
        return None
    findings = label_doc.get("expected_findings")
    if not isinstance(findings, list):
        bucketed = {
            key: [i for i in (label_doc.get(key) or []) if isinstance(i, dict)]
            for key in ("vulnerabilities", "supply_chain", "secrets")
            if isinstance(label_doc.get(key), list)
        }
        return bucketed or None
    buckets: dict[str, list] = {}
    if track == "repositories":
        buckets["vulnerabilities"] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        bucket = _FINDING_BUCKETS.get(str(item.get("category", "")).strip().lower())
        if bucket is None:
            continue
        buckets.setdefault(bucket, []).append(item)
    return buckets or None


def pack_files(files: dict) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(files):
            name = str(rel).replace("\\", "/").lstrip("/")
            if not name or ".." in name.split("/"):
                continue
            if name.rsplit("/", 1)[-1] in _SIDECAR_FILES:
                continue
            try:
                zf.writestr(name, base64.b64decode(str(files[rel]), validate=True))
            except (ValueError, TypeError):
                continue
    return base64.b64encode(buf.getvalue()).decode("ascii")


def select_from_listing(entries: list, draw_seed: str, count: int) -> list:
    pool = sorted(
        (e for e in entries if e.get("source_id")),
        key=lambda e: str(e.get("source_id")),
    )
    if not draw_seed or count <= 0 or count >= len(pool):
        return pool
    return random.Random(draw_seed).sample(pool, count)


def fetch_corpus(
    client, round_id: str, track: str, *, draw_seed: str = "", count: int = 0
) -> list[dict]:
    listing = client.get_round_tasks(round_id) or {}
    entries = select_from_listing(listing.get("tasks") or [], draw_seed, count)
    items: list[dict] = []
    for entry in entries:
        source_id = str(entry.get("source_id") or "")
        if not source_id:
            continue
        label = str(entry.get("label") or "")
        artifact = client.get_round_artifact(round_id, source_id) or {}
        files = artifact.get("files")
        if not isinstance(files, dict) or not files:
            continue
        truth = artifact.get("ground_truth")
        truth = truth if isinstance(truth, dict) else {}
        ground_truth = _ground_truth(track, truth)
        expected = [f for f in (truth.get("expected_findings") or []) if isinstance(f, dict)]
        if not expected and ground_truth:
            expected = [f for bucket in ground_truth.values() for f in bucket]
        items.append(
            {
                "ref": f"{track}/{label}/{source_id}",
                "label": label,
                "artifact_b64": pack_files(files),
                "ground_truth": ground_truth,
                "expected_findings": expected,
                "expected_capabilities": [
                    str(c.get("capability", ""))
                    for c in (truth.get("expected_capabilities") or [])
                    if isinstance(c, dict) and c.get("capability")
                ],
            }
        )
    return items


def load_corpus(track: str) -> list[dict]:
    root = _repo_root()
    if root is None:
        return []
    base = root / track
    items: list[dict] = []
    for label in _LABEL_DIRS:
        label_dir = base / label
        if not label_dir.is_dir():
            continue
        for entry in sorted(label_dir.iterdir()):
            if not entry.is_dir():
                continue
            label_doc = _load_label(entry)
            items.append(
                {
                    "ref": f"{track}/{label}/{entry.name}",
                    "label": label,
                    "artifact_b64": _zip_dir_b64(entry),
                    "ground_truth": _ground_truth(track, label_doc),
                    "expected_findings": [
                        f for f in (label_doc or {}).get("expected_findings", [])
                        if isinstance(f, dict)
                    ],
                    "expected_capabilities": [
                        str(c.get("capability", ""))
                        for c in (label_doc or {}).get("expected_capabilities", [])
                        if isinstance(c, dict) and c.get("capability")
                    ],
                }
            )
    return items
