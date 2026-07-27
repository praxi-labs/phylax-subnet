from __future__ import annotations

import base64
import io
import json
import os
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


def _repo_root() -> Path:
    override = os.getenv("PHYLAX_CORPUS_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parents[2] / "corpora"


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
        return None
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


def load_corpus(track: str) -> list[dict]:
    base = _repo_root() / track
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
                    "expected_capabilities": [
                        str(c.get("capability", ""))
                        for c in (label_doc or {}).get("expected_capabilities", [])
                        if isinstance(c, dict) and c.get("capability")
                    ],
                }
            )
    return items
