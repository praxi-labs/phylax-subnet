from __future__ import annotations

import base64
import io
import json
import os
import zipfile
from pathlib import Path

_LABEL_DIRS = ("known-good", "known-bad")
_GROUND_TRUTH_FILE = "ground_truth.json"


def _repo_root() -> Path:
    override = os.getenv("PHYLAX_CORPUS_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parents[2] / "corpora"


def _zip_dir_b64(directory: Path) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in sorted(directory.rglob("*")):
            if entry.is_file():
                rel = entry.relative_to(directory).as_posix()
                if rel == _GROUND_TRUTH_FILE:
                    continue
                zf.write(entry, rel)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _load_ground_truth(directory: Path) -> dict | None:
    path = directory / _GROUND_TRUTH_FILE
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


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
            items.append(
                {
                    "ref": f"{track}/{label}/{entry.name}",
                    "label": label,
                    "artifact_b64": _zip_dir_b64(entry),
                    "ground_truth": _load_ground_truth(entry),
                }
            )
    return items
