from __future__ import annotations

import base64
import io
import os
import zipfile
from pathlib import Path

_LABEL_DIRS = ("known-good", "known-bad")


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
                zf.write(entry, entry.relative_to(directory).as_posix())
    return base64.b64encode(buf.getvalue()).decode("ascii")


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
                }
            )
    return items
