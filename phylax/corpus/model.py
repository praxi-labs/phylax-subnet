from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

TRACKS = ("skills", "mcp_servers", "packages", "repositories")
LABELS = ("known-good", "known-bad")

_SAFE = re.compile(r"[^A-Za-z0-9._@-]+")


@dataclass
class CorpusEntry:
    source_id: str
    track: str
    label: str
    source: str
    files: dict[str, bytes] = field(default_factory=dict)
    ecosystem: str = ""
    scoped: str = ""
    name: str = ""
    version: str = ""
    ground_truth: dict | None = None


def content_hash(files: dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(path.encode("utf-8"))
        h.update(b"\0")
        h.update(files[path])
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def dir_name(source_id: str) -> str:
    return _SAFE.sub("_", source_id).strip("_")[:120] or "entry"


def total_size_kb(files: dict[str, bytes]) -> int:
    return max(1, sum(len(b) for b in files.values()) // 1024)


def _extension(path: str) -> str:
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1] if "." in base else ""


def file_rows(entry: CorpusEntry) -> list[dict]:
    size_kb = total_size_kb(entry.files)
    rows: list[dict] = []
    for path in sorted(entry.files):
        blob = entry.files[path]
        rows.append({
            "source_id": entry.source_id,
            "ecosystem": entry.ecosystem,
            "scoped": entry.scoped,
            "name": entry.name,
            "version": entry.version,
            "label": entry.label,
            "track": entry.track,
            "total_files": len(entry.files),
            "package_size_kb": size_kb,
            "file_path": path,
            "file_extension": _extension(path),
            "file_size_kb": max(1, len(blob) // 1024),
        })
    return rows
