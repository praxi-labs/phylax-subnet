from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path

from phylax.corpus.model import (
    CorpusEntry,
    content_hash,
    dir_name,
    file_rows,
    total_size_kb,
)

_INDEX = "index.json"
_GROUND_TRUTH = "ground_truth.json"
_FILE_FIELDS = [
    "source_id", "ecosystem", "scoped", "name", "version", "label", "track",
    "total_files", "package_size_kb", "file_path", "file_extension", "file_size_kb",
]


def load_index(root: Path) -> dict:
    path = Path(root) / _INDEX
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("entries"), dict):
                return data
        except (ValueError, OSError):
            pass
    return {"index_format": 1, "latest_version": None, "entries": {}}


def save_index(root: Path, index: dict) -> None:
    (Path(root) / _INDEX).write_text(
        json.dumps(index, indent=2, sort_keys=True), encoding="utf-8"
    )


def _classify(index: dict, source_id: str, chash: str) -> str:
    rec = index["entries"].get(source_id)
    if rec is None:
        return "new"
    if rec.get("content_hash") != chash:
        return "revised"
    return "unchanged"


def _write_artifact(root: Path, entry: CorpusEntry) -> str:
    rel = f"{entry.track}/{entry.label}/{dir_name(entry.source_id)}"
    dest = Path(root) / rel
    if dest.exists():
        for p in sorted(dest.rglob("*"), reverse=True):
            if p.is_file():
                p.unlink()
    dest.mkdir(parents=True, exist_ok=True)
    for path, blob in entry.files.items():
        fp = dest / path
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(blob)
    if entry.ground_truth is not None:
        (dest / _GROUND_TRUTH).write_text(
            json.dumps(entry.ground_truth, indent=2, sort_keys=True), encoding="utf-8"
        )
    return rel


def _record(entry: CorpusEntry, chash: str, version: str, rel: str, existing: dict | None) -> dict:
    first = existing.get("first_seen", version) if existing else version
    return {
        "source_id": entry.source_id,
        "track": entry.track,
        "label": entry.label,
        "source": entry.source,
        "ecosystem": entry.ecosystem,
        "scoped": entry.scoped,
        "name": entry.name,
        "version": entry.version,
        "content_hash": chash,
        "total_files": len(entry.files),
        "package_size_kb": total_size_kb(entry.files),
        "path": rel,
        "first_seen": first,
        "last_seen": version,
        "status": "active",
    }


@dataclass
class DumpResult:
    version: str
    new: list
    revised: list
    unchanged: list

    @property
    def held_out(self) -> list:
        return self.new + self.revised


def dump(connectors, root, version: str) -> DumpResult:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    index = load_index(root)
    new: list[str] = []
    revised: list[str] = []
    unchanged: list[str] = []
    rows: list[dict] = []
    seen: set[str] = set()

    for conn in connectors:
        for entry in conn.fetch():
            if entry.source_id in seen:
                continue
            seen.add(entry.source_id)
            chash = content_hash(entry.files)
            klass = _classify(index, entry.source_id, chash)
            if klass == "unchanged":
                index["entries"][entry.source_id]["last_seen"] = version
                unchanged.append(entry.source_id)
                continue
            existing = index["entries"].get(entry.source_id)
            rel = _write_artifact(root, entry)
            index["entries"][entry.source_id] = _record(entry, chash, version, rel, existing)
            rows.extend(file_rows(entry))
            (new if klass == "new" else revised).append(entry.source_id)

    index["latest_version"] = version
    save_index(root, index)
    _write_version(root, version, new, revised, unchanged, rows)
    return DumpResult(version, new, revised, unchanged)


def _write_version(root, version, new, revised, unchanged, rows) -> None:
    vdir = Path(root) / "versions" / version
    vdir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": version,
        "new": sorted(new),
        "revised": sorted(revised),
        "unchanged_count": len(unchanged),
        "held_out": sorted(new + revised),
    }
    (vdir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    if rows:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_FILE_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        (vdir / "files.csv").write_text(buf.getvalue(), encoding="utf-8")


def version_manifest(root, version: str) -> dict | None:
    path = Path(root) / "versions" / version / "manifest.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
