from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Iterable, Protocol

from phylax.corpus.model import CorpusEntry

_GROUND_TRUTH = "ground_truth.json"


class Connector(Protocol):
    name: str
    track: str

    def fetch(self) -> Iterable[CorpusEntry]:
        ...


class ExampleConnector:
    name = "example"

    def __init__(self, entries: list[CorpusEntry], track: str = "packages"):
        self._entries = entries
        self.track = track

    def fetch(self) -> Iterable[CorpusEntry]:
        return iter(self._entries)


class LocalDirConnector:
    def __init__(self, root, track: str, source: str = "local"):
        self.root = Path(root)
        self.track = track
        self.source = source
        self.name = f"local:{track}"

    def fetch(self) -> Iterable[CorpusEntry]:
        for label in ("known-good", "known-bad"):
            base = self.root / label
            if not base.is_dir():
                continue
            for entry_dir in sorted(p for p in base.iterdir() if p.is_dir()):
                files: dict[str, bytes] = {}
                ground_truth = None
                for fp in sorted(entry_dir.rglob("*")):
                    if not fp.is_file():
                        continue
                    rel = fp.relative_to(entry_dir).as_posix()
                    if rel == _GROUND_TRUTH:
                        try:
                            ground_truth = json.loads(fp.read_text(encoding="utf-8"))
                        except (ValueError, OSError):
                            ground_truth = None
                        continue
                    files[rel] = fp.read_bytes()
                if not files:
                    continue
                yield CorpusEntry(
                    source_id=f"{self.source}:{self.track}:{entry_dir.name}",
                    track=self.track,
                    label=label,
                    source=self.source,
                    files=files,
                    name=entry_dir.name,
                    ground_truth=ground_truth,
                )


class DatadogPackagesConnector:
    name = "datadog"
    track = "packages"
    zip_password = b"infected"

    def __init__(self, path):
        self.path = Path(path)

    def fetch(self) -> Iterable[CorpusEntry]:
        for ecosystem in ("npm", "pypi"):
            samples = self.path / "samples" / ecosystem
            if not samples.is_dir():
                continue
            for archive in sorted(samples.rglob("*.zip")):
                try:
                    files = self._read_zip(archive)
                except (RuntimeError, zipfile.BadZipFile, OSError):
                    continue
                if not files:
                    continue
                name = archive.stem
                scoped = ""
                if name.startswith("@") and "/" in name:
                    scoped, name = name.split("/", 1)[0], name.split("/", 1)[1]
                head = "" if not scoped else scoped + "/"
                yield CorpusEntry(
                    source_id=f"{ecosystem}:{head}{name}",
                    track="packages",
                    label="known-bad",
                    source="datadog",
                    files=files,
                    ecosystem=ecosystem,
                    scoped=scoped,
                    name=name,
                )

    def _read_zip(self, archive: Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                files[info.filename] = zf.read(info, pwd=self.zip_password)
        return files
