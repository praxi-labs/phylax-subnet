from __future__ import annotations

import hashlib
import json
from pathlib import Path

_TS_KEY = "ts"


def _normalise_records(raw: bytes) -> bytes:
    records: list[dict] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            records.append(json.loads(s))
        except (ValueError, TypeError):
            continue
    records.sort(key=lambda r: (float(r.get(_TS_KEY, 0) or 0), json.dumps(r, sort_keys=True)))
    serialised = "\n".join(
        json.dumps(rec, sort_keys=True, separators=(",", ":"))
        for rec in records
    )
    return serialised.encode("utf-8")


def hash_jsonl_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(_normalise_records(raw)).hexdigest()


def hash_jsonl_file(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    if not raw.strip():
        return None
    return hash_jsonl_bytes(raw)


def hash_raw_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
