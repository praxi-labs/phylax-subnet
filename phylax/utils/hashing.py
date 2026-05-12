"""
phylax/utils/hashing.py

Content-addressed hashing helpers used throughout the codebase.

Every artifact reference Phylax emits — bundle hash, SBOM hash, evidence
hashes, finding evidence — uses the form "sha256:<hex>" so downstream
consumers can verify integrity in a single, uniform way.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


def sha256_bytes(data: bytes) -> str:
    """Return 'sha256:<hex>' for the given bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: PathLike, chunk_size: int = 65536) -> str:
    """Stream a file through SHA-256 and return 'sha256:<hex>'."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def content_address(obj) -> str:
    """
    Compute a stable content address for a JSON-serialisable object.

    The same object always produces the same hash regardless of key order.
    """
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_bytes(canon.encode())


def is_valid_sha256_ref(s: str) -> bool:
    """Check that a string matches the 'sha256:<64 hex chars>' shape."""
    return (
        isinstance(s, str)
        and s.startswith("sha256:")
        and len(s) == 71
        and all(c in "0123456789abcdef" for c in s[7:])
    )
