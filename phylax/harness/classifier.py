from __future__ import annotations

import hashlib
import io
import re
import tarfile
from pathlib import Path

import httpx

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_FILES = 10_000
EXCLUDED_DIRS = {".git", "__pycache__", "node_modules", ".github", ".vscode"}
EXCLUDED_FILES = {".DS_Store"}

_GITHUB_URL = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.*))?)?/?$"
)


def parse_github_url(source_url: str) -> tuple[str, str, str | None, str | None]:
    m = _GITHUB_URL.match(source_url.strip())
    if not m:
        raise ValueError(f"unsupported source_url: {source_url}")
    owner, repo, ref, subpath = m.groups()
    return owner, repo, ref, (subpath.rstrip("/") if subpath else None)


def fetch_source(source_url: str, pinned_commit: str, dest: Path) -> Path:
    owner, repo, ref, subpath = parse_github_url(source_url)
    commit = pinned_commit or ref or "HEAD"
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{commit}"
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.content
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds size cap")

    dest_resolved = dest.resolve()
    extracted = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if len(parts) < 2:
                continue
            rel = Path(*parts[1:])
            rel_str = rel.as_posix()
            if subpath:
                prefix = subpath + "/"
                if not rel_str.startswith(prefix) and rel_str != subpath:
                    continue
                rel = Path(rel_str.removeprefix(prefix))
            if any(p in EXCLUDED_DIRS for p in rel.parts) or rel.name in EXCLUDED_FILES:
                continue
            target = (dest_resolved / rel).resolve()
            if dest_resolved != target and dest_resolved not in target.parents:
                raise ValueError(f"unsafe path in archive: {member.name}")
            total += member.size
            extracted += 1
            if total > MAX_ARCHIVE_BYTES or extracted > MAX_FILES:
                raise ValueError("archive exceeds extraction caps")
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            target.write_bytes(src.read())
    if extracted == 0:
        raise ValueError("no files extracted from source")
    return dest_resolved


def canonical_bundle_hash(root: Path) -> str:
    root = root.resolve()
    entries: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(p in EXCLUDED_DIRS for p in rel.parts) or rel.name in EXCLUDED_FILES:
            continue
        entries.append((rel.as_posix(), path))
    entries.sort(key=lambda e: e[0])
    h = hashlib.sha256()
    for rel_str, path in entries:
        h.update(rel_str.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(path.read_bytes()).digest())
        h.update(b"\x00")
    return "sha256:" + h.hexdigest()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def classify_tree(root: Path) -> str:
    root = root.resolve()
    files = [p for p in root.rglob("*") if p.is_file()]
    rel_names = {p.relative_to(root).as_posix().lower() for p in files}
    suffixes = {p.suffix.lower() for p in files}

    manifest = root / "phylax.skill.yaml"
    if manifest.exists():
        m = re.search(r"^skill_type:\s*(\S+)", _read_text(manifest), re.MULTILINE)
        if m and m.group(1) in {
            "declarative",
            "executable_python",
            "executable_script",
            "rag_knowledge",
            "mcp_server",
            "agent_composition",
        }:
            return m.group(1)

    if "mcp.json" in rel_names or any(n.endswith("/mcp.json") for n in rel_names):
        return "mcp_server"
    for dep_file in ("pyproject.toml", "package.json", "requirements.txt"):
        p = root / dep_file
        if p.exists() and re.search(r"modelcontextprotocol|fastmcp|\bmcp\b", _read_text(p)):
            return "mcp_server"

    agent = root / "agent.yaml"
    if agent.exists() and re.search(r"^\s*(steps|sub_skills):", _read_text(agent), re.MULTILINE):
        return "agent_composition"

    if any(n.endswith(".jsonl") or n.endswith("embeddings.bin") for n in rel_names):
        if ".py" not in suffixes and ".sh" not in suffixes:
            return "rag_knowledge"

    if ".py" in suffixes:
        return "executable_python"
    if ".sh" in suffixes or ".bash" in suffixes:
        return "executable_script"

    return "declarative"
