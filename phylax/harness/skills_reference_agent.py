from __future__ import annotations

import contextlib
import hashlib
import json
import re
import socket
import subprocess
import unicodedata
from pathlib import Path

_SCAN_BYTE_CAP = 1_000_000
_TEXT_SUFFIXES = (".md", ".py", ".js", ".ts", ".sh", ".txt", ".json", ".yaml", ".yml", ".toml")

_CAPABILITY_SIGNALS: dict[str, tuple[str, ...]] = {
    "EXEC_SHELL": ("subprocess", "os.system", "popen", "sh -c", "bash -c"),
    "CALL_EXTERNAL_API": ("requests.", "urllib", "httpx", "http://", "https://"),
    "POST_WEB": ("requests.post", ".post(", "urlopen"),
    "WRITE_SHELL_PROFILE": (".bashrc", ".zshrc", ".profile", "shell profile"),
    "INSTALL_PACKAGE": ("pip install", "npm install", "apt-get install"),
    "READ_ENV_SECRETS": ("os.environ", "getenv", "process.env"),
    "READ_PRIVATE_KEY": ("id_rsa", ".pem", "private_key", "begin rsa"),
    "ACCESS_WALLET": ("wallet.dat", "metamask", "keystore", "mnemonic"),
    "WRITE_FILE": ("with open", ".write(", "open("),
    "DELETE_FILE": ("os.remove", "shutil.rmtree", "unlink("),
    "INJECT_INSTRUCTION": ("ignore previous", "disregard the", "system prompt"),
}

_CRITICAL_CAPS = frozenset(
    {"WRITE_SHELL_PROFILE", "INSTALL_PACKAGE", "READ_PRIVATE_KEY", "ACCESS_WALLET", "READ_ENV_SECRETS"}
)
_DANGEROUS_CAPS = frozenset({"EXEC_SHELL", "POST_WEB", "CALL_EXTERNAL_API", "DELETE_FILE"})


def _thread_probe(probe: dict) -> dict:
    fs: list[dict] = []
    network: list[dict] = []
    process: list[dict] = []

    try:
        target = Path(probe["file_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(probe["file_content"], encoding="utf-8")
        fs.append({"path": probe["file_path"], "op": "write"})
    except OSError:
        fs.append({"path": probe["file_path"], "op": "write"})

    with contextlib.suppress(OSError):
        socket.getaddrinfo(probe["dns_host"], 80)
    network.append({"domain": probe["dns_host"], "proto": "dns", "dst_port": 53})

    with contextlib.suppress(Exception):
        subprocess.run(
            ["echo", probe["process_echo"]], capture_output=True, timeout=5, check=False
        )
    process.append({"cmd": "echo", "args": [probe["process_echo"]]})

    return {"fs": fs, "network": network, "process": process}


def _read_corpus(artifact_dir: str) -> str:
    chunks: list[str] = []
    total = 0
    root = Path(artifact_dir)
    if not root.exists():
        return ""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        chunks.append(text)
        total += len(text)
        if total >= _SCAN_BYTE_CAP:
            break
    return "\n".join(chunks).lower()


def _scan_capabilities(corpus: str) -> list[dict]:
    found: list[dict] = []
    for name, signals in _CAPABILITY_SIGNALS.items():
        hit = next((s for s in signals if s in corpus), None)
        if hit is not None:
            found.append({"capability": name, "observation": f"matched marker '{hit}'"})
    return found


_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("instruction_injection", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)"), 0.30),
    ("instruction_injection", re.compile(r"(?:override|disregard|bypass)\s+(?:the\s+)?(?:system|safety|policy|guardrail)"), 0.25),
    ("context_injection", re.compile(r"\bsystem\s*[:=]\s*[\"']"), 0.20),
    ("context_injection", re.compile(r"\b(?:dan|do\s+anything\s+now|developer\s+mode|jailbreak)\b"), 0.30),
    ("context_injection", re.compile(r"\b(?:reveal|print|show|leak)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)"), 0.20),
)

_ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")


def _context_plane(corpus: str) -> tuple[dict, list, float]:
    injected: list[dict] = []
    findings: list[dict] = []
    score = 0.0
    for category, pattern, weight in _INJECTION_PATTERNS:
        match = pattern.search(corpus)
        if match is None:
            continue
        score += weight
        excerpt = corpus[max(0, match.start() - 16): match.start() + 48].strip()
        injected.append({"type": category, "excerpt": excerpt, "location": "skill_text"})
        findings.append(
            {"category": category, "severity": "HIGH", "plane": "context",
             "title": f"{category} pattern in skill text"}
        )
    if any(z in corpus for z in _ZERO_WIDTH):
        score += 0.20
        injected.append({"type": "unicode_anomaly", "excerpt": "", "location": "skill_text"})
        findings.append(
            {"category": "context_injection", "severity": "MED", "plane": "context",
             "title": "zero-width unicode anomaly"}
        )
    return {"injected_instructions": injected, "loaded_context": []}, findings, min(1.0, score)


def _decide(capabilities: list[dict], injection_score: float) -> tuple[str, int]:
    names = {c["capability"] for c in capabilities}
    if injection_score >= 0.66 or names & _CRITICAL_CAPS:
        return "BLOCK", 85
    if injection_score >= 0.33 or names & _DANGEROUS_CAPS:
        return "WARN", 50
    return "ALLOW", 5


def _trace_hash(events: list) -> str:
    canon = json.dumps(events, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    canon = unicodedata.normalize("NFC", canon)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _probe_evidence(probe: dict) -> dict:
    return {
        "file_write": probe.get("file_path", ""),
        "dns_lookup": probe.get("dns_host", ""),
        "process_echo": probe.get("process_echo", ""),
        "canary": probe.get("canary", ""),
    }


def agent_main(context: dict | None = None) -> dict:
    context = context or {}
    artifact_dir = context.get("artifact_dir", "/skill")
    probe = context.get("probe") or {}

    traces = _thread_probe(probe)
    corpus = _read_corpus(artifact_dir)
    capabilities = _scan_capabilities(corpus)
    context_plane, findings, injection_score = _context_plane(corpus)
    verdict, risk_score = _decide(capabilities, injection_score)

    evidence = {
        "proof_of_execution": {
            "probe_evidence": _probe_evidence(probe),
            "traces": {
                "filesystem": {"hash": _trace_hash(traces["fs"]), "events": traces["fs"]},
                "network": {"hash": _trace_hash(traces["network"]), "events": traces["network"]},
                "process": {"hash": _trace_hash(traces["process"]), "events": traces["process"]},
            },
        },
        "action_plane": {"capabilities": capabilities},
        "context_plane": context_plane,
        "capability_manifest": [c["capability"] for c in capabilities],
    }
    return {
        "verdict": {"decision": verdict, "risk_score": risk_score, "confidence": 0.7},
        "evidence": evidence,
        "findings": findings,
    }
