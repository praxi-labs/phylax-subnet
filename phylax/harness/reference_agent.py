"""Unified reference agent for all four Phylax tracks.

This is the starting point miners fork and improve on. It follows the
intent-versus-behaviour principle: derive what the artifact declares, observe
what its code does, and flag the deviation. One `agent_main(context)` handles
skills, MCP servers, packages, and repositories, selecting the analysis by
``context['track']`` and emitting the evidence shape that track's evaluator
expects.

It is deliberately heuristic (static markers, no LLM). Real detection agents are
expected to beat it — that is the competition.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import re
import socket
import subprocess
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

_INFERENCE_TIMEOUT_S = 120
_INFERENCE_MAX_TOKENS = 1500
_REVIEW_CHARS = 24_000

_SCAN_BYTE_CAP = 2_000_000
_TEXT_SUFFIXES = (
    ".md", ".py", ".js", ".ts", ".sh", ".txt", ".json", ".yaml", ".yml",
    ".toml", ".cfg", ".ini", ".rb", ".go", ".rs", ".java",
)

# Capability markers shared across tracks (intent-vs-behaviour signals).
_CAPABILITY_SIGNALS: dict[str, tuple[str, ...]] = {
    "EXEC_SHELL": ("subprocess", "os.system", "popen", "sh -c", "bash -c", "child_process", "exec("),
    "CALL_EXTERNAL_API": ("requests.", "urllib", "httpx", "http://", "https://", "fetch("),
    "POST_WEB": ("requests.post", ".post(", "urlopen", "axios.post"),
    "WRITE_SHELL_PROFILE": (".bashrc", ".zshrc", ".profile", "shell profile"),
    "INSTALL_PACKAGE": ("pip install", "npm install", "apt-get install", "curl | sh", "curl | bash"),
    "READ_ENV_SECRETS": ("os.environ", "getenv", "process.env"),
    "READ_PRIVATE_KEY": ("id_rsa", ".pem", "private_key", "begin rsa"),
    "ACCESS_WALLET": ("wallet.dat", "metamask", "keystore", "mnemonic"),
    "WRITE_FILE": ("with open", ".write(", "open("),
    "DELETE_FILE": ("os.remove", "shutil.rmtree", "unlink("),
    "EVAL_DYNAMIC": ("eval(", "exec(", "compile(", "__import__"),
    "OBFUSCATION": ("base64.b64decode", "codecs.decode", "fromcharcode", "\\x", "marshal.loads"),
    "INJECT_INSTRUCTION": ("ignore previous", "disregard the", "system prompt"),
}

_CRITICAL_CAPS = frozenset(
    {"WRITE_SHELL_PROFILE", "INSTALL_PACKAGE", "READ_PRIVATE_KEY", "ACCESS_WALLET", "READ_ENV_SECRETS"}
)
_DANGEROUS_CAPS = frozenset(
    {"EXEC_SHELL", "POST_WEB", "CALL_EXTERNAL_API", "DELETE_FILE", "EVAL_DYNAMIC", "OBFUSCATION"}
)

# Capability -> (CWE, description) for the repositories static audit.
_CWE_BY_CAP: dict[str, tuple[str, str]] = {
    "EXEC_SHELL": ("CWE-78", "OS command execution from untrusted input"),
    "CALL_EXTERNAL_API": ("CWE-319", "outbound network call"),
    "POST_WEB": ("CWE-200", "data transmitted to an external endpoint"),
    "READ_ENV_SECRETS": ("CWE-522", "reads environment secrets"),
    "READ_PRIVATE_KEY": ("CWE-522", "reads private key material"),
    "ACCESS_WALLET": ("CWE-522", "accesses wallet or keystore material"),
    "WRITE_SHELL_PROFILE": ("CWE-506", "modifies shell startup for persistence"),
    "INSTALL_PACKAGE": ("CWE-494", "downloads and runs code without integrity check"),
    "DELETE_FILE": ("CWE-73", "external control of file deletion"),
    "EVAL_DYNAMIC": ("CWE-95", "dynamic code evaluation"),
    "OBFUSCATION": ("CWE-506", "obfuscated or encoded payload"),
}

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("instruction_injection", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)"), 0.30),
    ("instruction_injection", re.compile(r"(?:override|disregard|bypass)\s+(?:the\s+)?(?:system|safety|policy|guardrail)"), 0.25),
    ("context_injection", re.compile(r"\bsystem\s*[:=]\s*[\"']"), 0.20),
    ("context_injection", re.compile(r"\b(?:dan|do\s+anything\s+now|developer\s+mode|jailbreak)\b"), 0.30),
    ("context_injection", re.compile(r"\b(?:reveal|print|show|leak)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)"), 0.20),
    ("credential_exfil", re.compile(r"(?:read|cat|send|post|leak).{0,24}(?:id_rsa|\.ssh|\.env|secret|token|api[_-]?key)"), 0.30),
)

_ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")

_CURL_PIPE = re.compile(r"curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh")

# Source-code vulnerability patterns for the repositories static audit — code
# defects that aren't behavioural capabilities but a real detector must catch.
_REPO_PATTERNS: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (re.compile(r"""["'][^"']*\b(?:select|insert|update|delete|drop)\b[^"']*["']\s*(?:%|\+|\.format)""", re.I),
     "CWE-89", "SQL injection via string-formatted query", "high"),
    (re.compile(r"""\bf["'][^"']*\b(?:select|insert|update|delete)\b""", re.I),
     "CWE-89", "SQL injection via f-string query", "high"),
    (re.compile(r"pickle\.loads|yaml\.load\s*\((?![^)]*Loader)", re.I),
     "CWE-502", "unsafe deserialization of untrusted data", "high"),
    (re.compile(r"verify\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*:\s*false", re.I),
     "CWE-295", "TLS certificate verification disabled", "medium"),
    (re.compile(r"\bhashlib\.md5\b|\bhashlib\.sha1\b|createHash\(['\"](?:md5|sha1)", re.I),
     "CWE-327", "weak cryptographic hash", "medium"),
    (re.compile(r"(?:password|secret|api[_-]?key|token)\s*[=:]\s*[\"'][A-Za-z0-9+/]{8,}[\"']", re.I),
     "CWE-798", "hardcoded credential", "high"),
)

# Supply-chain layer for the repositories track (the Socket half): the repo's own
# dependency manifests, leaked secrets, and licence posture, scanned alongside the
# first-party code vulnerabilities above (the Bitsec half). Detection patterns
# only — matched values are reported redacted, never echoed.
_DEP_FILE_NAMES = (
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile",
    "package.json", "package-lock.json", "yarn.lock", "go.mod", "cargo.toml", "gemfile",
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws.{0,20}secret.{0,24}[\"'][A-Za-z0-9/+=]{40}[\"']")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("generic_token", re.compile(
        r"(?i)(?:api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)"
        r"\s*[=:]\s*[\"'][A-Za-z0-9_\-]{20,}[\"']")),
)

_SPDX_LICENCE = re.compile(
    r"(?i)\b(MIT|Apache-2\.0|BSD-3-Clause|BSD-2-Clause|GPL-3\.0|GPL-2\.0|AGPL-3\.0|"
    r"LGPL-3\.0|MPL-2\.0|Unlicense|ISC)\b")


# --------------------------------------------------------------------------- #
# proof of execution (behavioural tracks)
# --------------------------------------------------------------------------- #
def _thread_probe(probe: dict) -> dict:
    fs: list[dict] = []
    network: list[dict] = []
    process: list[dict] = []
    try:
        target = Path(probe["file_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(probe["file_content"], encoding="utf-8")
    except OSError:
        pass
    fs.append({"path": probe.get("file_path", ""), "op": "write"})
    with contextlib.suppress(OSError):
        socket.getaddrinfo(probe.get("dns_host", ""), 80)
    network.append({"domain": probe.get("dns_host", ""), "proto": "dns", "dst_port": 53})
    with contextlib.suppress(Exception):
        subprocess.run(
            ["echo", probe.get("process_echo", "")], capture_output=True, timeout=5, check=False
        )
    process.append({"cmd": "echo", "args": [probe.get("process_echo", "")]})
    return {"fs": fs, "network": network, "process": process}


def _trace_hash(events: list) -> str:
    canon = json.dumps(events, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    canon = unicodedata.normalize("NFC", canon)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _proof_of_execution(probe: dict) -> dict:
    traces = _thread_probe(probe)
    return {
        "probe_evidence": {
            "file_write": probe.get("file_path", ""),
            "dns_lookup": probe.get("dns_host", ""),
            "process_echo": probe.get("process_echo", ""),
            "canary": probe.get("canary", ""),
        },
        "traces": {
            "filesystem": {"hash": _trace_hash(traces["fs"]), "events": traces["fs"]},
            "network": {"hash": _trace_hash(traces["network"]), "events": traces["network"]},
            "process": {"hash": _trace_hash(traces["process"]), "events": traces["process"]},
        },
    }


# --------------------------------------------------------------------------- #
# artifact reading
# --------------------------------------------------------------------------- #
def _read_files(artifact_dir: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    total = 0
    root = Path(artifact_dir)
    if not root.exists():
        return out
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        out.append((rel, text))
        total += len(text)
        if total >= _SCAN_BYTE_CAP:
            break
    return out


def _corpus(files: list[tuple[str, str]]) -> str:
    return "\n".join(text for _, text in files).lower()


def _scan_capabilities(corpus: str) -> list[dict]:
    found: list[dict] = []
    for name, signals in _CAPABILITY_SIGNALS.items():
        hit = next((s for s in signals if s in corpus), None)
        if hit is not None:
            found.append({"capability": name, "observation": f"matched marker '{hit}'"})
    return found


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
        injected.append({"type": category, "excerpt": excerpt, "location": "artifact_text"})
        findings.append(
            {"category": category, "severity": "HIGH", "plane": "context",
             "title": f"{category} pattern in artifact text"}
        )
    if any(z in corpus for z in _ZERO_WIDTH):
        score += 0.20
        injected.append({"type": "unicode_anomaly", "excerpt": "", "location": "artifact_text"})
        findings.append(
            {"category": "context_injection", "severity": "MED", "plane": "context",
             "title": "zero-width unicode anomaly"}
        )
    return {"injected_instructions": injected, "loaded_context": []}, findings, min(1.0, score)


def _decide(capabilities: list[dict], injection_score: float) -> tuple[str, int]:
    names = {c["capability"] for c in capabilities}
    if injection_score >= 0.66 or names & _CRITICAL_CAPS:
        return "BLOCK", 88
    if injection_score >= 0.33 or names & _DANGEROUS_CAPS:
        return "WARN", 52
    return "ALLOW", 6


# --------------------------------------------------------------------------- #
# per-track evidence builders
# --------------------------------------------------------------------------- #
def _analyse_skills(files: list[tuple[str, str]], probe: dict) -> dict:
    corpus = _corpus(files)
    caps = _scan_capabilities(corpus)
    context_plane, findings, inj = _context_plane(corpus)
    decision, risk = _decide(caps, inj)
    return {
        "verdict": {"decision": decision, "risk_score": risk, "confidence": 0.7},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {"capabilities": caps},
            "context_plane": context_plane,
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": findings,
    }


def _analyse_mcp(files: list[tuple[str, str]], probe: dict) -> dict:
    corpus = _corpus(files)
    caps = _scan_capabilities(corpus)
    context_plane, findings, inj = _context_plane(corpus)

    tool_names = re.findall(r'"name"\s*:\s*"([a-zA-Z0-9_\-]+)"', corpus)
    tool_names += re.findall(r"@(?:mcp\.)?tool", corpus)
    exposed = [{"name": n, "schema_mismatch": "**kwargs" in corpus or "additionalproperties" in corpus}
               for n in dict.fromkeys(tool_names)]
    # Tool poisoning: injection patterns co-located with tool descriptions.
    poisoning = [inj_item for inj_item in context_plane["injected_instructions"]
                 if inj_item.get("type", "").endswith("injection")]
    if poisoning:
        findings.append({"category": "tool_poisoning", "severity": "CRITICAL", "plane": "context",
                         "title": "hidden instruction in tool surface"})
    decision, risk = _decide(caps, inj)
    if poisoning:
        decision, risk = "BLOCK", max(risk, 90)
    return {
        "verdict": {"decision": decision, "risk_score": risk, "confidence": 0.7},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {"capabilities": caps},
            "context_plane": context_plane,
            "mcp_surface": {"exposed_tools": exposed, "tool_poisoning": poisoning},
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": findings,
    }


_POPULAR = ("requests", "urllib3", "numpy", "pandas", "flask", "django", "express",
            "lodash", "react", "axios", "boto3", "pytest", "setuptools")


def _edit_distance_one(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if a == b:
        return False
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) > len(b):
            i += 1
        elif len(b) > len(a):
            j += 1
        else:
            i += 1
            j += 1
    return True


def _analyse_packages(files: list[tuple[str, str]], probe: dict) -> dict:
    corpus = _corpus(files)
    caps = _scan_capabilities(corpus)
    findings: list[dict] = []

    names = {rel.lower() for rel, _ in files}
    manifest_text = "\n".join(
        text for rel, text in files
        if rel.lower() in ("setup.py", "package.json", "pyproject.toml", "setup.cfg")
    ).lower()

    install_hook = bool(
        re.search(r"postinstall|preinstall|cmdclass|install_requires.*subprocess", manifest_text)
        or "setup.py" in names and any(k in corpus for k in ("subprocess", "os.system", "urlopen"))
        or "postinstall" in corpus
    )
    import_hook = any(
        rel.endswith("__init__.py") and any(m in text.lower() for m in ("subprocess", "os.environ", "urlopen", "requests"))
        for rel, text in files
    )
    lifecycle = {
        "install_time": {
            "hook_executed": install_hook,
            "side_effects": [c["capability"] for c in caps if c["capability"] in _CRITICAL_CAPS | _DANGEROUS_CAPS] if install_hook else [],
            "capabilities": [c["capability"] for c in caps] if install_hook else [],
        },
        "import_time": {
            "hook_executed": import_hook,
            "side_effects": [c["capability"] for c in caps] if import_hook else [],
            "capabilities": [c["capability"] for c in caps] if import_hook else [],
        },
    }

    pkg_name = ""
    m = re.search(r'name\s*[=:]\s*["\']([a-zA-Z0-9_.\-]+)["\']', manifest_text)
    if m:
        pkg_name = m.group(1)
    typo = next((p for p in _POPULAR if _edit_distance_one(pkg_name, p)), "")
    deps = re.findall(r'"([a-zA-Z0-9_.\-]+)"\s*:\s*"[\^~>=<0-9]', manifest_text)
    supply_chain = {
        "dependencies": [{"name": d, "cve": []} for d in dict.fromkeys(deps)],
        "typosquat": {"suspected": bool(typo), "of": typo},
        "dependency_confusion": False,
    }
    if install_hook:
        findings.append({"category": "install_hook", "severity": "CRITICAL",
                         "title": "install-time code execution"})
    if typo:
        findings.append({"category": "typosquat", "severity": "HIGH",
                         "title": f"name resembles '{typo}'"})

    inj = 0.4 if install_hook or typo else 0.0
    decision, risk = _decide(caps, inj)
    if install_hook or typo:
        decision, risk = "BLOCK", max(risk, 85)
    return {
        "verdict": {"decision": decision, "risk_score": risk, "confidence": 0.7},
        "evidence": {
            "proof_of_execution": _proof_of_execution(probe),
            "action_plane": {"capabilities": caps},
            "lifecycle": lifecycle,
            "supply_chain": supply_chain,
            "capability_manifest": [c["capability"] for c in caps],
        },
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
# repositories: supply-chain layer (dependencies, secrets, licence)
# --------------------------------------------------------------------------- #
def _basename(rel: str) -> str:
    return rel.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _top_dir(rel: str) -> str:
    return rel.replace("\\", "/").split("/", 1)[0].lower()


def _parse_dependencies(files: list[tuple[str, str]]) -> list[dict]:
    deps: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str, ecosystem: str) -> None:
        name = (name or "").strip()
        key = (ecosystem, name.lower())
        if not name or key in seen:
            return
        seen.add(key)
        deps.append({"name": name, "version": (version or "").strip(), "ecosystem": ecosystem, "cve": []})

    for rel, text in files:
        base = _basename(rel)
        if base == "requirements.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line or line[0] in "#-":
                    continue
                m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([0-9][\w.\-]*))?", line)
                if m:
                    add(m.group(1), m.group(2) or "", "pypi")
        elif base == "package.json":
            data = None
            with contextlib.suppress(ValueError, TypeError):
                data = json.loads(text)
            if isinstance(data, dict):
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    block = data.get(section)
                    if isinstance(block, dict):
                        for name, ver in block.items():
                            add(str(name), str(ver), "npm")
            else:
                for name, ver in re.findall(r'"([A-Za-z0-9_.@/\-]+)"\s*:\s*"([\^~>=<0-9][^"]*)"', text):
                    add(name, ver, "npm")
        elif base in ("pyproject.toml", "setup.py", "setup.cfg", "pipfile"):
            for name, ver in re.findall(r'["\']?([A-Za-z0-9_.\-]+)["\']?\s*(?:[=<>~!]=)\s*["\']?([0-9][\w.\-]*)', text):
                add(name, ver, "pypi")
        elif base == "go.mod":
            for name, ver in re.findall(r'(?m)^\s*([\w.\-]+(?:/[\w.\-]+)+)\s+v([\d][\w.\-]*)', text):
                add(name, "v" + ver, "go")
        elif base == "cargo.toml":
            for name, ver in re.findall(r'(?m)^\s*([A-Za-z0-9_\-]+)\s*=\s*["\']([\d][\w.\-]*)', text):
                add(name, ver, "crates")
    return deps


def _scan_secrets(files: list[tuple[str, str]]) -> list[dict]:
    out: list[dict] = []
    for rel, text in files:
        lines = text.splitlines()
        for stype, pat in _SECRET_PATTERNS:
            for i, ln in enumerate(lines):
                if pat.search(ln):
                    out.append({"file": rel, "line": i + 1, "type": stype, "redacted": True})
                    break
    return out


def _repo_supply_chain(files: list[tuple[str, str]], deps: list[dict]) -> dict:
    manifest_text = "\n".join(
        text for rel, text in files
        if _basename(rel) in ("setup.py", "package.json", "pyproject.toml", "setup.cfg", "pipfile")
    ).lower()

    typosquat = []
    for d in deps:
        near = next((p for p in _POPULAR if _edit_distance_one(d["name"].lower(), p)), "")
        if near:
            typosquat.append({"name": d["name"], "of": near, "ecosystem": d["ecosystem"]})

    src_pkgs = {_top_dir(rel) for rel, _ in files if "/" in rel.replace("\\", "/")}
    confusion = []
    for d in deps:
        n = d["name"].lower()
        if n in src_pkgs:
            confusion.append({"name": d["name"], "reason": "shadows a first-party package in the repo"})
        elif n.startswith("@") or n.endswith(("-internal", "-private")):
            confusion.append({"name": d["name"], "reason": "internal-looking name resolvable from a public registry"})

    install_scripts = []
    if re.search(r'"(?:pre|post)install"\s*:', manifest_text) or re.search(r"cmdclass|install_requires.*subprocess", manifest_text):
        install_scripts.append({"hook": "install", "detail": "manifest runs code at install time"})
    if _CURL_PIPE.search(manifest_text):
        install_scripts.append({"hook": "install", "detail": "manifest pipes a remote script into a shell"})

    return {
        "dependencies": deps,
        "typosquat": typosquat,
        "dependency_confusion": confusion,
        "install_scripts": install_scripts,
    }


def _repo_licences(files: list[tuple[str, str]]) -> dict:
    manifest = "\n".join(
        text for rel, text in files
        if _basename(rel) in ("package.json", "pyproject.toml", "setup.py", "setup.cfg")
    )
    declared: list[str] = []
    for spdx in _SPDX_LICENCE.findall(manifest):
        if spdx not in declared:
            declared.append(spdx)
    flagged = [{"license": lic, "risk": "strong copyleft"} for lic in declared
               if lic.upper().startswith(("GPL", "AGPL"))]
    return {"declared": declared, "flagged": flagged}


def _analyse_repositories(files: list[tuple[str, str]]) -> dict:
    vulnerabilities: list[dict] = []
    for rel, text in files:
        low = text.lower()
        lines = low.splitlines()
        for cap, signals in _CAPABILITY_SIGNALS.items():
            cwe_desc = _CWE_BY_CAP.get(cap)
            if cwe_desc is None:
                continue
            hit = next((s for s in signals if s in low), None)
            if hit is None:
                continue
            line_no = next((i + 1 for i, ln in enumerate(lines) if hit in ln), 1)
            cwe, desc = cwe_desc
            vulnerabilities.append({
                "file": rel,
                "line": line_no,
                "cwe": cwe,
                "title": f"{cap.replace('_', ' ').title()} in {rel}",
                "description": f"{desc} (marker '{hit}').",
                "remediation": "Review this call path and constrain or remove the capability.",
                "severity": "high" if cap in _CRITICAL_CAPS else "medium",
            })
        if _CURL_PIPE.search(low):
            line_no = next((i + 1 for i, ln in enumerate(lines) if _CURL_PIPE.search(ln)), 1)
            vulnerabilities.append({
                "file": rel, "line": line_no, "cwe": "CWE-494",
                "title": f"Unpinned remote code execution in {rel}",
                "description": "Pipes an unpinned remote script directly into a shell.",
                "remediation": "Pin by digest and verify before executing.",
                "severity": "high",
            })
        text_lines = text.splitlines()
        for pattern, cwe, title, severity in _REPO_PATTERNS:
            m = pattern.search(text)
            if m is None:
                continue
            line_no = next((i + 1 for i, ln in enumerate(text_lines) if pattern.search(ln)), 1)
            vulnerabilities.append({
                "file": rel, "line": line_no, "cwe": cwe,
                "title": f"{title} in {rel}",
                "description": f"{title} at {rel}:{line_no}.",
                "remediation": "Use parameterised/safe APIs and remove the unsafe construct.",
                "severity": severity,
            })

    deps = _parse_dependencies(files)
    supply_chain = _repo_supply_chain(files, deps)
    secrets = _scan_secrets(files)
    licences = _repo_licences(files)
    dep_files = sorted({rel for rel, _ in files if _basename(rel) in _DEP_FILE_NAMES})

    findings: list[dict] = [
        {"category": v["cwe"], "severity": v["severity"].upper(), "title": v["title"],
         "file": v["file"], "location": f"line {v['line']}"}
        for v in vulnerabilities
    ]
    findings += [
        {"category": "leaked_secret", "severity": "CRITICAL", "plane": "supply_chain",
         "title": f"{s['type']} in {s['file']}", "file": s["file"], "location": f"line {s['line']}"}
        for s in secrets
    ]
    findings += [
        {"category": "typosquat", "severity": "HIGH", "plane": "supply_chain",
         "title": f"dependency '{t['name']}' resembles '{t['of']}'", "file": ""}
        for t in supply_chain["typosquat"]
    ]
    findings += [
        {"category": "dependency_confusion", "severity": "HIGH", "plane": "supply_chain",
         "title": f"dependency '{c['name']}' {c['reason']}", "file": ""}
        for c in supply_chain["dependency_confusion"]
    ]
    findings += [
        {"category": "install_script", "severity": "HIGH", "plane": "supply_chain",
         "title": s["detail"], "file": ""}
        for s in supply_chain["install_scripts"]
    ]

    code_critical = any(v["severity"] == "high" for v in vulnerabilities)
    supply_critical = bool(
        secrets or supply_chain["typosquat"] or supply_chain["dependency_confusion"]
        or supply_chain["install_scripts"]
    )
    if code_critical or supply_critical:
        decision, risk = "BLOCK", 90
    elif vulnerabilities:
        decision, risk = "WARN", 45
    else:
        decision, risk = "ALLOW", 8

    return {
        "verdict": {"decision": decision, "risk_score": risk, "confidence": 0.7},
        "evidence": {
            "audit": {"files_analysed": len(files), "dependency_files": dep_files},
            "vulnerabilities": vulnerabilities,
            "supply_chain": supply_chain,
            "secrets": secrets,
            "licenses": licences,
        },
        "findings": findings,
    }


def call_inference(
    context: dict,
    messages: list[dict],
    temperature: float = 0.0,
    max_tokens: int = _INFERENCE_MAX_TOKENS,
) -> str | None:
    """Send a chat completion through the validator's inference proxy.

    The proxy is the only route out of the sandbox: it attaches the miner's
    provider credentials, meters the call against ``context['nonce']``, and
    forwards to Chutes or OpenRouter. Returns the assistant message, or None
    when inference is unavailable so a caller can fall back to static analysis.
    """
    config = (context or {}).get("inference") or {}
    api = str(config.get("api") or "").rstrip("/")
    api_key = str(config.get("api_key") or "")
    model = str(config.get("model") or "")
    if not api or not api_key or not model:
        return None

    body = json.dumps(
        {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310
        f"{api}/v1/chat/completions",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Phylax-Provider": str(config.get("provider") or ""),
            "X-Phylax-Nonce": str((context or {}).get("nonce") or ""),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=_INFERENCE_TIMEOUT_S) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None

    choices = payload.get("choices") or []
    if not choices:
        return None
    message = (choices[0] or {}).get("message") or {}
    return str(message.get("content") or "").strip() or None


def _declared_intent(files: list[tuple[str, str]]) -> str:
    wanted = ("readme", "skill.md", "manifest.json", "package.json", "pyproject.toml",
              "setup.py", "mcp.json", "description")
    for rel, text in files:
        name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if any(w in name for w in wanted):
            return f"--- {rel} ---\n{text[:4000]}"
    return "no manifest or description found"


def _observed_summary(observed: dict) -> str:
    if not observed:
        return "artifact was not detonated for this track"
    capabilities = observed.get("capabilities") or []
    phases = observed.get("phases") or {}
    lines = [f"capabilities exercised at runtime: {', '.join(map(str, capabilities)) or 'none'}"]
    for phase, detail in phases.items():
        if not isinstance(detail, dict):
            continue
        seen = detail.get("capabilities") or []
        lines.append(f"{phase}: {', '.join(map(str, seen)) or 'no observable effect'}")
    if observed.get("error"):
        lines.append(f"detonation error: {observed['error']}")
    return "\n".join(lines)


def _review_prompt(
    track: str, files: list[tuple[str, str]], result: dict, observed: dict
) -> list[dict]:
    corpus = []
    budget = _REVIEW_CHARS
    for rel, text in files:
        if budget <= 0:
            break
        chunk = text[:budget]
        corpus.append(f"--- {rel} ---\n{chunk}")
        budget -= len(chunk)
    findings = json.dumps(result.get("findings") or [], indent=2)[:4000]
    return [
        {
            "role": "system",
            "content": (
                "You audit AI supply chain artifacts. The artifact was executed in an "
                "isolated sandbox and its runtime behaviour was recorded, so judge what "
                "it DID against what it CLAIMS to do. A capability the artifact never "
                "declares is the strongest signal; a declared capability is not a "
                "finding on its own. Reply with JSON only: "
                '{"decision": "ALLOW|WARN|BLOCK", "findings": '
                '[{"category": str, "severity": str, "title": str}]}.'
            ),
        },
        {
            "role": "user",
            "content": (
                f"Track: {track}\n\n"
                f"What the artifact declares:\n{_declared_intent(files)}\n\n"
                f"What it did when executed:\n{_observed_summary(observed)}\n\n"
                f"Static analysis found:\n{findings}\n\n"
                f"Source:\n{chr(10).join(corpus)}"
            ),
        },
    ]


def _merge_review(result: dict, raw: str) -> dict:
    text = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    try:
        review = json.loads(text)
    except ValueError:
        return result
    if not isinstance(review, dict):
        return result

    decision = str(review.get("decision") or "").upper()
    if decision in ("ALLOW", "WARN", "BLOCK"):
        verdict = result.setdefault("verdict", {})
        rank = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
        if rank.get(decision, 0) > rank.get(str(verdict.get("decision", "ALLOW")).upper(), 0):
            verdict["decision"] = decision
            verdict["risk_score"] = max(int(verdict.get("risk_score", 0) or 0), 70)

    seen = {
        (str(f.get("category", "")).lower(), str(f.get("title", "")).lower())
        for f in result.get("findings") or []
        if isinstance(f, dict)
    }
    for item in review.get("findings") or []:
        if not isinstance(item, dict) or not item.get("title"):
            continue
        key = (str(item.get("category", "")).lower(), str(item.get("title", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        result.setdefault("findings", []).append(
            {
                "category": str(item.get("category") or "llm_review"),
                "severity": str(item.get("severity") or "MEDIUM").upper(),
                "title": str(item["title"])[:160],
            }
        )
    return result


def agent_main(context: dict | None = None) -> dict:
    context = context or {}
    track = context.get("track", "skills")
    artifact_dir = context.get("artifact_dir", "/task/artifact")
    probe = context.get("probe") or {}
    files = _read_files(artifact_dir)

    if track == "mcp_servers":
        result = _analyse_mcp(files, probe)
    elif track == "packages":
        result = _analyse_packages(files, probe)
    elif track == "repositories":
        result = _analyse_repositories(files)
    else:
        result = _analyse_skills(files, probe)

    observed = context.get("observed") or {}
    reviewed = call_inference(context, _review_prompt(track, files, result, observed))
    if reviewed:
        result = _merge_review(result, reviewed)
    return result
