from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("ignore_previous",
     re.compile(r"ignore (?:all )?(?:previous|prior|above) (?:instructions?|prompts?)", re.IGNORECASE),
     "instruction override directive"),
    ("forget_instructions",
     re.compile(r"forget (?:your |the )?(?:previous|prior|original|system) (?:instructions?|prompt|rules?)", re.IGNORECASE),
     "instruction forget directive"),
    ("act_as_jailbreak",
     re.compile(r"act as (?:if you (?:are|were)|though you have) (?:no |unrestricted )(?:rules?|restrictions?|limits?)", re.IGNORECASE),
     "jailbreak persona override"),
    ("system_role_swap",
     re.compile(r"you are now (?:the |an? )?(?:system|admin|root|developer|unrestricted)", re.IGNORECASE),
     "role swap to privileged"),
    ("dan_pattern",
     re.compile(r"\b(?:DAN|do anything now)\b", re.IGNORECASE),
     "DAN-style jailbreak"),
]

CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("env_dump",
     re.compile(r"(?:read|dump|print|show|cat|expose|leak) (?:all )?(?:env(?:ironment)? (?:vars?|variables?)|\$ENV|os\.environ)", re.IGNORECASE),
     "environment variable enumeration"),
    ("aws_creds",
     re.compile(r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)", re.IGNORECASE),
     "AWS credential reference"),
    ("github_token",
     re.compile(r"\b(?:GITHUB|GH)_TOKEN\b|\bgh[ps]_[A-Za-z0-9]{36,}\b"),
     "GitHub token reference / literal"),
    ("openai_key",
     re.compile(r"\bsk-[A-Za-z0-9]{20,}\b|OPENAI_API_KEY", re.IGNORECASE),
     "OpenAI API key reference / literal"),
    ("ssh_key_read",
     re.compile(r"(?:cat|read|open|access) (?:~?/\.ssh|/root/\.ssh|id_rsa|id_ed25519)", re.IGNORECASE),
     "SSH key access"),
    ("netrc_read",
     re.compile(r"(?:cat|read|open|access) (?:~?/\.netrc|\.netrc)", re.IGNORECASE),
     ".netrc credential access"),
]

SHELL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("rm_rf_root",
     re.compile(r"rm\s+-rf\s+(?:/(?:\s|$|\*)|~/?)"),
     "destructive rm targeting root or home"),
    ("curl_pipe_shell",
     re.compile(r"curl\s+[^|]+\|\s*(?:sh|bash|zsh)\b"),
     "remote-code-execution via curl | sh"),
    ("wget_pipe_shell",
     re.compile(r"wget\s+[^|]+(?:-O-|\s)\s*\|\s*(?:sh|bash|zsh)\b"),
     "remote-code-execution via wget | sh"),
    ("nc_reverse_shell",
     re.compile(r"\bnc\s+[^\s]+\s+\d+\s+-e\s+/bin/(?:sh|bash)|/bin/(?:sh|bash)\s+-i\s+>&\s*/dev/tcp/"),
     "netcat reverse shell"),
    ("dd_of_dev",
     re.compile(r"dd\s+if=[^\s]+\s+of=/dev/(?:sd[a-z]|nvme|disk)"),
     "raw disk overwrite"),
]

EXFIL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("post_to_external",
     re.compile(r"(?:POST|curl\s+-X\s*POST|requests\.post)\s+(?:to\s+)?https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)"),
     "POST to external URL"),
    ("base64_encode_file",
     re.compile(r"base64\s+(?:-w0\s+)?(?:~?/\.|/etc/|/root/)"),
     "base64-encode a sensitive path"),
    ("send_to_pastebin",
     re.compile(r"https?://(?:pastebin\.com|paste\.ee|ix\.io|0x0\.st|transfer\.sh|file\.io)/"),
     "pastebin-class exfiltration host"),
    ("dns_exfil",
     re.compile(r"dig\s+\+short\s+[^\s]+\.[a-z]+\s+TXT|nslookup\s+[A-Za-z0-9+/=]{20,}"),
     "DNS-based exfiltration"),
]

TOOL_BODY_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("declares_network_tool",
     re.compile(r"^\s*(?:tool:|capability:|requires:)\s*network", re.IGNORECASE | re.MULTILINE),
     "declares network capability"),
    ("declares_shell_tool",
     re.compile(r"^\s*(?:tool:|capability:|requires:)\s*(?:shell|bash|exec)", re.IGNORECASE | re.MULTILINE),
     "declares shell/exec capability"),
    ("declares_filesystem_write",
     re.compile(r"^\s*(?:tool:|capability:|requires:)\s*(?:filesystem|fs)[\.: ]+write", re.IGNORECASE | re.MULTILINE),
     "declares filesystem write capability"),
]


_URL_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9\-_.]+\.[a-zA-Z]{2,})")

_SEVERITY_BY_BANK = {
    "INJECTION_PATTERNS":   "HIGH",
    "CREDENTIAL_PATTERNS":  "CRITICAL",
    "SHELL_PATTERNS":       "CRITICAL",
    "EXFIL_PATTERNS":       "CRITICAL",
    "TOOL_BODY_PATTERNS":   "LOW",
}

_PATTERN_BANKS = (
    ("INJECTION_PATTERNS",   INJECTION_PATTERNS),
    ("CREDENTIAL_PATTERNS",  CREDENTIAL_PATTERNS),
    ("SHELL_PATTERNS",       SHELL_PATTERNS),
    ("EXFIL_PATTERNS",       EXFIL_PATTERNS),
    ("TOOL_BODY_PATTERNS",   TOOL_BODY_PATTERNS),
)


_CANARY_PREFIX = "<!-- phylax:canary:"
_CANARY_SUFFIX = " -->"
_CANARY_RE = re.compile(
    re.escape(_CANARY_PREFIX) + r"([0-9a-f]{32,64})" + re.escape(_CANARY_SUFFIX)
)


def extract_canary(text: str) -> str | None:
    m = _CANARY_RE.search(text or "")
    return m.group(1) if m else None


def layer0_sync_hash() -> str:
    h = hashlib.sha256()
    for bank_name, bank in _PATTERN_BANKS:
        severity = _SEVERITY_BY_BANK[bank_name]
        for kind, regex, _description in bank:
            h.update(f"{bank_name}|{kind}|{regex.pattern}|{severity}\n".encode("utf-8"))
    return "sha256:" + h.hexdigest()


@dataclass
class DeclarativeCapabilities:
    declared_capabilities: list[str] = field(default_factory=list)
    observed_urls: list[str] = field(default_factory=list)
    observed_hosts: list[str] = field(default_factory=list)
    references_filesystem: bool = False
    references_shell: bool = False
    references_network: bool = False
    references_secrets: bool = False


@dataclass
class DeclarativeFinding:
    kind: str
    pattern_bank: str
    description: str
    severity: str
    snippet: str = ""


@dataclass
class DeclarativeEvidence:
    canary_id_found: str | None
    skill_md_fingerprint: str
    findings_count: int
    layer0_sync_hash: str
    analysis_duration_ms: int


def _snippet_around(text: str, span: tuple[int, int], window: int = 60) -> str:
    start = max(0, span[0] - window)
    end = min(len(text), span[1] + window)
    return text[start:end].replace("\n", " ").strip()


def analyze_skill_md(
    text: str,
) -> tuple[DeclarativeCapabilities, list[DeclarativeFinding]]:
    caps = DeclarativeCapabilities()
    findings: list[DeclarativeFinding] = []
    if not text:
        return caps, findings

    seen_hosts: set[str] = set()
    for m in _URL_RE.finditer(text):
        host = m.group(1).lower()
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        caps.observed_urls.append(m.group(0))
        caps.observed_hosts.append(host)
        caps.references_network = True

    for bank_name, bank in _PATTERN_BANKS:
        severity = _SEVERITY_BY_BANK[bank_name]
        for kind, regex, description in bank:
            for m in regex.finditer(text):
                findings.append(DeclarativeFinding(
                    kind=kind,
                    pattern_bank=bank_name,
                    description=description,
                    severity=severity,
                    snippet=_snippet_around(text, m.span()),
                ))
                if bank_name == "SHELL_PATTERNS":
                    caps.references_shell = True
                elif bank_name == "CREDENTIAL_PATTERNS":
                    caps.references_secrets = True
                elif bank_name == "EXFIL_PATTERNS":
                    caps.references_network = True
                elif bank_name == "TOOL_BODY_PATTERNS":
                    if "shell" in kind:
                        caps.references_shell = True
                    elif "filesystem" in kind:
                        caps.references_filesystem = True
                    elif "network" in kind:
                        caps.references_network = True
                    caps.declared_capabilities.append(kind.replace("declares_", ""))
    return caps, findings


_SEVERITY_RISK = {
    "LOW":      5,
    "MEDIUM":  15,
    "HIGH":    30,
    "CRITICAL": 50,
}

_VERDICT_THRESHOLD_BLOCK = 50
_VERDICT_THRESHOLD_WARN  = 15


def compute_verdict_from_findings(
    findings: list[DeclarativeFinding],
) -> dict[str, Any]:
    if not findings:
        return {
            "decision":   "ALLOW",
            "risk_score": 0,
            "rationale":  "No pattern matches in SKILL.md.",
        }
    cumulative = 0
    rationales: list[str] = []
    has_critical = False
    for f in findings:
        cumulative += _SEVERITY_RISK.get(f.severity, 5)
        rationales.append(f"{f.severity}: {f.description}")
        if f.severity == "CRITICAL":
            has_critical = True
    risk_score = min(100, cumulative)
    if has_critical or risk_score >= _VERDICT_THRESHOLD_BLOCK:
        decision = "BLOCK"
    elif risk_score >= _VERDICT_THRESHOLD_WARN:
        decision = "WARN"
    else:
        decision = "ALLOW"
    return {
        "decision":   decision,
        "risk_score": risk_score,
        "rationale":  " | ".join(rationales[:5]),
    }


def derive_declarative_policy(
    capabilities: DeclarativeCapabilities,
    findings: list[DeclarativeFinding],
) -> dict[str, Any]:
    blocked_hosts: set[str] = set()
    for f in findings:
        if f.kind == "send_to_pastebin":
            for m in _URL_RE.finditer(f.snippet):
                blocked_hosts.add(m.group(1).lower())
    egress = [
        h for h in capabilities.observed_hosts
        if h not in blocked_hosts
    ]
    return {
        "egress_allowlist": sorted(egress),
        "egress_denylist":  sorted(blocked_hosts),
        "shell_access":     False,
        "env_allowlist":    [],
        "filesystem": {
            "read_only":       [],
            "restricted_write": [],
        },
        "max_memory_mb":   256,
        "timeout_seconds":  30,
    }


def skill_md_fingerprint(text: str) -> str:
    stripped = _CANARY_RE.sub("", text or "")
    return "sha256:" + hashlib.sha256(stripped.encode("utf-8")).hexdigest()
