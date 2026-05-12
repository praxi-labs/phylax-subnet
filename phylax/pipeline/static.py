"""
phylax/pipeline/static.py

Layer 1: Static analysis of a skill bundle.

Walks the source tree and looks for:
  - Dangerous API calls (eval, exec, subprocess with shell=True, etc.)
  - Permission-surface patterns (env access, file writes, network usage)
  - Known-bad strings (hardcoded webhook URLs, suspicious base64 blobs)

Optionally invokes external linters (bandit, semgrep) when available.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from phylax.protocol import Finding, FindingEvidence, Severity


# --------------------------------------------------------------------------
# Dangerous patterns
# --------------------------------------------------------------------------

DANGEROUS_CALLS = {
    "eval":               (Severity.HIGH,     "Dynamic code execution via eval()"),
    "exec":               (Severity.HIGH,     "Dynamic code execution via exec()"),
    "compile":            (Severity.MEDIUM,   "Dynamic compilation via compile()"),
    "__import__":         (Severity.MEDIUM,   "Dynamic import via __import__()"),
    "os.system":          (Severity.HIGH,     "Shell execution via os.system()"),
    "os.popen":           (Severity.HIGH,     "Shell execution via os.popen()"),
    "subprocess.Popen":   (Severity.MEDIUM,   "Subprocess invocation"),
    "subprocess.call":    (Severity.MEDIUM,   "Subprocess invocation"),
    "subprocess.run":     (Severity.MEDIUM,   "Subprocess invocation"),
    "pickle.loads":       (Severity.HIGH,     "Unsafe deserialization via pickle"),
    "pickle.load":        (Severity.HIGH,     "Unsafe deserialization via pickle"),
    "yaml.load":          (Severity.HIGH,     "Unsafe YAML load — use safe_load"),
    "marshal.loads":      (Severity.HIGH,     "Unsafe deserialization via marshal"),
}

NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "urllib.request.urlopen", "httpx.get", "httpx.post",
    "socket.socket", "socket.create_connection",
}

ENV_PATTERNS = [
    re.compile(r"os\.environ\.get\(['\"]([^'\"]+)['\"]"),
    re.compile(r"os\.environ\[['\"]([^'\"]+)['\"]"),
    re.compile(r"os\.getenv\(['\"]([^'\"]+)['\"]"),
]

URL_PATTERN     = re.compile(r"https?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
BASE64_PATTERN  = re.compile(r"['\"]([A-Za-z0-9+/]{200,}={0,2})['\"]")
HARDCODED_KEY   = re.compile(r"(api_key|secret|password|token)\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.IGNORECASE)


@dataclass
class StaticAnalysisResult:
    findings:         List[Finding]   = field(default_factory=list)
    fs_reads:         List[str]       = field(default_factory=list)
    fs_writes:        List[str]       = field(default_factory=list)
    network_domains:  List[str]       = field(default_factory=list)
    shell_commands:   List[str]       = field(default_factory=list)
    env_vars:         List[str]       = field(default_factory=list)
    files_scanned:    int             = 0


class StaticAnalyzer:
    """Walk the bundle tree and run pattern-based static checks."""

    def __init__(self, run_bandit: bool = True, run_semgrep: bool = False):
        self.run_bandit  = run_bandit
        self.run_semgrep = run_semgrep

    def analyze(self, bundle_path: str) -> StaticAnalysisResult:
        result = StaticAnalysisResult()
        root = Path(bundle_path)

        for py_file in root.rglob("*.py"):
            try:
                self._scan_python_file(py_file, root, result)
                result.files_scanned += 1
            except Exception:
                # Best-effort — skip unreadable / unparseable files
                continue

        # Optional: external linters
        if self.run_bandit:
            self._run_bandit(root, result)
        if self.run_semgrep:
            self._run_semgrep(root, result)

        return result

    # -----------------------------------------------------------------------

    def _scan_python_file(self, path: Path, root: Path, result: StaticAnalysisResult):
        rel = str(path.relative_to(root))
        source = path.read_text(encoding="utf-8", errors="replace")

        # AST-based dangerous-call detection
        try:
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = self._call_name(node)
                    if name in DANGEROUS_CALLS:
                        sev, title = DANGEROUS_CALLS[name]
                        result.findings.append(Finding(
                            severity=sev,
                            title=title,
                            description=f"Detected `{name}` in {rel}:{node.lineno}",
                            evidence=FindingEvidence(line_ref=f"{rel}:{node.lineno}"),
                            recommendation="Avoid dynamic execution; use safer alternatives.",
                            owasp_ref="AG02 — Insecure Code Execution",
                        ))
                        if "system" in name or "popen" in name or "subprocess" in name:
                            result.shell_commands.append(name)
                    if name in NETWORK_CALLS:
                        # Record network usage capability
                        if "requests" in name or "httpx" in name or "urllib" in name:
                            pass  # domains harvested from URL_PATTERN below
        except SyntaxError:
            pass

        # Regex-based scans
        for m in URL_PATTERN.finditer(source):
            result.network_domains.append(m.group(1))

        for pattern in ENV_PATTERNS:
            for m in pattern.finditer(source):
                result.env_vars.append(m.group(1))

        for m in BASE64_PATTERN.finditer(source):
            result.findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Large base64 blob embedded",
                description=f"Possible obfuscated payload in {rel}",
                evidence=FindingEvidence(
                    line_ref=rel,
                    snippet=m.group(1)[:80] + "…",
                ),
                recommendation="Inspect blob contents; obfuscated payloads are a common malware indicator.",
            ))

        for m in HARDCODED_KEY.finditer(source):
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="Hardcoded credential / secret detected",
                description=f"Potential secret in {rel}",
                evidence=FindingEvidence(line_ref=rel, snippet=m.group(0)[:80]),
                recommendation="Move secrets to environment variables or a secret manager.",
                owasp_ref="AG03 — Sensitive Information Disclosure",
            ))

        # Filesystem heuristics
        if "open(" in source:
            result.fs_reads.append(rel)
        if any(tok in source for tok in [".write(", "shutil.copy", "os.rename", "os.remove"]):
            result.fs_writes.append(rel)

    # -----------------------------------------------------------------------

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        """Reconstruct a dotted call name from an ast.Call node."""
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

    # -----------------------------------------------------------------------
    # External tool integration
    # -----------------------------------------------------------------------

    def _run_bandit(self, root: Path, result: StaticAnalysisResult) -> None:
        try:
            proc = subprocess.run(
                ["bandit", "-r", str(root), "-f", "json", "-q"],
                capture_output=True, text=True, timeout=60,
            )
            import json as _json
            data = _json.loads(proc.stdout or "{}")
            for issue in data.get("results", []):
                sev_map = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
                result.findings.append(Finding(
                    severity=sev_map.get(issue.get("issue_severity", "LOW").upper(), Severity.LOW),
                    title=f"bandit: {issue.get('test_name', 'unknown')}",
                    description=issue.get("issue_text", ""),
                    evidence=FindingEvidence(
                        line_ref=f"{issue.get('filename', '?')}:{issue.get('line_number', 0)}",
                        snippet=issue.get("code", "")[:200],
                    ),
                    recommendation="See bandit documentation for remediation.",
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

    def _run_semgrep(self, root: Path, result: StaticAnalysisResult) -> None:
        try:
            proc = subprocess.run(
                ["semgrep", "--config=auto", "--json", "--quiet", str(root)],
                capture_output=True, text=True, timeout=120,
            )
            import json as _json
            data = _json.loads(proc.stdout or "{}")
            for issue in data.get("results", []):
                sev_map = {"INFO": Severity.LOW, "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH}
                result.findings.append(Finding(
                    severity=sev_map.get(issue.get("extra", {}).get("severity", "INFO").upper(), Severity.LOW),
                    title=f"semgrep: {issue.get('check_id', 'unknown')}",
                    description=issue.get("extra", {}).get("message", ""),
                    evidence=FindingEvidence(
                        line_ref=f"{issue.get('path', '?')}:{issue.get('start', {}).get('line', 0)}",
                    ),
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass
