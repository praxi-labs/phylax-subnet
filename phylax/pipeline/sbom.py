"""
phylax/pipeline/sbom.py

Layer 2: SBOM generation + supply-chain risk analysis.

Generates a Software Bill of Materials for the bundle and checks each
dependency against:
  - CVE database (osv.dev or local snapshot)
  - Typosquatting heuristics (Levenshtein distance to known popular packages)
  - Install-hook detection (postinstall scripts, setup.py side effects)
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from phylax.protocol import Finding, FindingEvidence, Severity


# A small starter list of high-profile packages used for typosquat detection.
# Production deployments should load the top-10k from PyPI's BigQuery dataset.
POPULAR_PACKAGES = {
    "requests", "numpy", "pandas", "django", "flask", "fastapi",
    "pydantic", "sqlalchemy", "pytest", "scikit-learn", "tensorflow",
    "torch", "transformers", "openai", "anthropic", "langchain",
    "bittensor", "boto3", "matplotlib", "scipy",
}

INSTALL_HOOK_PATTERNS = [
    re.compile(r"cmdclass\s*=\s*\{[^}]*install", re.IGNORECASE),
    re.compile(r"def\s+run\s*\(.*\):", re.IGNORECASE),
    re.compile(r"postinstall|preinstall", re.IGNORECASE),
]


@dataclass
class SBOMResult:
    sbom_hash:          Optional[str]   = None
    packages:           List[dict]      = field(default_factory=list)
    high_risk_packages: List[str]       = field(default_factory=list)
    known_vulns:        List[str]       = field(default_factory=list)  # CVE IDs
    install_hooks:      List[str]       = field(default_factory=list)
    findings:           List[Finding]   = field(default_factory=list)


class SBOMAnalyzer:
    """
    Build an SBOM for the skill bundle and flag supply-chain risk.

    Prefers `syft` if installed for proper SBOM generation; falls back to a
    minimal parser of common manifest files (requirements.txt, pyproject.toml,
    package.json) when syft is unavailable.
    """

    def __init__(self, use_syft: bool = True):
        self.use_syft = use_syft

    def analyze(self, bundle_path: str) -> SBOMResult:
        result = SBOMResult()
        root = Path(bundle_path)

        # Generate the SBOM
        sbom = self._generate_sbom(root)
        result.packages  = sbom
        result.sbom_hash = self._hash_sbom(sbom)

        # Detect install hooks in setup.py / package.json
        result.install_hooks = self._detect_install_hooks(root, result)

        # Typosquat / known-bad / vulnerability checks
        for pkg in sbom:
            name = pkg.get("name", "")
            self._check_package(name, pkg, result)

        return result

    # -----------------------------------------------------------------------
    # SBOM generation
    # -----------------------------------------------------------------------

    def _generate_sbom(self, root: Path) -> list[dict]:
        if self.use_syft:
            sbom = self._syft(root)
            if sbom is not None:
                return sbom
        return self._manual_manifest_parse(root)

    def _syft(self, root: Path) -> Optional[list[dict]]:
        try:
            proc = subprocess.run(
                ["syft", "scan", str(root), "-o", "cyclonedx-json", "-q"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(proc.stdout or "{}")
            components = data.get("components", [])
            return [
                {"name": c.get("name"), "version": c.get("version"), "type": c.get("type", "library")}
                for c in components
            ]
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            return None

    def _manual_manifest_parse(self, root: Path) -> list[dict]:
        pkgs = []

        # requirements.txt
        for req_file in root.rglob("requirements*.txt"):
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # name[==version]
                m = re.match(r"^([A-Za-z0-9_\-.\[\]]+)\s*([<>=!~]+)?\s*([0-9A-Za-z._\-]+)?", line)
                if m:
                    pkgs.append({
                        "name": m.group(1).split("[")[0].lower(),
                        "version": m.group(3) or "unpinned",
                        "type": "python",
                    })

        # pyproject.toml (TOML parser optional)
        for pyproj in root.rglob("pyproject.toml"):
            try:
                try:
                    import tomllib                  # py3.11+
                except ImportError:
                    import tomli as tomllib         # type: ignore
                data = tomllib.loads(pyproj.read_text(encoding="utf-8", errors="ignore"))
                for dep in data.get("project", {}).get("dependencies", []):
                    m = re.match(r"^([A-Za-z0-9_\-.]+)", dep)
                    if m:
                        pkgs.append({"name": m.group(1).lower(), "version": "unpinned", "type": "python"})
            except Exception:
                pass

        # package.json
        for pkg_json in root.rglob("package.json"):
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                for kind in ("dependencies", "devDependencies"):
                    for name, ver in (data.get(kind) or {}).items():
                        pkgs.append({"name": name, "version": ver, "type": "npm"})
            except Exception:
                pass

        return pkgs

    # -----------------------------------------------------------------------
    # Risk checks
    # -----------------------------------------------------------------------

    def _check_package(self, name: str, pkg: dict, result: SBOMResult) -> None:
        # Typosquat check (Python ecosystem only — extend as needed)
        if pkg.get("type") in ("python", None):
            squat = self._typosquat_target(name)
            if squat:
                result.high_risk_packages.append(name)
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Possible typosquat of '{squat}'",
                    description=f"Dependency '{name}' closely resembles popular package '{squat}'.",
                    evidence=FindingEvidence(snippet=f"{name} vs {squat}"),
                    recommendation=f"Verify intent — did you mean '{squat}'?",
                    owasp_ref="AG07 — Insecure Supply Chain",
                ))

        # CVE lookup (stub — production uses osv.dev or local DB)
        cves = self._lookup_cves(name, pkg.get("version", ""))
        for cve in cves:
            result.known_vulns.append(cve)
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Known vulnerability: {cve}",
                description=f"Package '{name}'@{pkg.get('version')} has known CVE {cve}",
                evidence=FindingEvidence(snippet=f"{name}@{pkg.get('version')}"),
                recommendation=f"Upgrade '{name}' to a patched version.",
                owasp_ref="AG07 — Insecure Supply Chain",
            ))

    @staticmethod
    def _typosquat_target(name: str) -> Optional[str]:
        """Return the popular package this name most resembles, if any."""
        if not name or name in POPULAR_PACKAGES:
            return None
        for pop in POPULAR_PACKAGES:
            if SBOMAnalyzer._levenshtein(name, pop) == 1 and len(pop) > 4:
                return pop
        return None

    @staticmethod
    def _levenshtein(a: str, b: str) -> int:
        if len(a) < len(b):
            return SBOMAnalyzer._levenshtein(b, a)
        if not b:
            return len(a)
        previous = list(range(len(b) + 1))
        for i, ca in enumerate(a):
            current = [i + 1]
            for j, cb in enumerate(b):
                insert = previous[j + 1] + 1
                delete = current[j] + 1
                substitute = previous[j] + (ca != cb)
                current.append(min(insert, delete, substitute))
            previous = current
        return previous[-1]

    def _lookup_cves(self, name: str, version: str) -> list[str]:
        """
        Look up CVEs for a package@version.
        Production: query osv.dev (https://osv.dev/docs/) or a local mirror.
        Stub: return empty list.
        """
        return []

    # -----------------------------------------------------------------------

    def _detect_install_hooks(self, root: Path, result: SBOMResult) -> list[str]:
        hooks = []
        for setup_py in root.rglob("setup.py"):
            text = setup_py.read_text(encoding="utf-8", errors="ignore")
            for pat in INSTALL_HOOK_PATTERNS:
                if pat.search(text):
                    rel = str(setup_py.relative_to(root))
                    hooks.append(rel)
                    result.findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Custom install hook in setup.py",
                        description=f"setup.py contains code that runs at install time: {rel}",
                        evidence=FindingEvidence(line_ref=rel),
                        recommendation="Audit install-time code carefully — common malware vector.",
                        owasp_ref="AG07 — Insecure Supply Chain",
                    ))
                    break

        for pkg_json in root.rglob("package.json"):
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                scripts = data.get("scripts", {}) or {}
                for hook in ("preinstall", "install", "postinstall"):
                    if hook in scripts:
                        rel = str(pkg_json.relative_to(root))
                        hooks.append(f"{rel}:{hook}")
                        result.findings.append(Finding(
                            severity=Severity.HIGH,
                            title=f"npm {hook} hook detected",
                            description=f"package.json defines a {hook} script in {rel}",
                            evidence=FindingEvidence(line_ref=rel, snippet=str(scripts[hook])[:200]),
                            recommendation="Audit install-time script — common malware vector.",
                            owasp_ref="AG07 — Insecure Supply Chain",
                        ))
            except Exception:
                pass

        return hooks

    @staticmethod
    def _hash_sbom(sbom: list[dict]) -> str:
        canon = json.dumps(sbom, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canon.encode()).hexdigest()
