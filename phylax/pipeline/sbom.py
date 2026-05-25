from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from phylax.protocol import Finding, FindingEvidence, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_CACHE_DIR = Path(os.getenv("PHYLAX_OSV_CACHE_DIR", str(Path.home() / ".phylax" / "osv_cache")))
OSV_CACHE_TTL_SECONDS = 24 * 60 * 60
OSV_TIMEOUT_SECONDS = 10

OSV_ECOSYSTEMS = {
    "python": "PyPI",
    "pypi": "PyPI",
    "npm": "npm",
    "node": "npm",
    "go": "Go",
    "rust": "crates.io",
    "java": "Maven",
    "maven": "Maven",
    "ruby": "RubyGems",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
}


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



def _osv_cache_key(ecosystem: str, name: str, version: str) -> Path:
    digest = hashlib.sha256(f"{ecosystem}|{name.lower()}|{version}".encode()).hexdigest()
    return OSV_CACHE_DIR / f"{digest}.json"


def _osv_cache_get(ecosystem: str, name: str, version: str) -> list[str] | None:
    path = _osv_cache_key(ecosystem, name, version)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if time.time() - data.get("fetched_at", 0) > OSV_CACHE_TTL_SECONDS:
        return None
    return list(data.get("ids", []))


def _osv_cache_put(ecosystem: str, name: str, version: str, ids: list[str]) -> None:
    try:
        OSV_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _osv_cache_key(ecosystem, name, version)
        path.write_text(
            json.dumps({"fetched_at": time.time(), "ids": ids}, sort_keys=True),
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001 — cache failures must never break a scan
        pass


@dataclass
class SBOMResult:
    sbom_hash:          str | None   = None
    packages:           list[dict]      = field(default_factory=list)
    high_risk_packages: list[str]       = field(default_factory=list)
    known_vulns:        list[str]       = field(default_factory=list)
    install_hooks:      list[str]       = field(default_factory=list)
    findings:           list[Finding]   = field(default_factory=list)


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

        sbom = self._generate_sbom(root)
        result.packages  = sbom
        result.sbom_hash = self._hash_sbom(sbom)

        result.install_hooks = self._detect_install_hooks(root, result)

        for pkg in sbom:
            name = pkg.get("name", "")
            self._check_package(name, pkg, result)

        return result


    def _generate_sbom(self, root: Path) -> list[dict]:
        if self.use_syft:
            sbom = self._syft(root)
            if sbom is not None:
                return sbom
        return self._manual_manifest_parse(root)

    def _syft(self, root: Path) -> list[dict] | None:
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

        for req_file in root.rglob("requirements*.txt"):
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_\-.\[\]]+)\s*([<>=!~]+)?\s*([0-9A-Za-z._\-]+)?", line)
                if m:
                    pkgs.append({
                        "name": m.group(1).split("[")[0].lower(),
                        "version": m.group(3) or "unpinned",
                        "type": "python",
                    })

        for pyproj in root.rglob("pyproject.toml"):
            try:
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib  # type: ignore
                data = tomllib.loads(pyproj.read_text(encoding="utf-8", errors="ignore"))
                for dep in data.get("project", {}).get("dependencies", []):
                    m = re.match(r"^([A-Za-z0-9_\-.]+)", dep)
                    if m:
                        pkgs.append({"name": m.group(1).lower(), "version": "unpinned", "type": "python"})
            except Exception:
                pass

        for pkg_json in root.rglob("package.json"):
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                for kind in ("dependencies", "devDependencies"):
                    for name, ver in (data.get(kind) or {}).items():
                        pkgs.append({"name": name, "version": ver, "type": "npm"})
            except Exception:
                pass

        return pkgs


    def _check_package(self, name: str, pkg: dict, result: SBOMResult) -> None:
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

        cves = self._lookup_cves(name, pkg.get("version", ""), pkg.get("type", "python"))
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
    def _typosquat_target(name: str) -> str | None:
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

    _cve_cache: dict[tuple[str, str, str], list[str]] = {}

    def _lookup_cves(self, name: str, version: str, pkg_type: str = "python") -> list[str]:
        """
        Query osv.dev /v1/query for vulnerabilities affecting ``name@version``.

        Two layers of cache: in-memory for the lifetime of this analyzer
        instance, and disk-backed under ``OSV_CACHE_DIR`` with 24h TTL so
        the cache survives process restarts and can be warmed by
        phylax-server's drift watcher.

        Silent-failure semantics: any network / parse error returns an
        empty list. The next scan will retry once the disk cache expires.
        """
        if not name or not version or version == "unpinned":
            return []

        ecosystem = OSV_ECOSYSTEMS.get((pkg_type or "python").lower(), "PyPI")
        cache_key = (ecosystem, name.lower(), version)

        cached = self._cve_cache.get(cache_key)
        if cached is not None:
            return list(cached)

        disk = _osv_cache_get(ecosystem, name, version)
        if disk is not None:
            self._cve_cache[cache_key] = disk
            return list(disk)

        try:
            import httpx
        except ImportError:
            self._cve_cache[cache_key] = []
            return []

        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": ecosystem},
        }
        ids: list[str] = []
        try:
            r = httpx.post(OSV_API_URL, json=payload, timeout=OSV_TIMEOUT_SECONDS)
            if r.status_code == 200:
                for vuln in r.json().get("vulns", []) or []:
                    vid = vuln.get("id")
                    if vid:
                        ids.append(vid)
        except Exception:  # noqa: BLE001
            ids = []

        ids = sorted(set(ids))
        self._cve_cache[cache_key] = ids
        _osv_cache_put(ecosystem, name, version, ids)
        return list(ids)


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

