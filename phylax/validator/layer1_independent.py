from __future__ import annotations

import io
import os
import tempfile
import time
import zipfile
from dataclasses import dataclass, field

from phylax.pipeline.static import StaticAnalysisResult, StaticAnalyzer
from phylax.protocol import Severity

_SEVERITY_RISK = {
    Severity.LOW:      5,
    Severity.MEDIUM:  15,
    Severity.HIGH:    30,
    Severity.CRITICAL: 50,
}

_VERDICT_THRESHOLD_BLOCK = 50
_VERDICT_THRESHOLD_WARN  = 15


@dataclass
class ValidatorLayer1Result:
    verdict: str
    risk_score: int
    rationale: str
    findings_count: int = 0
    domains_observed: list[str] = field(default_factory=list)
    fs_writes: list[str] = field(default_factory=list)
    shell_commands: list[str] = field(default_factory=list)
    files_scanned: int = 0
    analysis_duration_ms: int = 0


def _verdict_from_findings(static_result: StaticAnalysisResult) -> tuple[str, int, str]:
    cumulative = 0
    rationales: list[str] = []
    has_critical = False
    for f in static_result.findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(str(f.severity))
        cumulative += _SEVERITY_RISK.get(sev, 5)
        rationales.append(f"{sev.value}: {f.title}")
        if sev == Severity.CRITICAL:
            has_critical = True
    if static_result.shell_commands:
        cumulative += 10
        rationales.append("MEDIUM: shell command observed")
    if any(not w.startswith(("/tmp", "/var/tmp")) for w in static_result.fs_writes):  # noqa: S108  # path-prefix check, not a temp file creation
        cumulative += 5
        rationales.append("LOW: write outside /tmp")
    risk_score = min(100, cumulative)

    if has_critical or risk_score >= _VERDICT_THRESHOLD_BLOCK:
        decision = "BLOCK"
    elif risk_score >= _VERDICT_THRESHOLD_WARN:
        decision = "WARN"
    else:
        decision = "ALLOW"
    return decision, risk_score, " | ".join(rationales[:5]) or "no findings"


def run_validator_layer1(
    bundle_bytes: bytes,
    *,
    staging_root: str | None = None,
) -> ValidatorLayer1Result:
    start = time.time()
    root = staging_root or os.path.expanduser(
        os.getenv("PHYLAX_EVIDENCE_DIR", tempfile.gettempdir())
    )
    os.makedirs(root, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="phylax_l1_", dir=root)

    try:
        with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as zf:
            zf.extractall(tmp)
    except zipfile.BadZipFile:
        with open(os.path.join(tmp, "main.py"), "wb") as fh:
            fh.write(bundle_bytes)

    analyzer = StaticAnalyzer(run_bandit=True, run_semgrep=False)
    result = analyzer.analyze(tmp).dedup()
    decision, risk_score, rationale = _verdict_from_findings(result)

    return ValidatorLayer1Result(
        verdict=decision,
        risk_score=risk_score,
        rationale=rationale,
        findings_count=len(result.findings),
        domains_observed=list(result.network_domains),
        fs_writes=list(result.fs_writes),
        shell_commands=list(result.shell_commands),
        files_scanned=result.files_scanned,
        analysis_duration_ms=int((time.time() - start) * 1000),
    )
