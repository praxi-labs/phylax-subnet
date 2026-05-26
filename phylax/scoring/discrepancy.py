"""Manifest-vs-behavior discrepancy engine — the structural fix for the
Detection axis being a tautology.

Until this lands, both miner and validator compute the verdict with the
same hand-coded heuristic, and the synth corpus labels its expected
verdicts with that same heuristic, so "miner agrees with ground truth"
reduces to "miner agrees with itself." Detection scored 1.0 by
construction, even for the canonical exfiltration pattern.

The discrepancy engine breaks the loop. The ground truth is now the
delta between the skill's declared SKILL.md manifest (the contract) and
the sandbox's observed behavior (the reality). Under-declaration —
the skill did things it didn't say it would — is a security violation.
Over-declaration — manifest is broader than what the skill actually
uses — is a soft signal of over-permissive design.

The compute is fully deterministic: same observed map + same manifest
produces the same DiscrepancyReport on any host. No LLM, no judgment,
nothing that could be prompt-injected or vary between runs.

When a skill ships without a SKILL.md, the manifest defaults to
IMPLICIT_ZERO_TRUST and any observed behavior counts as discrepancy —
which is the structural pressure for ecosystem-wide manifest adoption.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from phylax.manifest import SkillManifest
from phylax.protocol import (
    CapabilityMap,
    Severity,
    Verdict,
    VerdictBlock,
)


@dataclass(frozen=True)
class DiscrepancyFinding:
    """One specific gap between what the manifest declared and what the
    sandbox observed. ``axis`` is one of network/filesystem/process/
    secrets. ``kind`` distinguishes the gap class (undeclared_egress,
    undeclared_domain, etc.) so downstream consumers can group/route by
    pattern without parsing ``detail``."""

    axis: str
    kind: str
    detail: str
    severity: Severity


@dataclass
class DiscrepancyReport:
    findings: list[DiscrepancyFinding] = field(default_factory=list)
    discrepancy_score: float = 0.0
    verdict: Verdict = Verdict.ALLOW
    risk_score: int = 0


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.5,
    Severity.MEDIUM: 0.25,
    Severity.LOW: 0.10,
}


_CANARY_PATH_MARKER = ".phylax_canary_"


def _is_canary_path(p: str) -> bool:
    """The harness writes + reads a canary file at ``/evidence/.phylax_
    canary_<id>`` to prove sandbox execution. It's harness-internal
    plumbing, not a real filesystem capability of the skill, so the
    discrepancy engine ignores it."""
    return _CANARY_PATH_MARKER in p


def _dedup(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def compute_discrepancy(
    observed: CapabilityMap,
    declared: SkillManifest,
) -> DiscrepancyReport:
    """Compare what the sandbox observed against what the manifest declared.

    Asymmetric semantics: under-declaration (skill did something not in
    the manifest) is a security finding; over-declaration (manifest
    promised something the skill never used) is silent here — the soft
    "tighten your manifest" hint is a separate concern, surfaced through
    a different reporting path so it doesn't crater the verdict.
    """
    findings: list[DiscrepancyFinding] = []

    # ----- Network --------------------------------------------------------
    obs_domains = _dedup(observed.network.observed_domains)
    obs_ips = _dedup(observed.network.observed_ips)
    declared_domains = set(declared.network.allowed_domains)
    declared_ips = set(declared.network.allowed_ips)

    if observed.network.egress and not declared.network.egress:
        findings.append(DiscrepancyFinding(
            axis="network",
            kind="undeclared_egress",
            detail="skill made outbound network calls but manifest declares network.egress: false",
            severity=Severity.CRITICAL,
        ))

    for d in obs_domains:
        if d not in declared_domains:
            findings.append(DiscrepancyFinding(
                axis="network",
                kind="undeclared_domain",
                detail=f"skill contacted {d!r} which is not in network.allowed_domains",
                severity=Severity.HIGH,
            ))
    for ip in obs_ips:
        if ip not in declared_ips:
            findings.append(DiscrepancyFinding(
                axis="network",
                kind="undeclared_ip",
                detail=f"skill connected to IP {ip!r} which is not in network.allowed_ips",
                severity=Severity.HIGH,
            ))

    # ----- Process --------------------------------------------------------
    if observed.process.shell_exec and not declared.process.shell_exec:
        findings.append(DiscrepancyFinding(
            axis="process",
            kind="undeclared_shell",
            detail="skill executed a shell but manifest declares process.shell_exec: false",
            severity=Severity.CRITICAL,
        ))

    declared_commands = set(declared.process.allowed_commands)
    for cmd in _dedup(observed.process.observed_commands):
        if cmd not in declared_commands:
            findings.append(DiscrepancyFinding(
                axis="process",
                kind="undeclared_command",
                detail=f"skill spawned {cmd!r} which is not in process.allowed_commands",
                severity=Severity.HIGH,
            ))

    # ----- Secrets --------------------------------------------------------
    if observed.secrets.env_access and not declared.secrets.env_access:
        findings.append(DiscrepancyFinding(
            axis="secrets",
            kind="undeclared_env_access",
            detail="skill read environment variables but manifest declares secrets.env_access: false",
            severity=Severity.HIGH,
        ))

    declared_vars = set(declared.secrets.allowed_vars)
    for v in _dedup(observed.secrets.observed_vars):
        if v not in declared_vars:
            findings.append(DiscrepancyFinding(
                axis="secrets",
                kind="undeclared_env_var",
                detail=f"skill read env var {v!r} which is not in secrets.allowed_vars",
                severity=Severity.HIGH,
            ))

    # ----- Filesystem -----------------------------------------------------
    declared_ro = set(declared.filesystem.read_only)
    declared_rw = set(declared.filesystem.read_write)

    for p in _dedup(observed.filesystem.writes):
        if _is_canary_path(p):
            continue
        if p not in declared_rw:
            findings.append(DiscrepancyFinding(
                axis="filesystem",
                kind="undeclared_fs_write",
                detail=f"skill wrote to {p!r} which is not in filesystem.read_write",
                severity=Severity.HIGH,
            ))

    for p in _dedup(observed.filesystem.reads):
        if _is_canary_path(p):
            continue
        if p not in declared_ro and p not in declared_rw:
            findings.append(DiscrepancyFinding(
                axis="filesystem",
                kind="undeclared_fs_read",
                detail=f"skill read {p!r} which is not in filesystem.read_only or read_write",
                severity=Severity.MEDIUM,
            ))

    # ----- Aggregate ------------------------------------------------------
    weighted = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)
    # Saturate at 1.0 once weighted gets meaningful. The 5.0 divisor means
    # a single CRITICAL contributes 0.2 to the score, five CRITICALs caps
    # it. Keeps the gradient smooth so a "barely violating" skill isn't
    # treated identically to a "wildly violating" one.
    discrepancy_score = min(1.0, weighted / 5.0)

    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

    if critical_count:
        verdict = Verdict.BLOCK
        risk_score = min(100, 75 + 5 * critical_count)
    elif high_count:
        verdict = Verdict.WARN
        risk_score = min(74, 40 + 4 * high_count)
    elif findings:
        verdict = Verdict.WARN
        risk_score = 20
    else:
        verdict = Verdict.ALLOW
        risk_score = 0

    return DiscrepancyReport(
        findings=findings,
        discrepancy_score=discrepancy_score,
        verdict=verdict,
        risk_score=risk_score,
    )


def combine_verdict(
    discrepancy: DiscrepancyReport,
    static_findings: list,
    known_vulns: list[str],
) -> VerdictBlock:
    """Combine the discrepancy verdict with static-analysis findings and
    SBOM CVE hits to produce the final VerdictBlock the SSSA carries.

    Takes the strictest of the three signals — a skill that declares
    ``shell_exec: true`` and uses it correctly (no discrepancy) can still
    be BLOCKed by a CRITICAL bandit finding or by a known CVE in its
    dependencies. The discrepancy verdict is the ground floor, not a
    ceiling.
    """
    static_critical = [f for f in static_findings if f.severity == Severity.CRITICAL]
    static_high = [f for f in static_findings if f.severity == Severity.HIGH]

    if static_critical or discrepancy.verdict == Verdict.BLOCK:
        decision = Verdict.BLOCK
        risk = max(
            discrepancy.risk_score,
            min(100, 75 + 5 * len(static_critical)) if static_critical else 0,
        )
    elif (
        discrepancy.verdict == Verdict.WARN
        or static_high
        or known_vulns
    ):
        decision = Verdict.WARN
        risk = max(
            discrepancy.risk_score,
            min(74, 40 + 4 * len(static_high)) if static_high else 0,
            55 if known_vulns else 0,
        )
    else:
        decision = Verdict.ALLOW
        risk = 0

    top_reasons: list[str] = []
    for f in discrepancy.findings[:3]:
        top_reasons.append(f"[{f.severity.value}] {f.detail}")
    for f in static_critical[:2] + static_high[:2]:
        top_reasons.append(f"[{f.severity.value}] {f.title}")
    if known_vulns:
        top_reasons.append(f"[CVE] {len(known_vulns)} known vulnerability(ies) in dependencies")

    summary = (
        f"Verdict {decision.value}: risk={risk}. "
        f"{len(discrepancy.findings)} contract violation(s), "
        f"{len(static_findings)} static finding(s), "
        f"{len(known_vulns)} CVE(s)."
    )
    confidence = 0.95 if (discrepancy.findings or static_findings or known_vulns) else 0.99

    return VerdictBlock(
        decision=decision,
        risk_score=risk,
        confidence=confidence,
        summary=summary,
        top_reasons=top_reasons[:5],
    )
