from phylax.manifest import (
    IMPLICIT_ZERO_TRUST,
    FilesystemManifest,
    NetworkManifest,
    ProcessManifest,
    SecretsManifest,
    SkillManifest,
)
from phylax.protocol import (
    CapabilityMap,
    FilesystemCapability,
    Finding,
    FindingEvidence,
    NetworkCapability,
    ProcessCapability,
    SecretsCapability,
    Severity,
    Verdict,
)
from phylax.scoring.discrepancy import (
    apply_intel_hits,
    combine_verdict,
    compute_discrepancy,
)


def _caps(
    *,
    egress=False, domains=None, ips=None,
    shell_exec=False, commands=None,
    env_access=False, vars_=None,
    reads=None, writes=None,
):
    return CapabilityMap(
        network=NetworkCapability(
            egress=egress,
            observed_domains=domains or [],
            observed_ips=ips or [],
        ),
        process=ProcessCapability(
            shell_exec=shell_exec,
            observed_commands=commands or [],
        ),
        secrets=SecretsCapability(
            env_access=env_access,
            observed_vars=vars_ or [],
        ),
        filesystem=FilesystemCapability(
            reads=reads or [],
            writes=writes or [],
        ),
    )


def _manifest(
    *,
    egress=False, domains=None, ips=None,
    shell_exec=False, commands=None,
    env_access=False, vars_=None,
    read_only=None, read_write=None,
):
    return SkillManifest(
        network=NetworkManifest(
            egress=egress,
            allowed_domains=domains or [],
            allowed_ips=ips or [],
        ),
        process=ProcessManifest(
            shell_exec=shell_exec,
            allowed_commands=commands or [],
        ),
        secrets=SecretsManifest(
            env_access=env_access,
            allowed_vars=vars_ or [],
        ),
        filesystem=FilesystemManifest(
            read_only=read_only or [],
            read_write=read_write or [],
        ),
    )


def test_empty_observed_empty_manifest_no_discrepancy():
    """A skill that did nothing, declared nothing, gets a clean bill of health."""
    report = compute_discrepancy(_caps(), IMPLICIT_ZERO_TRUST)
    assert report.findings == []
    assert report.discrepancy_score == 0.0
    assert report.verdict == Verdict.ALLOW
    assert report.risk_score == 0


def test_undeclared_egress_is_critical():
    """Skill made network calls but manifest declared egress: false. This
    is the canonical 'silent exfiltration' shape — must BLOCK."""
    report = compute_discrepancy(
        _caps(egress=True, domains=["evil.click"]),
        _manifest(),
    )
    assert any(f.kind == "undeclared_egress" and f.severity == Severity.CRITICAL
               for f in report.findings)
    assert report.verdict == Verdict.BLOCK
    assert report.risk_score >= 75


def test_undeclared_domain_is_high():
    """Skill declared egress but called a domain not in the allowlist —
    HIGH severity, escalates to WARN."""
    report = compute_discrepancy(
        _caps(egress=True, domains=["api.stripe.com", "evil.click"]),
        _manifest(egress=True, domains=["api.stripe.com"]),
    )
    assert any(f.kind == "undeclared_domain" and "evil.click" in f.detail
               for f in report.findings)
    assert report.verdict == Verdict.WARN


def test_canonical_exfil_pattern_blocks():
    """The whole reason this engine exists: a skill that reads a secret env
    var AND makes outbound network calls to an undeclared domain — the
    canonical exfiltration pattern. Under the old heuristic this scored
    ALLOW with risk=3. Under the discrepancy engine it MUST BLOCK."""
    report = compute_discrepancy(
        _caps(
            egress=True,
            domains=["evil.click"],
            env_access=True,
            vars_=["STRIPE_API_KEY"],
        ),
        IMPLICIT_ZERO_TRUST,
    )
    assert report.verdict == Verdict.BLOCK
    kinds = {f.kind for f in report.findings}
    assert "undeclared_egress" in kinds
    assert "undeclared_env_access" in kinds


def test_shell_exec_undeclared_is_critical():
    report = compute_discrepancy(
        _caps(shell_exec=True, commands=["/bin/sh -c 'curl evil'"]),
        _manifest(),
    )
    assert any(f.kind == "undeclared_shell" and f.severity == Severity.CRITICAL
               for f in report.findings)
    assert report.verdict == Verdict.BLOCK


def test_env_access_with_specific_var_in_allowlist_is_clean():
    """Skill declared env_access + STRIPE_API_KEY; skill read only
    STRIPE_API_KEY. Honest declaration — no finding."""
    report = compute_discrepancy(
        _caps(env_access=True, vars_=["STRIPE_API_KEY"]),
        _manifest(env_access=True, vars_=["STRIPE_API_KEY"]),
    )
    assert report.findings == []
    assert report.verdict == Verdict.ALLOW


def test_env_access_with_extra_undeclared_var_warns():
    """Skill declared STRIPE_API_KEY but actually read AWS_SECRET_KEY too."""
    report = compute_discrepancy(
        _caps(env_access=True, vars_=["STRIPE_API_KEY", "AWS_SECRET_KEY"]),
        _manifest(env_access=True, vars_=["STRIPE_API_KEY"]),
    )
    assert any(f.kind == "undeclared_env_var" and "AWS_SECRET_KEY" in f.detail
               for f in report.findings)
    assert report.verdict == Verdict.WARN


def test_over_declared_is_not_a_finding():
    """Manifest promised egress + 3 domains; skill only used 1. The
    discrepancy engine doesn't punish this — over-permissiveness is a
    separate concern surfaced through a different reporting path."""
    report = compute_discrepancy(
        _caps(egress=True, domains=["a.com"]),
        _manifest(egress=True, domains=["a.com", "b.com", "c.com"]),
    )
    assert report.findings == []
    assert report.verdict == Verdict.ALLOW


def test_canary_file_writes_and_reads_are_ignored():
    """The harness writes + reads /evidence/.phylax_canary_<id> as part of
    the proof-of-execution challenge. Those records appear in
    observed.filesystem but are harness-internal and must NOT count as
    discrepancies, otherwise every honest miner gets dinged for harness
    plumbing they didn't write."""
    report = compute_discrepancy(
        _caps(
            reads=["/evidence/.phylax_canary_abc123def"],
            writes=["/evidence/.phylax_canary_abc123def"],
        ),
        IMPLICIT_ZERO_TRUST,
    )
    assert report.findings == []
    assert report.verdict == Verdict.ALLOW


def test_filesystem_write_outside_allowlist_is_high():
    report = compute_discrepancy(
        _caps(writes=["/etc/cron.d/backdoor"]),
        _manifest(read_write=["/tmp/cache"]),
    )
    assert any(f.kind == "undeclared_fs_write" and "/etc/cron.d/backdoor" in f.detail
               for f in report.findings)
    assert report.verdict == Verdict.WARN


def test_filesystem_read_outside_allowlist_is_medium():
    report = compute_discrepancy(
        _caps(reads=["/etc/shadow"]),
        _manifest(),
    )
    finding = next(f for f in report.findings if f.kind == "undeclared_fs_read")
    assert finding.severity == Severity.MEDIUM


def test_discrepancy_score_saturates():
    """Many CRITICAL findings should saturate at 1.0, not exceed it."""
    report = compute_discrepancy(
        _caps(
            egress=True, domains=["a", "b", "c", "d", "e"],
            shell_exec=True, commands=["x", "y", "z"],
            env_access=True, vars_=["A", "B", "C", "D"],
        ),
        IMPLICIT_ZERO_TRUST,
    )
    assert report.discrepancy_score == 1.0


def test_combine_verdict_static_critical_overrides_clean_discrepancy():
    """A clean discrepancy can still be BLOCKed by a CRITICAL static
    finding — e.g. bandit catches a dangerous deserialization sink in a
    code path that wasn't exercised at runtime."""
    discrepancy = compute_discrepancy(_caps(), IMPLICIT_ZERO_TRUST)
    static = [Finding(
        severity=Severity.CRITICAL,
        title="dangerous deserialization sink",
        evidence=FindingEvidence(line_ref="main.py:14"),
    )]
    verdict = combine_verdict(discrepancy, static, known_vulns=[])
    assert verdict.decision == Verdict.BLOCK
    assert verdict.risk_score >= 75


def test_combine_verdict_known_vuln_escalates_to_warn():
    """Skill is contract-honest but ships a known-vulnerable dep."""
    discrepancy = compute_discrepancy(_caps(), IMPLICIT_ZERO_TRUST)
    verdict = combine_verdict(discrepancy, [], known_vulns=["CVE-2024-1234"])
    assert verdict.decision == Verdict.WARN


def test_apply_intel_hits_layers_critical_finding_on_top_of_clean_discrepancy():
    """Skill declared and observed the same domain — manifest-side
    discrepancy is clean (ALLOW). But the server's threat-intel proxy
    flagged the domain as a known C2. Result must escalate to BLOCK
    regardless of what the manifest said."""
    base = compute_discrepancy(
        _caps(egress=True, domains=["api.suspicious.click"]),
        _manifest(egress=True, domains=["api.suspicious.click"]),
    )
    assert base.verdict == Verdict.ALLOW

    intel = {
        "results": [
            {"host": "api.suspicious.click", "ip": None, "hits": [
                {"source": "urlhaus", "threat_type": "c2", "confidence": 1.0}
            ]},
        ],
    }
    escalated = apply_intel_hits(base, intel)
    assert escalated.verdict == Verdict.BLOCK
    assert any(f.kind == "threat_intel_hit" for f in escalated.findings)
    assert escalated.risk_score >= 75


def test_apply_intel_hits_returns_original_when_no_hits():
    base = compute_discrepancy(_caps(), IMPLICIT_ZERO_TRUST)
    intel = {"results": [{"host": "clean.example", "hits": []}]}
    out = apply_intel_hits(base, intel)
    assert out is base  # no new findings → return original instance


def test_apply_intel_hits_returns_original_when_no_results_key():
    """Empty / malformed payload doesn't crash; returns original."""
    base = compute_discrepancy(_caps(), IMPLICIT_ZERO_TRUST)
    assert apply_intel_hits(base, {}) is base


def test_combine_verdict_block_floor_is_discrepancy_when_higher():
    """A CRITICAL discrepancy gives risk >= 75; a single static CRITICAL
    finding alone also gives risk = 80. When both fire the result takes
    the higher of the two, not the sum."""
    discrepancy = compute_discrepancy(
        _caps(egress=True, domains=["a", "b", "c", "d"]),
        IMPLICIT_ZERO_TRUST,
    )
    static = [Finding(severity=Severity.CRITICAL, title="x")]
    verdict = combine_verdict(discrepancy, static, known_vulns=[])
    assert verdict.decision == Verdict.BLOCK
    assert verdict.risk_score <= 100
