from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from phylax.manifest import load_manifest
from phylax.pipeline.sandbox import SandboxDetonator, SandboxResult
from phylax.pipeline.sbom import SBOMAnalyzer, SBOMResult
from phylax.pipeline.static import StaticAnalysisResult, StaticAnalyzer
from phylax.policy.generator import PolicyGenerator
from phylax.protocol import (
    CapabilityMap,
    FilesystemCapability,
    Finding,
    NetworkCapability,
    ProcessCapability,
    RecommendedPolicy,
    SecretsCapability,
    Severity,
    Verdict,
    VerdictBlock,
)
from phylax.scoring.discrepancy import apply_intel_hits, combine_verdict, compute_discrepancy


@dataclass
class GroundTruth:
    """The validator's independent baseline output for a single (S, η) pair."""

    verdict: VerdictBlock
    capabilities: CapabilityMap
    policy: RecommendedPolicy
    findings: list[Finding]
    evidence_hashes: dict[str, str | None] = field(default_factory=dict)
    sbom_hash: str | None = None
    duration_ms: int = 0

    def as_task_dict(self) -> dict:
        """Render into a dict the scoring functions can consume."""
        return {
            "expected_verdict": self.verdict.decision.value,
            "expected_risk_score": self.verdict.risk_score,
            "expected_capabilities": self.capabilities.model_dump(mode="json"),
            "expected_policy": self.policy.model_dump(mode="json"),
            "ground_truth_evidence": self.evidence_hashes,
        }


class BaselineRunner:
    """
    Runs the three-layer Phylax pipeline under pinned tooling.

    The validator owns one instance per process. The sandbox component
    requires Docker on the validator host (see docs/validator_setup.md).
    """

    def __init__(
        self,
        *,
        sandbox_image: str = "phylax-sandbox:latest",
        sandbox_timeout_seconds: int = 120,
        run_bandit: bool = True,
        run_semgrep: bool = False,
        intel_client=None,
    ):
        self.static_analyzer = StaticAnalyzer(run_bandit=run_bandit, run_semgrep=run_semgrep)
        self.sbom_analyzer = SBOMAnalyzer()
        self.sandbox = SandboxDetonator(
            image=sandbox_image,
            timeout_seconds=int(os.getenv("SANDBOX_TIMEOUT", str(sandbox_timeout_seconds))),
        )
        self.policy_generator = PolicyGenerator()
        # Optional phylax-server client; when present, every observed
        # domain/IP gets a threat-intel lookup via /v1/intel/lookup.
        # Hits become CRITICAL discrepancy findings regardless of the
        # skill's manifest declaration. Miners can't reach this endpoint
        # so they have to integrate their own threat-intel pipeline to
        # match the validator's coverage — that's the moat.
        self.intel_client = intel_client


    def run(
        self,
        bundle_path: str,
        nonce: int,
        *,
        deep: bool = False,
        canary_id: str = "",
        canary_val: str = "",
        pre_baked_intel_findings: list[dict] | None = None,
        pre_baked_cve_findings: list[dict] | None = None,
    ) -> GroundTruth:
        start = time.time()

        static_result = self.static_analyzer.analyze(bundle_path)
        sbom_result = self.sbom_analyzer.analyze(bundle_path)
        sandbox_result: SandboxResult | None = None
        try:
            sandbox_result = self.sandbox.detonate(
                bundle_path,
                seed=nonce,
                extended=deep,
                canary_id=canary_id,
                canary_val=canary_val,
            )
        except ValueError:
            sandbox_result = None
        except Exception:  # noqa: BLE001
            sandbox_result = None

        capabilities = _merge_capabilities(static_result, sandbox_result)
        findings = list(static_result.findings) + list(sbom_result.findings)
        manifest = load_manifest(bundle_path)
        discrepancy = compute_discrepancy(capabilities, manifest)
        if pre_baked_intel_findings is not None:
            discrepancy = self._apply_prebaked_intel(
                discrepancy, pre_baked_intel_findings,
            )
        else:
            discrepancy = self._apply_threat_intel(discrepancy, capabilities)
        if pre_baked_cve_findings is not None:
            cve_vulns = [
                f.get("cve_id") for f in pre_baked_cve_findings
                if isinstance(f, dict) and f.get("cve_id")
            ]
        else:
            cve_vulns = self._lookup_cves(sbom_result)
        known_vulns = list(sbom_result.known_vulns) + cve_vulns
        verdict = combine_verdict(discrepancy, findings, known_vulns)
        policy = self.policy_generator.generate(capabilities, findings)

        evidence = {
            "N": sandbox_result.network_trace_hash if sandbox_result else None,
            "F": sandbox_result.fs_trace_hash if sandbox_result else None,
            "P": sandbox_result.process_trace_hash if sandbox_result else None,
            "K": sandbox_result.secrets_trace_hash if sandbox_result else None,
        }
        duration_ms = int((time.time() - start) * 1000)

        return GroundTruth(
            verdict=verdict,
            capabilities=capabilities,
            policy=policy,
            findings=findings,
            evidence_hashes=evidence,
            sbom_hash=sbom_result.sbom_hash,
            duration_ms=duration_ms,
        )


    def _apply_prebaked_intel(self, discrepancy, prebaked: list[dict]):
        if not prebaked:
            return discrepancy
        by_indicator: dict[str, list[dict]] = {}
        for entry in prebaked:
            if not isinstance(entry, dict):
                continue
            indicator = entry.get("indicator")
            if not indicator:
                continue
            hit = {k: v for k, v in entry.items() if k != "indicator"}
            by_indicator.setdefault(indicator, []).append(hit)
        intel_results = {
            "results": [
                {"host": indicator, "hits": hits}
                for indicator, hits in by_indicator.items()
            ],
        }
        return apply_intel_hits(discrepancy, intel_results)

    def _apply_threat_intel(self, discrepancy, capabilities):
        """If an intel_client is wired in, look up every observed
        domain/IP and fold the hits into the discrepancy report. Failure
        of the intel call is non-fatal — we log it and proceed with the
        manifest-only discrepancy rather than crater the whole round."""
        if self.intel_client is None:
            return discrepancy
        hosts = list(set(capabilities.network.observed_domains))
        ips = list(set(capabilities.network.observed_ips))
        if not hosts and not ips:
            return discrepancy
        try:
            intel_results = self.intel_client.intel_lookup(hosts=hosts, ips=ips)
        except Exception:  # noqa: BLE001
            return discrepancy
        return apply_intel_hits(discrepancy, intel_results)

    def _lookup_cves(self, sbom_result) -> list[str]:
        """Query the server's CVE proxy for every package in the SBOM.
        Returns a list of "CVE-xxxx-yyyy" identifiers that feed into
        combine_verdict's ``known_vulns`` parameter.

        When intel_client is None (no server / offline mode), this is a
        no-op. Server failures are non-fatal — log and return [] so the
        round proceeds with whatever local SBOM analysis already found.
        """
        if self.intel_client is None or not hasattr(self.intel_client, "cve_lookup"):
            return []
        packages = list(getattr(sbom_result, "packages", []) or [])
        if not packages:
            return []
        cve_payload = []
        for p in packages:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            version = p.get("version")
            if not name or not version:
                continue
            cve_payload.append({
                "name": name,
                "version": str(version),
                "ecosystem": p.get("ecosystem", "PyPI"),
            })
        if not cve_payload:
            return []
        try:
            resp = self.intel_client.cve_lookup(packages=cve_payload)
        except Exception:  # noqa: BLE001
            return []
        cves: list[str] = []
        for result in resp.get("results", []):
            for record in result.get("records", []) or []:
                cid = record.get("cve_id")
                if cid:
                    cves.append(cid)
        return cves


    def run_from_bytes(
        self,
        bundle_bytes: bytes,
        nonce: int,
        *,
        deep: bool = False,
        canary_id: str = "",
        canary_val: str = "",
        pre_baked_intel_findings: list[dict] | None = None,
        pre_baked_cve_findings: list[dict] | None = None,
    ) -> GroundTruth:
        import zipfile

        staging_root = os.path.expanduser(
            os.getenv("PHYLAX_EVIDENCE_DIR", tempfile.gettempdir())
        )
        os.makedirs(staging_root, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="phylax_gt_", dir=staging_root))
        bundle_zip = tmp / "bundle.zip"
        bundle_zip.write_bytes(bundle_bytes)
        extract_dir = tmp / "extracted"
        extract_dir.mkdir()
        try:
            with zipfile.ZipFile(bundle_zip) as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            (extract_dir / "main.py").write_bytes(bundle_bytes)
        return self.run(
            str(extract_dir),
            nonce=nonce,
            deep=deep,
            canary_id=canary_id,
            canary_val=canary_val,
            pre_baked_intel_findings=pre_baked_intel_findings,
            pre_baked_cve_findings=pre_baked_cve_findings,
        )




def _merge_capabilities(
    static_result: StaticAnalysisResult, sandbox_result: SandboxResult | None
) -> CapabilityMap:
    fs_reads = list(set(static_result.fs_reads + (sandbox_result.fs_reads if sandbox_result else [])))
    fs_writes = list(set(static_result.fs_writes + (sandbox_result.fs_writes if sandbox_result else [])))
    domains = list(
        set(static_result.network_domains + (sandbox_result.network_domains if sandbox_result else []))
    )
    commands = list(set(static_result.shell_commands + (sandbox_result.shell_commands if sandbox_result else [])))
    env_vars = list(set(static_result.env_vars + (sandbox_result.env_vars if sandbox_result else [])))

    return CapabilityMap(
        filesystem=FilesystemCapability(reads=sorted(fs_reads), writes=sorted(fs_writes)),
        network=NetworkCapability(
            egress=bool(domains),
            observed_domains=sorted(domains),
        ),
        process=ProcessCapability(
            spawns=bool(commands),
            shell_exec=any("sh" in c or "bash" in c for c in commands),
            observed_commands=sorted(commands),
        ),
        secrets=SecretsCapability(env_access=bool(env_vars), observed_vars=sorted(env_vars)),
    )


def _compute_verdict(
    findings: list[Finding],
    capabilities: CapabilityMap,
    sbom_result: SBOMResult,
) -> VerdictBlock:
    """Reference verdict logic; shared between miner default and validator GT."""
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    high = [f for f in findings if f.severity == Severity.HIGH]

    exfil_pattern = (
        capabilities.network.egress
        and capabilities.secrets.env_access
        and capabilities.process.shell_exec
    )
    if critical or exfil_pattern:
        decision = Verdict.BLOCK
        risk = min(100, 75 + len(critical) * 5)
    elif high or sbom_result.known_vulns or capabilities.process.shell_exec:
        decision = Verdict.WARN
        risk = min(74, 40 + len(high) * 8)
    else:
        decision = Verdict.ALLOW
        risk = max(0, len(findings) * 3)

    severity_names = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
    }
    top_reasons = [f"[{severity_names[f.severity]}] {f.title}" for f in (critical + high)[:3]]

    confidence = 0.95 if (capabilities.network.observed_domains or capabilities.process.shell_exec) else 0.9
    summary = (
        f"Verdict {decision.value}: risk={risk}. "
        f"{len(findings)} finding(s); domains={capabilities.network.observed_domains or 'none'}."
    )
    return VerdictBlock(
        decision=decision,
        risk_score=risk,
        confidence=confidence,
        summary=summary,
        top_reasons=top_reasons,
    )

