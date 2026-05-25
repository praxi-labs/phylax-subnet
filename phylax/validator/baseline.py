from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

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
    ):
        self.static_analyzer = StaticAnalyzer(run_bandit=run_bandit, run_semgrep=run_semgrep)
        self.sbom_analyzer = SBOMAnalyzer()
        self.sandbox = SandboxDetonator(
            image=sandbox_image,
            timeout_seconds=int(os.getenv("SANDBOX_TIMEOUT", str(sandbox_timeout_seconds))),
        )
        self.policy_generator = PolicyGenerator()

    # ------------------------------------------------------------------

    def run(
        self,
        bundle_path: str,
        nonce: int,
        *,
        deep: bool = False,
        canary_id: str = "",
        canary_val: str = "",
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
        verdict = _compute_verdict(findings, capabilities, sbom_result)
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

    # ------------------------------------------------------------------

    def run_from_bytes(
        self,
        bundle_bytes: bytes,
        nonce: int,
        *,
        deep: bool = False,
        canary_id: str = "",
        canary_val: str = "",
    ) -> GroundTruth:
        """Convenience: writes bytes to a temp dir, unpacks if a zip, then runs.

        The staging directory MUST live under PHYLAX_EVIDENCE_DIR (which is
        bind-mounted from the host) so the sandbox container — launched via
        the host docker socket — can actually see the bundle. A path under
        /tmp would only exist inside the validator container; the host
        dockerd would silently create an empty dir there and mount it into
        /skill, producing the same "no_entry" baseline for every task and
        pinning evidence_score to 0 regardless of what miners submit.
        """
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
            # Not a zip — treat as a single-file bundle.
            (extract_dir / "main.py").write_bytes(bundle_bytes)
        return self.run(
            str(extract_dir),
            nonce=nonce,
            deep=deep,
            canary_id=canary_id,
            canary_val=canary_val,
        )


# ---------------------------------------------------------------------------
# Helpers shared with the miner verdict logic
# ---------------------------------------------------------------------------


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
