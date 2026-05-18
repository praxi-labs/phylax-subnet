from __future__ import annotations

from phylax.protocol import (
    CapabilityMap,
    Finding,
    RecommendedPolicy,
    Severity,
)


class PolicyGenerator:
    """Build a RecommendedPolicy from analysis output."""

    # Heuristic defaults
    DEFAULT_MEMORY_MB = 256
    DEFAULT_TIMEOUT_S = 30
    DEEP_MEMORY_MB    = 512
    DEEP_TIMEOUT_S    = 120

    def generate(self,
                 capabilities: CapabilityMap,
                 findings: list[Finding]) -> RecommendedPolicy:
        """
        Construct the policy:
          - egress_allowlist  = observed domains (least-privilege)
          - shell_access      = True only if shell was observed
          - env_allowlist     = observed env vars
          - filesystem read/write = observed paths
          - memory/timeout    = scale with finding severity
        """
        # Allowlist exactly what we saw
        egress_allowlist = sorted(set(capabilities.network.observed_domains))
        egress_denylist  = list(capabilities.network.denylist_suggestion)

        shell_access = capabilities.process.shell_exec
        env_allowlist = sorted(set(capabilities.secrets.observed_vars))

        fs_block = {}
        if capabilities.filesystem.reads:
            fs_block["read_only"] = sorted(set(capabilities.filesystem.reads))
        if capabilities.filesystem.writes:
            fs_block["restricted_write"] = sorted(set(capabilities.filesystem.writes))

        # Memory / timeout: bump up only if no high-severity findings
        has_high = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
        if has_high:
            memory  = self.DEFAULT_MEMORY_MB
            timeout = self.DEFAULT_TIMEOUT_S
        else:
            memory  = self.DEEP_MEMORY_MB
            timeout = self.DEEP_TIMEOUT_S

        return RecommendedPolicy(
            egress_allowlist=egress_allowlist,
            egress_denylist=egress_denylist,
            filesystem=fs_block,
            shell_access=shell_access,
            env_allowlist=env_allowlist,
            max_memory_mb=memory,
            timeout_seconds=timeout,
        )
