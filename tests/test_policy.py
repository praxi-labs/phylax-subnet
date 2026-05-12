"""Tests for the RecommendedPolicy generator."""

from phylax.policy.generator import PolicyGenerator
from phylax.protocol import (
    CapabilityMap, NetworkCapability, ProcessCapability,
    SecretsCapability, FilesystemCapability,
    Finding, Severity,
)


def test_policy_least_privilege():
    """Only observed domains should be in the egress allowlist."""
    caps = CapabilityMap(
        network=NetworkCapability(egress=True, observed_domains=["api.stripe.com"]),
        secrets=SecretsCapability(env_access=True, observed_vars=["STRIPE_API_KEY"]),
    )
    policy = PolicyGenerator().generate(caps, findings=[])

    assert policy.egress_allowlist == ["api.stripe.com"]
    assert policy.env_allowlist == ["STRIPE_API_KEY"]
    assert policy.shell_access is False


def test_policy_high_severity_tightens_limits():
    """A HIGH finding should reduce memory/timeout headroom."""
    caps = CapabilityMap()
    policy = PolicyGenerator().generate(
        caps,
        findings=[Finding(severity=Severity.HIGH, title="t", description="d")],
    )
    assert policy.max_memory_mb == PolicyGenerator.DEFAULT_MEMORY_MB
    assert policy.timeout_seconds == PolicyGenerator.DEFAULT_TIMEOUT_S


def test_policy_clean_run_gets_headroom():
    """No HIGH findings → larger memory/timeout."""
    caps = CapabilityMap()
    policy = PolicyGenerator().generate(caps, findings=[])
    assert policy.max_memory_mb == PolicyGenerator.DEEP_MEMORY_MB
    assert policy.timeout_seconds == PolicyGenerator.DEEP_TIMEOUT_S


def test_policy_shell_observed_enables_shell_access():
    caps = CapabilityMap(
        process=ProcessCapability(spawns=True, shell_exec=True, observed_commands=["bash -c"]),
    )
    policy = PolicyGenerator().generate(caps, findings=[])
    assert policy.shell_access is True
