# Runtime Integration Guide

How to consume Signed Skill Safety Attestations (SSSAs) from your agent
runtime, marketplace, or CI pipeline.

## Why integrate

An SSSA gives you, for any skill bundle:

1. A pass/warn/block verdict
2. A risk score 0–100
3. A capability map (what the skill *actually* accesses)
4. A machine-readable policy you can enforce
5. Cryptographic proof of who produced the attestation

Use it as a precondition to skill execution. Treat unsigned or expired
SSSAs as untrusted.

## Quickstart — Python

```python
import hashlib
import requests

PHYLAX_API = "https://api.phylax.network/v1"

def fetch_sssa(bundle_path: str) -> dict:
    with open(bundle_path, "rb") as f:
        bundle_hash = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    r = requests.get(f"{PHYLAX_API}/attestation/{bundle_hash}", timeout=10)
    r.raise_for_status()
    return r.json()

def enforce(sssa: dict, sandbox):
    if sssa["verdict"]["decision"] == "BLOCK":
        raise RuntimeError(f"Phylax BLOCKED: {sssa['verdict']['summary']}")

    policy = sssa["recommended_policy"]
    sandbox.configure(
        egress_allowlist = policy["egress_allowlist"],
        shell_access     = policy["shell_access"],
        env_allowlist    = policy["env_allowlist"],
        max_memory_mb    = policy["max_memory_mb"],
        timeout_seconds  = policy["timeout_seconds"],
    )
```

## Verifying the signature

Never trust an SSSA solely on appearance — verify the signature against
the on-chain miner hotkey before enforcing.

```python
from phylax.attestation.signer import verify_attestation
from phylax.protocol import SSSA

sssa = SSSA(**fetched_dict)
assert verify_attestation(sssa), "SSSA signature invalid"
```

## Verdict semantics

| Verdict | Meaning | Typical runtime action |
|---|---|---|
| `ALLOW` | Safe to run with recommended_policy | Apply policy, execute |
| `WARN` | Risky but not malicious | Apply policy + log + alert |
| `BLOCK` | Malicious or dangerous | Refuse to execute |

A `WARN` is a deliberate middle ground — many legitimate skills need shell
access or broad network reach. The recommended_policy will still constrain
those capabilities to what was observed.

## Cache + staleness

- SSSAs are content-addressed by `bundle_hash`. Cache them indefinitely.
- A new SSSA is needed when the bundle changes (hash changes) or when the
  miner's analysis tooling has been upgraded (signaled by `schema_version`
  or `run_metadata.tools` versions).

## Marketplace integration

Marketplaces should:

1. Require every uploaded skill to have a non-expired SSSA from a
   high-stake Phylax miner.
2. Display the SSSA verdict + summary next to the listing.
3. Hide skills with `BLOCK` verdicts from search results.
4. Refuse to publish skills whose declared capabilities exceed those
   observed in the SSSA.

## CI pipeline integration

Add a gate to your build that fetches the SSSA for any included skill:

```yaml
- name: Phylax safety gate
  run: |
    python -m phylax.cli check ./dist/skill.zip \
        --max-risk 30 \
        --require ALLOW
```

The gate fails the build if any included skill is `BLOCK`, or exceeds
the configured max risk score.

## Reporting issues

If you find an SSSA that's clearly wrong (false positive or false
negative), open an issue tagged `triage/sssa` with the bundle hash and
the miner hotkey. The validator corpora is the source of truth for
ground-truth verdicts.
