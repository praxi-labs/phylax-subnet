from __future__ import annotations

from dataclasses import dataclass

from phylax.analysis import capability, proof, scoring

VERDICTS = ("ALLOW", "WARN", "BLOCK")
_MALICIOUS_LABELS = ("malicious", "known_bad", "block", "unsafe")


@dataclass(frozen=True)
class SkillsEvaluation:
    result: scoring.ScoreResult
    capability_manifest: list[dict]


def _verdict_correctness(verdict: str, label: str | None) -> float:
    if label is None:
        return 0.5
    if label.lower() in _MALICIOUS_LABELS:
        return 1.0 if verdict in ("BLOCK", "WARN") else 0.0
    return 1.0 if verdict == "ALLOW" else 0.0


def _build_manifest(capabilities: list) -> tuple[list[dict], float]:
    manifest: list[dict] = []
    canonical = 0
    for entry in capabilities:
        name = entry if isinstance(entry, str) else str(entry.get("capability", ""))
        perm = capability.lookup(name)
        if perm is None or not capability.is_valid_for("skills", name):
            continue
        canonical += 1
        observation = "" if isinstance(entry, str) else str(entry.get("observation", ""))
        manifest.append(
            {
                "capability": name,
                "group": perm.group.value,
                "protection": perm.protection.value,
                "severity": perm.severity,
                "observation": observation,
            }
        )
    fraction = canonical / len(capabilities) if capabilities else 1.0
    return manifest, fraction


def _solution_quality(manifest: list[dict], context_plane: dict) -> float:
    cap_depth = min(1.0, len(manifest) / 6.0)
    injected = context_plane.get("injected_instructions") or []
    ctx_depth = min(1.0, len(injected) / 3.0)
    return scoring.clip01(0.6 * cap_depth + 0.4 * ctx_depth)


def evaluate(
    evidence: dict | None,
    verdict: str,
    *,
    label: str | None,
    probe: proof.ProbeSpec,
) -> SkillsEvaluation:
    evidence = evidence or {}

    poe = proof.verify_proof_of_execution(probe, evidence, detonation=True)
    if not poe.passed:
        return SkillsEvaluation(scoring.zero(poe.reason), [])

    action_plane = evidence.get("action_plane")
    context_plane = evidence.get("context_plane")
    if not isinstance(action_plane, dict):
        return SkillsEvaluation(scoring.zero("action_plane missing"), [])
    if not isinstance(context_plane, dict):
        return SkillsEvaluation(scoring.zero("context_plane missing"), [])

    capabilities = action_plane.get("capabilities") or []
    manifest, canonical_fraction = _build_manifest(capabilities)

    if capabilities:
        evidence_integrity = scoring.clip01(0.4 + 0.6 * canonical_fraction)
    else:
        evidence_integrity = 0.7

    components = scoring.ScoreComponents(
        verdict_correctness=_verdict_correctness(verdict, label),
        evidence_integrity=evidence_integrity,
        solution_quality=_solution_quality(manifest, context_plane),
        benchmark_agreement=_verdict_correctness(verdict, label),
    )
    return SkillsEvaluation(scoring.combine(components), manifest)
