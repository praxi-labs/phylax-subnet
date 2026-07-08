from __future__ import annotations

from phylax.analysis import common, proof, scoring

_TRACK = "skills"


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
) -> common.TrackEvaluation:
    evidence = evidence or {}

    poe = proof.verify_proof_of_execution(probe, evidence, detonation=True)
    if not poe.passed:
        return common.TrackEvaluation(scoring.zero(poe.reason), [])

    action_plane = evidence.get("action_plane")
    context_plane = evidence.get("context_plane")
    if not isinstance(action_plane, dict):
        return common.TrackEvaluation(scoring.zero("action_plane missing"), [])
    if not isinstance(context_plane, dict):
        return common.TrackEvaluation(scoring.zero("context_plane missing"), [])

    capabilities = action_plane.get("capabilities") or []
    manifest, canonical_fraction = common.build_manifest(_TRACK, capabilities)

    components = scoring.ScoreComponents(
        verdict_correctness=common.verdict_correctness(verdict, label),
        evidence_integrity=common.integrity_from_caps(capabilities, canonical_fraction),
        solution_quality=_solution_quality(manifest, context_plane),
        benchmark_agreement=common.verdict_correctness(verdict, label),
    )
    return common.TrackEvaluation(scoring.combine(components), manifest)
