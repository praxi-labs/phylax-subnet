from __future__ import annotations

from phylax.analysis import common, proof, scoring

_TRACK = "mcp_servers"


def _solution_quality(manifest: list[dict], context_plane: dict, mcp_surface: dict) -> float:
    cap_depth = min(1.0, len(manifest) / 6.0)
    injected = context_plane.get("injected_instructions") or []
    ctx_depth = min(1.0, len(injected) / 3.0)
    tools = mcp_surface.get("exposed_tools") or []
    poison = mcp_surface.get("tool_poisoning") or []
    mismatches = sum(1 for t in tools if isinstance(t, dict) and t.get("schema_mismatch"))
    surface_depth = min(1.0, (len(tools) + 2 * len(poison) + mismatches) / 6.0)
    return scoring.clip01(0.45 * cap_depth + 0.25 * ctx_depth + 0.30 * surface_depth)


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
    mcp_surface = evidence.get("mcp_surface")
    if not isinstance(action_plane, dict):
        return common.TrackEvaluation(scoring.zero("action_plane missing"), [])
    if not isinstance(context_plane, dict):
        return common.TrackEvaluation(scoring.zero("context_plane missing"), [])
    if not isinstance(mcp_surface, dict):
        return common.TrackEvaluation(scoring.zero("mcp_surface missing"), [])

    capabilities = action_plane.get("capabilities") or []
    manifest, fraction = common.build_manifest(_TRACK, capabilities)

    components = scoring.ScoreComponents(
        verdict_correctness=common.verdict_correctness(verdict, label),
        evidence_integrity=common.integrity_from_caps(capabilities, fraction),
        solution_quality=_solution_quality(manifest, context_plane, mcp_surface),
        benchmark_agreement=common.verdict_correctness(verdict, label),
    )
    return common.TrackEvaluation(scoring.combine(components), manifest)
