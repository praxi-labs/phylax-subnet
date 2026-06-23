from __future__ import annotations

from phylax.analysis import common, proof, scoring

_TRACK = "packages"


def _lifecycle_depth(lifecycle: dict) -> float:
    depth = 0.0
    for key in ("install_time", "import_time"):
        phase = lifecycle.get(key) or {}
        if isinstance(phase, dict) and (
            phase.get("hook_executed") or phase.get("side_effects") or phase.get("capabilities")
        ):
            depth += 0.5
    return min(1.0, depth)


def _supply_chain_depth(supply_chain: dict) -> float:
    deps = supply_chain.get("dependencies") or []
    cve = sum(len(d.get("cve") or []) for d in deps if isinstance(d, dict))
    typo = 1 if (supply_chain.get("typosquat") or {}).get("suspected") else 0
    confusion = 1 if supply_chain.get("dependency_confusion") else 0
    return min(1.0, (len(deps) + 2 * cve + 2 * typo + 2 * confusion) / 6.0)


def _solution_quality(manifest: list[dict], lifecycle: dict, supply_chain: dict) -> float:
    cap_depth = min(1.0, len(manifest) / 6.0)
    return scoring.clip01(
        0.4 * cap_depth
        + 0.3 * _lifecycle_depth(lifecycle)
        + 0.3 * _supply_chain_depth(supply_chain)
    )


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
    lifecycle = evidence.get("lifecycle")
    supply_chain = evidence.get("supply_chain")
    if not isinstance(action_plane, dict):
        return common.TrackEvaluation(scoring.zero("action_plane missing"), [])
    if not isinstance(lifecycle, dict):
        return common.TrackEvaluation(scoring.zero("lifecycle missing"), [])
    if not isinstance(supply_chain, dict):
        return common.TrackEvaluation(scoring.zero("supply_chain missing"), [])

    capabilities = action_plane.get("capabilities") or []
    manifest, fraction = common.build_manifest(_TRACK, capabilities)

    components = scoring.ScoreComponents(
        verdict_correctness=common.verdict_correctness(verdict, label),
        evidence_integrity=common.integrity_from_caps(capabilities, fraction),
        solution_quality=_solution_quality(manifest, lifecycle, supply_chain),
        benchmark_agreement=common.verdict_correctness(verdict, label),
    )
    return common.TrackEvaluation(scoring.combine(components), manifest)
