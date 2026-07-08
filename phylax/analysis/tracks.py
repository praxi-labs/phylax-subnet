from __future__ import annotations

from phylax.analysis import common, mcp, packages, proof, repositories, scoring, skills

_EVALUATORS = {
    "skills": skills.evaluate,
    "mcp_servers": mcp.evaluate,
    "packages": packages.evaluate,
    "repositories": repositories.evaluate,
}


def evaluate(
    track: str,
    evidence: dict | None,
    verdict: str,
    *,
    label: str | None,
    probe: proof.ProbeSpec,
) -> common.TrackEvaluation:
    fn = _EVALUATORS.get(track)
    if fn is None:
        return common.TrackEvaluation(scoring.zero(f"unknown track '{track}'"), [])
    return fn(evidence, verdict, label=label, probe=probe)
