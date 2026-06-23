from __future__ import annotations

from phylax.analysis import common, proof, scoring

_TRACK = "repositories"


def _solution_quality(vulnerabilities: list) -> float:
    if not vulnerabilities:
        return 0.0
    detailed = sum(
        1
        for v in vulnerabilities
        if isinstance(v, dict) and v.get("remediation") and v.get("cwe")
    )
    depth = min(1.0, len(vulnerabilities) / 5.0)
    detail_ratio = detailed / len(vulnerabilities)
    return scoring.clip01(0.6 * depth + 0.4 * detail_ratio)


def evaluate(
    evidence: dict | None,
    verdict: str,
    *,
    label: str | None,
    probe: proof.ProbeSpec | None = None,
) -> common.TrackEvaluation:
    evidence = evidence or {}

    audit = evidence.get("audit")
    files = int((audit or {}).get("files_analysed", 0) or 0) if isinstance(audit, dict) else 0
    if not isinstance(audit, dict) or files <= 0:
        return common.TrackEvaluation(scoring.zero("audit evidence missing"), [])

    vulnerabilities = evidence.get("vulnerabilities") or []
    evidence_integrity = scoring.clip01(0.5 + 0.5 * min(1.0, files / 5.0))

    components = scoring.ScoreComponents(
        verdict_correctness=common.verdict_correctness(verdict, label),
        evidence_integrity=evidence_integrity,
        solution_quality=_solution_quality(vulnerabilities),
        benchmark_agreement=common.verdict_correctness(verdict, label),
    )
    return common.TrackEvaluation(scoring.combine(components), [])
