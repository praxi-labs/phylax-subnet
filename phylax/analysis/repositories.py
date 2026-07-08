from __future__ import annotations

from phylax.analysis import common, proof, scoring

_TRACK = "repositories"


def _vuln_key(vuln: dict) -> tuple[str, str]:
    return (
        str(vuln.get("file", "")).strip().lower(),
        str(vuln.get("cwe", "")).strip().upper(),
    )


def _recall(reported: list, expected: list) -> float:
    expected_keys = {_vuln_key(v) for v in expected if isinstance(v, dict)}
    if not expected_keys:
        return 0.0
    reported_keys = {_vuln_key(v) for v in reported if isinstance(v, dict)}
    return len(expected_keys & reported_keys) / len(expected_keys)


def _clean_precision(reported: list) -> float:
    return scoring.clip01(1.0 - len(reported) / 5.0)


def _heuristic_quality(vulnerabilities: list) -> float:
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
    ground_truth: dict | None = None,
) -> common.TrackEvaluation:
    evidence = evidence or {}

    audit = evidence.get("audit")
    files = int((audit or {}).get("files_analysed", 0) or 0) if isinstance(audit, dict) else 0
    if not isinstance(audit, dict) or files <= 0:
        return common.TrackEvaluation(scoring.zero("audit evidence missing"), [])

    vulnerabilities = evidence.get("vulnerabilities") or []
    evidence_integrity = scoring.clip01(0.5 + 0.5 * min(1.0, files / 5.0))

    if isinstance(ground_truth, dict) and "vulnerabilities" in ground_truth:
        expected = ground_truth.get("vulnerabilities") or []
        if expected:
            benchmark = _recall(vulnerabilities, expected)
        else:
            benchmark = _clean_precision(vulnerabilities)
        quality = benchmark
    else:
        benchmark = common.verdict_correctness(verdict, label)
        quality = _heuristic_quality(vulnerabilities)

    components = scoring.ScoreComponents(
        verdict_correctness=common.verdict_correctness(verdict, label),
        evidence_integrity=evidence_integrity,
        solution_quality=quality,
        benchmark_agreement=benchmark,
    )
    return common.TrackEvaluation(scoring.combine(components), [])
