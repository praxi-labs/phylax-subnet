from __future__ import annotations

import re

from phylax.analysis import common, proof, scoring

_TRACK = "repositories"

_TITLE_OVERLAP_MIN = 0.34
_LINE_WINDOW = 10


def _norm_file(vuln: dict) -> str:
    return str(vuln.get("file", "")).strip().lower()


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", str(text).lower()))


def _title_overlap(a: dict, b: dict) -> float:
    ta = _tokens(a.get("title", "")) | _tokens(a.get("description", ""))
    tb = _tokens(b.get("title", "")) | _tokens(b.get("description", ""))
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _line_ok(a: dict, b: dict) -> bool:
    try:
        la, lb = int(a.get("line")), int(b.get("line"))
    except (TypeError, ValueError):
        return True  # missing line info does not disqualify a match
    return abs(la - lb) <= _LINE_WINDOW


def _matches(expected: dict, reported: dict) -> bool:
    if _norm_file(expected) != _norm_file(reported):
        return False
    cwe_e = str(expected.get("cwe", "")).strip().upper()
    cwe_r = str(reported.get("cwe", "")).strip().upper()
    cwe_match = bool(cwe_e) and cwe_e == cwe_r
    title_match = _title_overlap(expected, reported) >= _TITLE_OVERLAP_MIN
    if not (cwe_match or title_match):
        return False
    return _line_ok(expected, reported)


def _recall(reported: list, expected: list) -> float:
    # Semantic, greedy one-to-one matching: same file, plus CWE or fuzzy
    # title/description overlap, within a line window. Each reported finding can
    # satisfy at most one expected finding.
    exp = [v for v in expected if isinstance(v, dict)]
    rep = [v for v in reported if isinstance(v, dict)]
    if not exp:
        return 0.0
    used: set[int] = set()
    hits = 0
    for e in exp:
        for i, r in enumerate(rep):
            if i in used:
                continue
            if _matches(e, r):
                used.add(i)
                hits += 1
                break
    return hits / len(exp)


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
