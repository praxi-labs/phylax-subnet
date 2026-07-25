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


def _match_counts(reported: list, expected: list, matcher) -> tuple[int, int, int]:
    exp = [v for v in expected if isinstance(v, dict)]
    rep = [v for v in reported if isinstance(v, dict)]
    used: set[int] = set()
    hits = 0
    for e in exp:
        for i, r in enumerate(rep):
            if i in used:
                continue
            if matcher(e, r):
                used.add(i)
                hits += 1
                break
    return hits, len(exp), len(rep)


def _clean_precision(reported: list) -> float:
    return scoring.clip01(1.0 - len(reported) / 5.0)


def _sc_matches(expected: dict, reported: dict) -> bool:
    if str(expected.get("type", "")).strip().lower() != str(reported.get("type", "")).strip().lower():
        return False
    name_e = str(expected.get("name", "")).strip().lower()
    name_r = str(reported.get("name", "")).strip().lower()
    return not name_e or name_e == name_r


def _secret_matches(expected: dict, reported: dict) -> bool:
    if _norm_file(expected) != _norm_file(reported):
        return False
    type_e = str(expected.get("type", "")).strip().lower()
    type_r = str(reported.get("type", "")).strip().lower()
    if type_e and type_r and type_e != type_r:
        return _line_ok(expected, reported)
    return True


def _flatten_supply_chain(sc: dict | None) -> list[dict]:
    # Normalise the agent's supply_chain evidence into typed {type, name} findings
    # so ground truth can be authored as a flat list of the same shape.
    if not isinstance(sc, dict):
        return []
    flat: list[dict] = []
    for t in sc.get("typosquat") or []:
        flat.append({"type": "typosquat", "name": str(t.get("name", "")).lower()})
    for c in sc.get("dependency_confusion") or []:
        flat.append({"type": "dependency_confusion", "name": str(c.get("name", "")).lower()})
    for _ in sc.get("install_scripts") or []:
        flat.append({"type": "install_script", "name": ""})
    for d in sc.get("dependencies") or []:
        if d.get("cve"):
            flat.append({"type": "vulnerable_dependency", "name": str(d.get("name", "")).lower()})
    return flat


def _dim_score(reported: list, expected: list, matcher) -> float:
    hits, n_exp, n_rep = _match_counts(reported, expected, matcher)
    if not n_exp:
        return _clean_precision(reported)
    if not n_rep:
        return 0.0
    return scoring.fbeta(hits / n_rep, hits / n_exp, beta=2.0)


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

    gt = ground_truth if isinstance(ground_truth, dict) else {}
    if any(k in gt for k in ("vulnerabilities", "supply_chain", "secrets")):
        # Blend recall across the labelled dimensions: exploitable code vulns (the
        # Bitsec half) plus supply-chain and leaked-secret findings (the Socket
        # half). A dimension only counts when the corpus labels it, so a
        # vulnerabilities-only ground truth scores exactly as before.
        dims: list[tuple[float, float]] = []
        if "vulnerabilities" in gt:
            dims.append((0.5, _dim_score(vulnerabilities, gt.get("vulnerabilities") or [], _matches)))
        if "supply_chain" in gt:
            reported_sc = _flatten_supply_chain(evidence.get("supply_chain"))
            dims.append((0.3, _dim_score(reported_sc, gt.get("supply_chain") or [], _sc_matches)))
        if "secrets" in gt:
            dims.append((0.2, _dim_score(evidence.get("secrets") or [], gt.get("secrets") or [], _secret_matches)))
        total_w = sum(w for w, _ in dims)
        benchmark = sum(w * s for w, s in dims) / total_w if total_w else 0.0
        components = scoring.ScoreComponents(
            verdict_correctness=common.verdict_correctness(verdict, label),
            evidence_integrity=evidence_integrity,
            solution_quality=benchmark,
            benchmark_agreement=benchmark,
        )
        return common.TrackEvaluation(
            scoring.ScoreResult(scoring.clip01(benchmark), True, components, ""), []
        )

    benchmark = common.verdict_correctness(verdict, label)
    quality = _heuristic_quality(vulnerabilities)
    components = scoring.ScoreComponents(
        verdict_correctness=common.verdict_correctness(verdict, label),
        evidence_integrity=evidence_integrity,
        solution_quality=quality,
        benchmark_agreement=benchmark,
    )
    return common.TrackEvaluation(scoring.combine(components), [])
