from __future__ import annotations

import re

from phylax.analysis import scoring

_TOKEN = re.compile(r"[a-z0-9]+")
_TITLE_OVERLAP_MIN = 0.34
_REF_KEYS = ("evidence_ref", "file", "path", "location", "ref", "source")
_CATEGORY_KEYS = ("category", "type", "class", "kind")
_TITLE_KEYS = ("title", "summary", "description", "detail", "message")


def _first(entry: dict, keys) -> str:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text.lower()))


def _norm_ref(value: str) -> str:
    return value.replace("\\", "/").strip().lower().lstrip("./")


def _same_category(expected: str, reported: str) -> bool:
    exp, rep = expected.lower().strip(), reported.lower().strip()
    if not exp or not rep:
        return False
    if exp == rep:
        return True
    return bool(_tokens(exp) & _tokens(rep))


def _matches(expected: dict, reported: dict) -> bool:
    if not _same_category(
        _first(expected, _CATEGORY_KEYS), _first(reported, _CATEGORY_KEYS)
    ):
        return False
    exp_ref = _norm_ref(_first(expected, _REF_KEYS))
    rep_ref = _norm_ref(_first(reported, _REF_KEYS))
    if exp_ref and rep_ref:
        if exp_ref == rep_ref or exp_ref.endswith(rep_ref) or rep_ref.endswith(exp_ref):
            return True
        return False
    exp_title = _tokens(_first(expected, _TITLE_KEYS))
    rep_title = _tokens(_first(reported, _TITLE_KEYS))
    if not exp_title or not rep_title:
        return True
    union = exp_title | rep_title
    return bool(union) and len(exp_title & rep_title) / len(union) >= _TITLE_OVERLAP_MIN


def delta_findings(expected: list, observed_capabilities) -> list[dict]:
    observed = set(observed_capabilities or [])
    out: list[dict] = []
    for entry in expected or []:
        if not isinstance(entry, dict):
            continue
        plane = str(entry.get("plane", "")).strip().lower()
        if plane == "context" or not observed:
            out.append(entry)
    return out


def finding_quality(
    expected: list, reported: list, observed_capabilities=None
) -> float:
    wanted = delta_findings(expected, observed_capabilities)
    if not wanted:
        return 0.0
    found = [r for r in (reported or []) if isinstance(r, dict)]
    if not found:
        return 0.0
    used: set[int] = set()
    hits = 0
    for target in wanted:
        for index, candidate in enumerate(found):
            if index in used:
                continue
            if _matches(target, candidate):
                used.add(index)
                hits += 1
                break
    if not hits:
        return 0.0
    recall = hits / len(wanted)
    precision = hits / len(found)
    return scoring.clip01(scoring.fbeta(precision, recall, beta=1.0))
