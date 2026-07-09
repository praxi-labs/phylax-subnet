from __future__ import annotations

import difflib

SIMILARITY_THRESHOLD = 0.92


def normalise_code(code: str) -> str:
    lines = []
    for raw in code.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def duplicate_hotkeys(submissions: dict[str, tuple[str, int]]) -> set[str]:
    entries = [
        (uid, hotkey, normalise_code(code))
        for hotkey, (code, uid) in submissions.items()
    ]
    entries.sort()
    excluded: set[str] = set()
    for i, (_, hotkey_a, code_a) in enumerate(entries):
        if hotkey_a in excluded:
            continue
        for _, hotkey_b, code_b in entries[i + 1:]:
            if hotkey_b in excluded:
                continue
            if code_a == code_b:
                excluded.add(hotkey_b)
                continue
            ratio = difflib.SequenceMatcher(None, code_a, code_b).quick_ratio()
            if ratio >= SIMILARITY_THRESHOLD:
                ratio = difflib.SequenceMatcher(None, code_a, code_b).ratio()
                if ratio >= SIMILARITY_THRESHOLD:
                    excluded.add(hotkey_b)
    return excluded
