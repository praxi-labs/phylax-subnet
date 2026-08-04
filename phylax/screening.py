from __future__ import annotations

import ast
import difflib
import re

SIMILARITY_THRESHOLD = 0.92
STRUCTURE_THRESHOLD = 0.95
_STRUCTURE_SIZE_GUARD = 0.75

_STRING_LITERAL = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'')


def _strip_literals(code: str) -> str:
    return _STRING_LITERAL.sub('""', code)


_ABUSE_RULES: tuple[tuple[str, re.Pattern[str], bool], ...] = (
    (
        "reads operator secrets",
        re.compile(
            r"(?:open|read_text|read_bytes|readlines|expanduser|Path|load|"
            r"readFileSync|cat)\s*\([^)\n]{0,160}"
            r"(?:\.ssh/id_|id_rsa|id_ed25519|\.aws/credentials|\.netrc|"
            r"\.git-credentials|\.password-store|/etc/shadow|"
            r"\.docker/config|\.kube/config|wallet\.dat|coldkey|\.bittensor)"
        ),
        False,
    ),
    (
        "executes unauthorised system commands",
        re.compile(
            r"os\.system\s*\(|subprocess\.(?:Popen|run|call|check_output)\s*\(\s*"
            r"[\"'](?:/bin/|/usr/bin/|sh\b|bash\b|curl\b|wget\b|nc\b)|"
            r"pty\.spawn|/dev/tcp/"
        ),
        True,
    ),
    (
        "obfuscates its behaviour",
        re.compile(
            r"eval\s*\(\s*(?:base64|bytes\.fromhex|codecs\.decode|__import__)|"
            r"exec\s*\(\s*(?:base64|bytes\.fromhex|codecs\.decode|__import__)|"
            r"marshal\.loads|pickle\.loads\s*\(\s*base64|"
            r"getattr\s*\(\s*__import__\s*\("
        ),
        True,
    ),
    (
        "exhausts resources",
        re.compile(
            r"while\s+True\s*:\s*(?:\n\s+pass|\s*pass\b)|"
            r"fork\s*\(\s*\)\s*(?:while|for)|os\.fork\s*\(\s*\)\s*\n\s*while|"
            r"\[\s*0\s*\]\s*\*\s*\d{9,}|range\s*\(\s*\d{10,}\s*\)"
        ),
        True,
    ),
    (
        "abuses the inference channel",
        re.compile(
            r"for\s+\w+\s+in\s+range\s*\(\s*\d{4,}\s*\)\s*:[^\n]{0,200}\n[^\n]{0,200}"
            r"(?:chat/completions|inference|\.complete\s*\(|openai|anthropic)"
        ),
        True,
    ),
)


def abuse_reason(code: str) -> str:
    base = normalise_code(code)
    without_literals = _strip_literals(base)
    for reason, pattern, strip in _ABUSE_RULES:
        if pattern.search(without_literals if strip else base):
            return reason
    return ""


def _docstring_lines(code: str) -> set[int]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    holders = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, holders):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr):
            continue
        value = first.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            lines.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    return lines


def normalise_code(code: str) -> str:
    skip = _docstring_lines(code)
    lines = []
    for number, raw in enumerate(code.splitlines(), start=1):
        if number in skip:
            continue
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def structural_shape(code: str) -> tuple[str, ...]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ()
    shape: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            shape.append(f"Const:{type(node.value).__name__}")
        else:
            shape.append(type(node).__name__)
    return tuple(sorted(shape))


def _similar(code_a: str, code_b: str) -> bool:
    if difflib.SequenceMatcher(None, code_a, code_b).quick_ratio() < SIMILARITY_THRESHOLD:
        return False
    return difflib.SequenceMatcher(None, code_a, code_b).ratio() >= SIMILARITY_THRESHOLD


def _same_structure(shape_a: tuple[str, ...], shape_b: tuple[str, ...]) -> bool:
    if not shape_a or not shape_b:
        return False
    if shape_a == shape_b:
        return True
    shorter, longer = sorted((len(shape_a), len(shape_b)))
    if longer and shorter / longer < _STRUCTURE_SIZE_GUARD:
        return False
    ratio = difflib.SequenceMatcher(None, shape_a, shape_b).ratio()
    return ratio >= STRUCTURE_THRESHOLD


def duplicate_hotkeys(submissions: dict[str, tuple[str, int]]) -> set[str]:
    entries = [
        (uid, hotkey, normalise_code(code), structural_shape(code))
        for hotkey, (code, uid) in submissions.items()
    ]
    entries.sort()
    excluded: set[str] = set()
    for i, (_, hotkey_a, code_a, shape_a) in enumerate(entries):
        if hotkey_a in excluded:
            continue
        for _, hotkey_b, code_b, shape_b in entries[i + 1:]:
            if hotkey_b in excluded:
                continue
            if code_a == code_b:
                excluded.add(hotkey_b)
                continue
            if _same_structure(shape_a, shape_b) or _similar(code_a, code_b):
                excluded.add(hotkey_b)
    return excluded
