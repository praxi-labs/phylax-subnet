from __future__ import annotations

from dataclasses import dataclass

from phylax.analysis import capability, scoring

_MALICIOUS_LABELS = ("malicious", "known_bad", "known-bad", "block", "unsafe", "vulnerable")
_SAFE_LABELS = ("safe", "known_good", "known-good", "allow", "clean")


@dataclass(frozen=True)
class TrackEvaluation:
    result: scoring.ScoreResult
    capability_manifest: list[dict]


def verdict_correctness(verdict: str, label: str | None) -> float:
    if label is None:
        return 0.5
    low = label.lower()
    if low in _MALICIOUS_LABELS:
        return 1.0 if verdict in ("BLOCK", "WARN") else 0.0
    if low in _SAFE_LABELS:
        return 1.0 if verdict == "ALLOW" else 0.0
    return 0.5


def build_manifest(track: str, capabilities: list) -> tuple[list[dict], float]:
    manifest: list[dict] = []
    canonical = 0
    for entry in capabilities:
        name = entry if isinstance(entry, str) else str(entry.get("capability", ""))
        perm = capability.lookup(name)
        if perm is None or not capability.is_valid_for(track, name):
            continue
        canonical += 1
        observation = "" if isinstance(entry, str) else str(entry.get("observation", ""))
        manifest.append(
            {
                "capability": name,
                "group": perm.group.value,
                "protection": perm.protection.value,
                "severity": perm.severity,
                "observation": observation,
            }
        )
    fraction = canonical / len(capabilities) if capabilities else 1.0
    return manifest, fraction


def integrity_from_caps(capabilities: list, canonical_fraction: float) -> float:
    if capabilities:
        return scoring.clip01(0.4 + 0.6 * canonical_fraction)
    return 0.7
