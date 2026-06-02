from __future__ import annotations

import random
from dataclasses import dataclass, field

from phylax.protocol import MinerRole, SkillType

PRIMARY_COUNT = 3
AUDITOR_COUNT = 2
AUDITOR_ROTATION_THRESHOLD = 3
MIN_REPUTATION = 0.2


@dataclass
class VerificationGroup:
    skill_type: SkillType
    primaries: list[tuple[str, int]] = field(default_factory=list)
    auditors: list[tuple[str, int]] = field(default_factory=list)
    consensus_enabled: bool = False

    def all_members(self) -> list[tuple[str, int, MinerRole]]:
        out: list[tuple[str, int, MinerRole]] = []
        for hk, uid in self.primaries:
            out.append((hk, uid, MinerRole.PRIMARY))
        for hk, uid in self.auditors:
            out.append((hk, uid, MinerRole.AUDITOR))
        return out


class AuditorRotationTracker:
    def __init__(self, threshold: int = AUDITOR_ROTATION_THRESHOLD) -> None:
        self.threshold = threshold
        self._consecutive: dict[tuple[str, str], int] = {}

    def record(self, hotkey: str, skill_type: SkillType, role: MinerRole) -> None:
        key = (hotkey, skill_type.value)
        if role == MinerRole.AUDITOR:
            self._consecutive[key] = self._consecutive.get(key, 0) + 1
        else:
            self._consecutive[key] = 0

    def needs_promotion(self, hotkey: str, skill_type: SkillType) -> bool:
        return self._consecutive.get((hotkey, skill_type.value), 0) >= self.threshold


def select_verification_group(
    candidates: list[tuple[str, int]],
    *,
    skill_type: SkillType,
    per_type_reputation: dict[str, dict[str, float]],
    rotation: AuditorRotationTracker | None = None,
    rng: random.Random | None = None,
) -> VerificationGroup:
    rng = rng or random.Random()
    rep = per_type_reputation or {}
    eligible: list[tuple[str, int, float]] = []
    for hotkey, uid in candidates:
        score = float(rep.get(hotkey, {}).get(skill_type.value, 0.0))
        if score < MIN_REPUTATION:
            continue
        eligible.append((hotkey, uid, score))
    if not eligible:
        return VerificationGroup(skill_type=skill_type)

    eligible.sort(key=lambda x: (-x[2], x[0]))

    promoted: list[tuple[str, int, float]] = []
    if rotation is not None:
        remaining: list[tuple[str, int, float]] = []
        for hk, uid, score in eligible:
            if rotation.needs_promotion(hk, skill_type):
                promoted.append((hk, uid, score))
            else:
                remaining.append((hk, uid, score))
        promoted.sort(key=lambda x: (-x[2], x[0]))
        eligible = promoted + remaining

    primary_slots = min(PRIMARY_COUNT, len(eligible))
    primaries_raw = eligible[:primary_slots]
    auditor_pool = eligible[primary_slots:]
    auditor_slots = min(AUDITOR_COUNT, len(auditor_pool))
    if auditor_slots > 0:
        sampled = rng.sample(auditor_pool, auditor_slots)
    else:
        sampled = []

    primaries = [(hk, uid) for hk, uid, _ in primaries_raw]
    auditors = [(hk, uid) for hk, uid, _ in sampled]
    total_in_group = len(primaries) + len(auditors)
    consensus_enabled = total_in_group >= 3
    return VerificationGroup(
        skill_type=skill_type,
        primaries=primaries,
        auditors=auditors,
        consensus_enabled=consensus_enabled,
    )
