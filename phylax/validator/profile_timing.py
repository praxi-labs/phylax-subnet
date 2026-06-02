from __future__ import annotations

from phylax.protocol import MinerRole, SkillType, TestProfile

PROFILE_TIMING: dict[SkillType, dict[TestProfile, tuple[int, int]]] = {
    SkillType.RAG_KNOWLEDGE: {
        TestProfile.FAST: (2, 20),
        TestProfile.STANDARD: (5, 45),
        TestProfile.DEEP: (10, 90),
    },
    SkillType.DECLARATIVE: {
        TestProfile.FAST: (5, 45),
        TestProfile.STANDARD: (10, 90),
        TestProfile.DEEP: (20, 180),
    },
    SkillType.EXECUTABLE_PYTHON: {
        TestProfile.FAST: (15, 150),
        TestProfile.STANDARD: (30, 300),
        TestProfile.DEEP: (60, 600),
    },
    SkillType.EXECUTABLE_SCRIPT: {
        TestProfile.FAST: (15, 150),
        TestProfile.STANDARD: (30, 300),
        TestProfile.DEEP: (60, 600),
    },
    SkillType.MCP_SERVER: {
        TestProfile.FAST: (30, 300),
        TestProfile.STANDARD: (60, 600),
        TestProfile.DEEP: (120, 900),
    },
    SkillType.AGENT_COMPOSITION: {
        TestProfile.FAST: (60, 600),
        TestProfile.STANDARD: (120, 900),
        TestProfile.DEEP: (240, 1800),
    },
}


AUDITOR_TIMING: dict[SkillType, tuple[int, int]] = {
    SkillType.RAG_KNOWLEDGE: (2, 15),
    SkillType.DECLARATIVE: (3, 30),
    SkillType.EXECUTABLE_PYTHON: (10, 90),
    SkillType.EXECUTABLE_SCRIPT: (10, 90),
    SkillType.MCP_SERVER: (20, 150),
    SkillType.AGENT_COMPOSITION: (30, 240),
}


def resolve_timing(
    skill_type: SkillType, profile: TestProfile, role: MinerRole = MinerRole.PRIMARY,
) -> tuple[int, int]:
    if role == MinerRole.AUDITOR:
        timing = AUDITOR_TIMING.get(skill_type)
        if timing:
            return timing
    by_profile = PROFILE_TIMING.get(skill_type)
    if not by_profile:
        return 15, 150
    return by_profile.get(profile, (15, 150))
