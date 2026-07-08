from __future__ import annotations

from dataclasses import dataclass, field

EVIDENCE_GATE = 0.10

W_VERDICT = 0.40
W_SOLUTION = 0.35
W_BENCHMARK = 0.25


def clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


@dataclass(frozen=True)
class ScoreComponents:
    verdict_correctness: float = 0.0
    evidence_integrity: float = 0.0
    solution_quality: float = 0.0
    benchmark_agreement: float = 0.0


@dataclass(frozen=True)
class ScoreResult:
    score: float
    gate_passed: bool
    components: ScoreComponents = field(default_factory=ScoreComponents)
    reason: str = ""


def zero(reason: str, components: ScoreComponents | None = None) -> ScoreResult:
    return ScoreResult(0.0, False, components or ScoreComponents(), reason)


def combine(components: ScoreComponents) -> ScoreResult:
    if components.evidence_integrity < EVIDENCE_GATE:
        return ScoreResult(0.0, False, components, "evidence below gate")
    base = (
        W_VERDICT * components.verdict_correctness
        + W_SOLUTION * components.solution_quality
        + W_BENCHMARK * components.benchmark_agreement
    )
    return ScoreResult(clip01(base * components.evidence_integrity), True, components, "")


TRACK_EMISSION_WEIGHTS: dict[str, float] = {
    "repositories": 0.30,
    "packages": 0.30,
    "mcp_servers": 0.22,
    "skills": 0.18,
}

TOP_K = 3
TOP_K_SPLIT: tuple[float, ...] = (0.60, 0.30, 0.10)

PERFORMANCE_SHARE = 0.95
CONTRIBUTION_SHARE = 0.05


def compute_emission_weights(
    scores_by_track: dict[str, list[tuple[str, float]]],
    contributor_hotkeys: set[str] | None = None,
) -> dict[str, float]:
    weights: dict[str, float] = {}
    active: set[str] = set()
    for track, ranked in scores_by_track.items():
        track_share = TRACK_EMISSION_WEIGHTS.get(track, 0.0)
        if track_share <= 0.0:
            continue
        positive = [(hk, s) for hk, s in sorted(ranked, key=lambda r: r[1], reverse=True) if s > 0.0]
        active.update(hk for hk, _ in positive)
        top = positive[:TOP_K]
        if not top:
            continue
        split = TOP_K_SPLIT[: len(top)]
        denom = sum(split)
        for (hotkey, _score), frac in zip(top, split, strict=True):
            weights[hotkey] = weights.get(hotkey, 0.0) + track_share * (frac / denom)

    perf_total = sum(weights.values())
    if perf_total > 0.0:
        for hotkey in list(weights):
            weights[hotkey] = weights[hotkey] / perf_total * PERFORMANCE_SHARE

    eligible = sorted(active & (contributor_hotkeys or set()))
    if eligible:
        per = CONTRIBUTION_SHARE / len(eligible)
        for hotkey in eligible:
            weights[hotkey] = weights.get(hotkey, 0.0) + per

    total = sum(weights.values())
    if total > 0.0:
        weights = {hk: w / total for hk, w in weights.items()}
    return weights
