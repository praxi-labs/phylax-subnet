from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from phylax.protocol import SSSA, Verdict


@dataclass
class MinerSubmission:
    uid: int
    hotkey: str
    sssa: SSSA
    quality_score: float
    submission_latency_ms: int


@dataclass
class ConsensusResult:
    verdict: Verdict
    quality_score: float
    winning_submission: Optional[MinerSubmission]
    verdict_weights: dict[Verdict, float] = field(default_factory=dict)
    participating_miners: int = 0

    def is_ALLOW(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def is_BLOCK(self) -> bool:
        return self.verdict == Verdict.BLOCK


class ConsensusAggregator:
    """Compute the quality-weighted consensus over a set of miner submissions."""

    def aggregate(self, submissions: list[MinerSubmission]) -> Optional[ConsensusResult]:
        if not submissions:
            return None

        weights: dict[Verdict, float] = {Verdict.ALLOW: 0.0, Verdict.WARN: 0.0, Verdict.BLOCK: 0.0}
        per_verdict_top: dict[Verdict, MinerSubmission] = {}

        for sub in submissions:
            try:
                v = sub.sssa.verdict.decision
            except AttributeError:
                continue
            weights[v] += max(0.0, sub.quality_score)
            top = per_verdict_top.get(v)
            if top is None or sub.quality_score > top.quality_score:
                per_verdict_top[v] = sub

        winning_verdict = max(weights, key=lambda v: weights[v])
        winning_sub = per_verdict_top.get(winning_verdict)

        if winning_sub is None or weights[winning_verdict] <= 0.0:
            return ConsensusResult(
                verdict=Verdict.WARN,
                quality_score=0.0,
                winning_submission=None,
                verdict_weights=weights,
                participating_miners=len(submissions),
            )

        return ConsensusResult(
            verdict=winning_verdict,
            quality_score=winning_sub.quality_score,
            winning_submission=winning_sub,
            verdict_weights=weights,
            participating_miners=len(submissions),
        )
