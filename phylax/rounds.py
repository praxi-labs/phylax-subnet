from __future__ import annotations

import hashlib
import random

TRACKS = ("skills", "mcp_servers", "packages", "repositories")

ROUND_BLOCKS = 3600

TRACK_BUDGETS: dict[str, dict[str, int]] = {
    "skills": {"tasks": 50, "repetitions": 3, "cpu_s": 8},
    "mcp_servers": {"tasks": 40, "repetitions": 3, "cpu_s": 15},
    "packages": {"tasks": 30, "repetitions": 3, "cpu_s": 30},
    "repositories": {"tasks": 50, "repetitions": 2, "cpu_s": 90},
}

WALL_BACKSTOP_FACTOR = 3
AGENT_WALL_FACTOR = 2


def budgets_for(track: str) -> dict[str, int]:
    return dict(TRACK_BUDGETS.get(track, TRACK_BUDGETS["skills"]))


def agent_wall_cap_s(track: str) -> int:
    b = budgets_for(track)
    return AGENT_WALL_FACTOR * b["tasks"] * b["repetitions"] * b["cpu_s"]


def round_start(block: int, blocks_per_round: int = ROUND_BLOCKS) -> int:
    return (block // blocks_per_round) * blocks_per_round


def round_seed(start_block_hash: str, track: str) -> str:
    return hashlib.sha256(f"{start_block_hash}:{track}".encode()).hexdigest()


def select_tasks(corpus: list[dict], seed: str, count: int) -> list[dict]:
    items = sorted(corpus, key=lambda item: item["ref"])
    if count >= len(items):
        return items
    return random.Random(seed).sample(items, count)  # noqa: S311


def task_nonce(seed: str, ref: str, agent: str = "") -> str:
    return hashlib.sha256(f"{seed}:{ref}:{agent}".encode()).hexdigest()
