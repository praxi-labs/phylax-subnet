from __future__ import annotations

import hashlib
import os
import random

TRACK_ROUND_PARAMS: dict[str, dict[str, int]] = {
    "skills": {"blocks": 1440, "tasks": 30, "repetitions": 3, "timeout_s": 8},
    "mcp_servers": {"blocks": 2250, "tasks": 25, "repetitions": 3, "timeout_s": 15},
    "packages": {"blocks": 3600, "tasks": 20, "repetitions": 3, "timeout_s": 30},
    "repositories": {"blocks": 4800, "tasks": 10, "repetitions": 2, "timeout_s": 120},
}

_ENV_OVERRIDES = {
    "blocks": "PHYLAX_ROUND_BLOCKS",
    "tasks": "PHYLAX_TASKS_PER_ROUND",
    "repetitions": "PHYLAX_REPETITIONS",
    "timeout_s": "PHYLAX_TASK_TIMEOUT",
}


def params_for(track: str) -> dict[str, int]:
    params = dict(TRACK_ROUND_PARAMS.get(track, TRACK_ROUND_PARAMS["skills"]))
    for key, env in _ENV_OVERRIDES.items():
        raw = os.getenv(env, "").strip()
        if raw:
            params[key] = int(raw)
    return params


def round_start(block: int, blocks_per_round: int) -> int:
    return (block // blocks_per_round) * blocks_per_round


def round_seed(start_block_hash: str, track: str) -> str:
    return hashlib.sha256(f"{start_block_hash}:{track}".encode()).hexdigest()


def select_tasks(corpus: list[dict], seed: str, count: int) -> list[dict]:
    items = sorted(corpus, key=lambda item: item["ref"])
    if count >= len(items):
        return items
    return random.Random(seed).sample(items, count)  # noqa: S311


def task_nonce(seed: str, ref: str, agent: str = "") -> str:
    # Per-(agent, task) so each agent's probe and inference-liveness are keyed to
    # it alone — one agent's activity can never vouch for another's on the same task.
    return hashlib.sha256(f"{seed}:{ref}:{agent}".encode()).hexdigest()
