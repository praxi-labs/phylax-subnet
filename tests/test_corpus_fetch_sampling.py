from __future__ import annotations

from phylax import rounds
from phylax.harness.corpus import fetch_corpus, select_from_listing


class _Client:
    def __init__(self, n: int):
        self.n = n
        self.fetched: list[str] = []

    def get_round_tasks(self, _round_id):
        return {"tasks": [
            {"source_id": f"sid{i:03d}", "label": "known-bad" if i % 2 else "known-good"}
            for i in range(self.n)
        ]}

    def get_round_artifact(self, _round_id, source_id):
        self.fetched.append(source_id)
        return {"files": {"a.py": "eA=="}, "ground_truth": {"expected_findings": []}}


def test_only_the_drawn_tasks_are_downloaded():
    c = _Client(150)
    items = fetch_corpus(c, "r1", "repositories", draw_seed="seed-a", count=50)
    assert len(c.fetched) == 50
    assert len(items) == 50


def test_without_a_seed_it_still_takes_everything():
    c = _Client(20)
    fetch_corpus(c, "r1", "repositories")
    assert len(c.fetched) == 20


def test_two_validators_download_different_subsets():
    a, b = _Client(150), _Client(150)
    sa = rounds.validator_draw_seed("round-seed", "hotkeyA")
    sb = rounds.validator_draw_seed("round-seed", "hotkeyB")
    fetch_corpus(a, "r1", "repositories", draw_seed=sa, count=50)
    fetch_corpus(b, "r1", "repositories", draw_seed=sb, count=50)
    assert set(a.fetched) != set(b.fetched)


def test_a_pool_smaller_than_the_draw_returns_all_of_it():
    entries = [{"source_id": f"s{i}"} for i in range(10)]
    assert len(select_from_listing(entries, "seed", 50)) == 10


def test_the_draw_is_reproducible():
    entries = [{"source_id": f"s{i}"} for i in range(150)]
    one = select_from_listing(entries, "seed-x", 50)
    two = select_from_listing(entries, "seed-x", 50)
    assert [e["source_id"] for e in one] == [e["source_id"] for e in two]
