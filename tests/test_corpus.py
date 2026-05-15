import json
import random

import pytest

from phylax.validator.corpus import FAMILIES, CorpusLoader


def _write_task(path, *, bundle_hash, verdict="ALLOW", name=None):
    payload = {
        "name": name or path.stem,
        "bundle_hash": bundle_hash,
        "metadata": {"name": "x", "version": "0.0.1"},
        "test_profile": "standard",
        "expected_verdict": verdict,
        "expected_risk_score": 10,
        "expected_capabilities": {},
        "expected_policy": {},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_loads_all_seven_families(tmp_path):
    for fam in FAMILIES:
        (tmp_path / fam).mkdir()
    for i, fam in enumerate(FAMILIES):
        _write_task(
            tmp_path / fam / "t.json",
            bundle_hash="sha256:" + f"{i:064x}",
        )

    loader = CorpusLoader(tmp_path).load()
    assert len(loader.tasks) == len(FAMILIES)
    fams = {t.family for t in loader.tasks}
    assert fams == set(FAMILIES)


def test_invalid_bundle_hash_recorded_as_error(tmp_path):
    (tmp_path / "known_bad").mkdir()
    bad = {
        "name": "bad",
        "bundle_hash": "not-a-sha256",
        "expected_verdict": "BLOCK",
    }
    (tmp_path / "known_bad" / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    loader = CorpusLoader(tmp_path).load()
    assert loader.tasks == []
    assert len(loader.errors) == 1


def test_stratified_sample_balances_families(tmp_path):
    for fam in ("known_bad", "known_good"):
        (tmp_path / fam).mkdir()
        for i in range(5):
            _write_task(
                tmp_path / fam / f"t{i}.json",
                bundle_hash="sha256:" + f"{fam.encode().hex():>064}"[-64:].replace("z", "0"),
                name=f"{fam}-{i}",
            )

    loader = CorpusLoader(tmp_path).load()
    sample = loader.sample_stratified(4, rng=random.Random(42))
    families = {t.family for t in sample}
    assert "known_bad" in families
    assert "known_good" in families
