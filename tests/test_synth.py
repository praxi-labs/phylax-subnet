import hashlib
import random
import zipfile
from io import BytesIO

import pytest

from phylax.validator.synth import SyntheticGenerator


def test_generator_produces_valid_zip_with_manifest():
    gen = SyntheticGenerator(rng=random.Random(1))
    sk = gen.generate("adversarial")
    assert sk.bundle_hash.startswith("sha256:")
    assert sk.bundle_hash == "sha256:" + hashlib.sha256(sk.bundle_bytes).hexdigest()
    with zipfile.ZipFile(BytesIO(sk.bundle_bytes)) as zf:
        names = set(zf.namelist())
    assert "manifest.json" in names
    assert any(n.endswith(".py") for n in names)


@pytest.mark.parametrize(
    "family,expected_verdict",
    [
        ("adversarial", "BLOCK"),
        ("canary", "WARN"),
        ("near_miss", "WARN"),
        ("prompt_conditioned", "BLOCK"),
    ],
)
def test_each_family_emits_expected_verdict(family, expected_verdict):
    gen = SyntheticGenerator(rng=random.Random(7))
    sk = gen.generate(family)
    assert sk.task["expected_verdict"] == expected_verdict


def test_synthetic_tasks_have_required_fields():
    gen = SyntheticGenerator(rng=random.Random(2))
    sk = gen.generate("adversarial")
    for k in ("name", "bundle_hash", "expected_verdict", "expected_policy", "tags"):
        assert k in sk.task
