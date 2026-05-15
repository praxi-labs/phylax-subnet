from __future__ import annotations

import pytest

from neurons.validator import PhylaxValidator
from phylax.validator.corpus import CorpusTask


def _server_task(**overrides):
    base = {
        "bundle_hash": "sha256:" + "a" * 64,
        "family": "known_bad",
        "name": "exfil-webhook",
        "description": "",
        "bundle_url": "https://example/exfil.zip",
        "metadata": {"name": "exfil-webhook", "permissions": ["network"]},
        "test_profile": "standard",
        "expected_verdict": "BLOCK",
        "expected_risk_score": 95,
        "expected_capabilities": {"network": {"egress": True}},
        "expected_policy": {"egress_allowlist": []},
        "expected_findings": [{"title_contains": "exfil"}],
        "tags": ["exfil"],
    }
    base.update(overrides)
    return base


def test_adapter_preserves_required_fields():
    server_task = _server_task()
    ct = PhylaxValidator._server_task_to_corpus_task(server_task)
    assert isinstance(ct, CorpusTask)
    assert ct.bundle_hash == server_task["bundle_hash"]
    assert ct.family == "known_bad"
    assert ct.expected_verdict == "BLOCK"
    assert ct.expected_risk_score == 95
    assert ct.path.startswith("server://sha256:")


def test_adapter_handles_missing_expected_fields():
    """Server-generated synthetic tasks may arrive without expected_verdict."""
    server_task = _server_task(
        family="synthetic", expected_verdict=None, expected_risk_score=None
    )
    ct = PhylaxValidator._server_task_to_corpus_task(server_task)
    # Adapter defaults expected_verdict to ALLOW so the CorpusTask
    # constructor doesn't reject it (it requires ALLOW/WARN/BLOCK).
    assert ct.expected_verdict == "ALLOW"
    assert ct.expected_risk_score is None


def test_adapter_handles_inline_bundle_bytes():
    server_task = _server_task(
        bundle_url=None, bundle_bytes_b64="Zm9vYmFy"  # b64 for "foobar"
    )
    ct = PhylaxValidator._server_task_to_corpus_task(server_task)
    assert ct.bundle_url is None
    assert ct.bundle_bytes_b64 == "Zm9vYmFy"


def test_adapter_handles_empty_optional_fields():
    server_task = _server_task(
        metadata=None,
        expected_capabilities=None,
        expected_policy=None,
        expected_findings=None,
        tags=None,
    )
    ct = PhylaxValidator._server_task_to_corpus_task(server_task)
    assert ct.metadata == {}
    assert ct.expected_capabilities == {}
    assert ct.expected_policy == {}
    assert ct.expected_findings == []
    assert ct.tags == []
