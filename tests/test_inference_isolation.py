from __future__ import annotations

import json
import types

import pytest

from phylax.harness import inference_proxy as proxy


@pytest.fixture(autouse=True)
def _clear_metrics():
    with proxy._LOCK:
        proxy._METRICS.clear()
    yield
    with proxy._LOCK:
        proxy._METRICS.clear()


def test_exhausted_key_is_recorded_without_counting_as_a_call():
    proxy._record_upstream_error("nonce-a", 402)
    row = proxy._usage("nonce-a")
    assert row["requests"] == 0
    assert row["key_failures"] == 1
    assert row["last_upstream_status"] == 402


def test_a_server_side_upstream_fault_is_not_blamed_on_the_key():
    proxy._record_upstream_error("nonce-b", 503)
    row = proxy._usage("nonce-b")
    assert row.get("key_failures", 0) == 0
    assert row["upstream_errors"] == 1


def test_one_agents_failure_leaves_another_agents_meter_untouched():
    proxy._record_upstream_error("agent-1", 401)
    proxy._record("agent-2", json.dumps({"usage": {"prompt_tokens": 5}}).encode())
    assert proxy._usage("agent-1")["requests"] == 0
    assert proxy._usage("agent-2")["requests"] == 1
    assert proxy._usage("agent-2").get("key_failures", 0) == 0


def _validator_stub(metrics: dict | None, healthy: bool):
    pytest.importorskip("bittensor")
    import neurons.validator as v

    stub = types.SimpleNamespace(
        _proxy_admin=lambda path, payload=None: metrics or {},
        _inference_ready=lambda: healthy,
    )
    stub._inference_failure_reason = types.MethodType(
        v.PhylaxValidator._inference_failure_reason, stub
    )
    stub._inference_required = types.MethodType(
        v.PhylaxValidator._inference_required, stub
    )
    return stub


def test_failure_reason_separates_a_dead_key_from_a_skipped_call():
    dead = _validator_stub({"usage": {"key_failures": 3}}, healthy=True)
    assert dead._inference_failure_reason("n") == "inference_key_failed"

    skipped = _validator_stub({"usage": {"requests": 0}}, healthy=True)
    assert skipped._inference_failure_reason("n") == "no_inference"


def test_repositories_never_requires_the_inference_proxy():
    stub = _validator_stub({}, healthy=False)
    assert stub._inference_required("repositories") is False
    assert stub._inference_required("packages") is True
