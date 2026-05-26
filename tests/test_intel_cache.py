"""Validator-side intel cache tests.

The cache exists for SPOF defense: when phylax-server is unreachable,
validators serve last-known-good responses from disk and only take
the freshness hit, not the correctness hit.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from phylax.validator import intel_cache


@pytest.fixture
def cache(tmp_path):
    return intel_cache.IntelCache(db_path=str(tmp_path / "test_intel.sqlite3"))


def test_cache_round_trip(cache):
    payload = {"hosts": ["a.example"], "ips": []}
    response = {"queried_at": "2026-05-26T00:00:00", "results": [{"host": "a.example", "hits": []}]}
    cache.put("/v1/intel/lookup", payload, response)
    cached = cache.get("/v1/intel/lookup", payload)
    assert cached is not None
    out, is_fresh = cached
    assert out == response
    assert is_fresh is True


def test_cache_key_is_payload_independent_of_dict_order(cache):
    """Same logical payload with different dict ordering must hit the
    same cache entry. Otherwise validators with non-deterministic dict
    iteration order double-fetch."""
    p1 = {"hosts": ["a"], "ips": []}
    p2 = {"ips": [], "hosts": ["a"]}
    cache.put("/v1/intel/lookup", p1, {"results": [], "queried_at": ""})
    assert cache.get("/v1/intel/lookup", p2) is not None


def test_cache_miss_returns_none(cache):
    assert cache.get("/v1/intel/lookup", {"hosts": ["never-cached"]}) is None


def test_cache_marks_stale_after_fresh_ttl(cache, monkeypatch):
    """After FRESH_TTL but before STALE_TTL, entry is still returned but
    flagged as stale so the caller knows to try a refresh."""
    cache.put("/v1/intel/lookup", {"hosts": ["x"]}, {"results": []})
    # Fast-forward time past the fresh window
    monkeypatch.setattr(intel_cache.time, "time",
                        lambda: time.time() + intel_cache.FRESH_TTL_SECONDS + 60)
    cached = cache.get("/v1/intel/lookup", {"hosts": ["x"]})
    assert cached is not None
    _, is_fresh = cached
    assert is_fresh is False


def test_cache_evicts_after_stale_ttl(cache, monkeypatch):
    cache.put("/v1/intel/lookup", {"hosts": ["x"]}, {"results": []})
    monkeypatch.setattr(intel_cache.time, "time",
                        lambda: time.time() + intel_cache.STALE_TTL_SECONDS + 60)
    assert cache.get("/v1/intel/lookup", {"hosts": ["x"]}) is None


def test_cache_evict_expired_returns_count(cache, monkeypatch):
    for i in range(5):
        cache.put("/v1/intel/lookup", {"hosts": [f"x{i}"]}, {"results": []})
    monkeypatch.setattr(intel_cache.time, "time",
                        lambda: time.time() + intel_cache.STALE_TTL_SECONDS + 60)
    assert cache.evict_expired() == 5


def test_cache_stats(cache):
    cache.put("/v1/intel/lookup", {"hosts": ["a"]}, {"results": []})
    cache.put("/v1/intel/lookup", {"hosts": ["b"]}, {"results": []})
    s = cache.stats()
    assert s["total"] == 2
    assert s["fresh"] == 2
    assert s["stale"] == 0


# ---------------------------------------------------------------------------
# ServerIntelClient — the wrapper BaselineRunner actually uses
# ---------------------------------------------------------------------------


def test_server_intel_client_caches_on_first_call(cache):
    """First call goes to server; second call to same payload hits cache."""
    inner = MagicMock()
    inner.intel_lookup.return_value = {"queried_at": "", "results": [{"host": "a", "hits": []}]}
    client = intel_cache.ServerIntelClient(inner, cache=cache)

    client.intel_lookup(hosts=["a"])
    client.intel_lookup(hosts=["a"])
    assert inner.intel_lookup.call_count == 1


def test_server_intel_client_returns_stale_on_server_failure(cache, monkeypatch):
    """When the server fails AND we have a stale cached entry, return
    the stale response rather than crater the round."""
    inner = MagicMock()
    inner.intel_lookup.return_value = {"queried_at": "", "results": [{"host": "a", "hits": []}]}
    client = intel_cache.ServerIntelClient(inner, cache=cache)

    # Prime the cache
    client.intel_lookup(hosts=["a"])
    # Age it past fresh
    monkeypatch.setattr(intel_cache.time, "time",
                        lambda: time.time() + intel_cache.FRESH_TTL_SECONDS + 60)
    # Now server fails on the refresh attempt
    inner.intel_lookup.side_effect = RuntimeError("server unreachable")
    out = client.intel_lookup(hosts=["a"])
    assert out["results"] == [{"host": "a", "hits": []}]


def test_server_intel_client_returns_empty_when_no_cache_and_server_fails(cache):
    """The genuinely bad case: no cache, server down. Return an empty
    well-formed response so BaselineRunner can proceed with
    manifest-only discrepancy rather than crash."""
    inner = MagicMock()
    inner.intel_lookup.side_effect = RuntimeError("server unreachable")
    client = intel_cache.ServerIntelClient(inner, cache=cache)

    out = client.intel_lookup(hosts=["a"])
    assert out == {"queried_at": "", "results": []}


def test_server_intel_client_cve_lookup_uses_same_cache_path(cache):
    inner = MagicMock()
    inner.cve_lookup.return_value = {"queried_at": "", "results": []}
    client = intel_cache.ServerIntelClient(inner, cache=cache)

    client.cve_lookup(packages=[{"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"}])
    client.cve_lookup(packages=[{"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"}])
    assert inner.cve_lookup.call_count == 1
