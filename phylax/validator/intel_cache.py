"""Validator-side cache for the server's intel/CVE responses.

Purpose: keep the validator running cleanly when phylax-server is
unreachable for short periods. Without this, every server outage
craters the round (no intel queries → degraded discrepancy → divergent
verdicts across validators). With it, the validator serves recent
responses from disk and only takes the freshness hit, not the
correctness hit.

Cache shape: a single SQLite file under PHYLAX_REGISTRY_PATH's directory.
Keys are content-addressed by the request body (so re-issuing the same
intel_lookup or cve_lookup payload returns the cached response).
Entries carry both ``fetched_at`` and ``expires_at`` so the runtime can
distinguish "fresh cached" from "stale, last-known-good fallback."

This file is purely defensive — it doesn't add new scoring signals,
it just keeps existing ones working through transient server outages.
A miner can't observe the cache directly (it's local to the validator)
so it doesn't change the asymmetry story.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from phylax.utils.logging import get_logger

logger = get_logger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS intel_cache (
    cache_key   TEXT PRIMARY KEY,
    endpoint    TEXT NOT NULL,
    response    TEXT NOT NULL,
    fetched_at  REAL NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intel_cache_expires ON intel_cache(expires_at);
"""

# How long an entry stays "fresh." After this point the cache still
# returns it (better than nothing during a server outage), but flags
# it as stale.
FRESH_TTL_SECONDS = 6 * 60 * 60       # 6h
# Hard upper bound: entries older than this get evicted and the
# fallback is "no cached answer" (caller proceeds without intel).
STALE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7d


def _default_cache_path() -> str:
    """Cache file lives next to the attestation registry so operators
    only configure one persistent path. Falls back to /tmp for tests."""
    registry_path = os.getenv("PHYLAX_REGISTRY_PATH", "")
    if registry_path:
        parent = Path(registry_path).expanduser().parent
    else:
        parent = Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    return str(parent / "phylax_intel_cache.sqlite3")


def _hash_payload(endpoint: str, payload: dict) -> str:
    """Canonical hash so re-issuing the same logical query maps to the
    same cache key regardless of dict ordering."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256()
    h.update(endpoint.encode("ascii"))
    h.update(b"\n")
    h.update(canonical.encode("utf-8"))
    return h.hexdigest()


class IntelCache:
    """Thread-safe SQLite-backed cache for server intel responses.

    All methods are sync (the cache itself never makes network calls).
    The caller — typically ``ServerIntelClient`` below — wraps this
    around real ``server_client.intel_lookup`` / ``cve_lookup`` calls.
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or _default_cache_path()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def get(self, endpoint: str, payload: dict) -> tuple[dict, bool] | None:
        """Return (response, is_fresh) or None if there's no usable entry."""
        key = _hash_payload(endpoint, payload)
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT response, fetched_at FROM intel_cache "
                "WHERE cache_key = ? AND expires_at > ?",
                (key, time.time()),
            ).fetchone()
        if row is None:
            return None
        response = json.loads(row[0])
        is_fresh = (time.time() - row[1]) < FRESH_TTL_SECONDS
        return response, is_fresh

    def put(self, endpoint: str, payload: dict, response: dict) -> None:
        key = _hash_payload(endpoint, payload)
        now = time.time()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO intel_cache (cache_key, endpoint, response, fetched_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    response = excluded.response,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (key, endpoint, json.dumps(response, sort_keys=True), now, now + STALE_TTL_SECONDS),
            )

    def evict_expired(self) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM intel_cache WHERE expires_at <= ?", (time.time(),))
            return cur.rowcount

    def stats(self) -> dict[str, int]:
        with self._lock, self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM intel_cache").fetchone()[0]
            fresh = conn.execute(
                "SELECT COUNT(*) FROM intel_cache WHERE fetched_at > ?",
                (time.time() - FRESH_TTL_SECONDS,),
            ).fetchone()[0]
        return {"total": total, "fresh": fresh, "stale": total - fresh}


class ServerIntelClient:
    """Cached wrapper around the validator's server_client.intel_lookup
    and cve_lookup calls.

    ``intel_client.intel_lookup(hosts=...)`` checks the cache first; on
    miss it calls the server and caches the response. On server failure
    (unreachable, HTTP error), it falls back to the stale-but-cached
    entry if one exists and logs a warning. If there's no usable cache
    entry AND the server fails, it returns an empty-results response so
    BaselineRunner can proceed with manifest-only discrepancy rather
    than crater the whole round.

    BaselineRunner gets one of these (constructed from the validator's
    server_client) instead of the raw server_client when intel is wired
    in. When the validator has no server_client (offline / local-dev),
    intel_client is None and BaselineRunner skips intel entirely.
    """

    def __init__(self, server_client, cache: IntelCache | None = None):
        self.server_client = server_client
        self.cache = cache or IntelCache()

    def intel_lookup(
        self,
        hosts: list[str] | None = None,
        ips: list[str] | None = None,
    ) -> dict:
        payload = {"hosts": hosts or [], "ips": ips or []}
        return self._cached_call("/v1/intel/lookup", payload, "intel_lookup")

    def cve_lookup(self, packages: list[dict] | None = None) -> dict:
        payload = {"packages": packages or []}
        return self._cached_call("/v1/intel/cve_lookup", payload, "cve_lookup")

    def _cached_call(self, endpoint: str, payload: dict, method_name: str) -> dict:
        cached = self.cache.get(endpoint, payload)
        if cached is not None:
            response, is_fresh = cached
            if is_fresh:
                return response
            # Stale-but-usable. Try to refresh; fall back to cached
            # response if the refresh fails.
            try:
                fresh = getattr(self.server_client, method_name)(**self._payload_to_kwargs(method_name, payload))
                self.cache.put(endpoint, payload, fresh)
                return fresh
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "intel refresh failed (%s); serving stale cache: %s", method_name, e
                )
                return response

        # No cache entry. Hit the server; on failure, return an empty
        # response so the discrepancy engine can proceed.
        try:
            fresh = getattr(self.server_client, method_name)(**self._payload_to_kwargs(method_name, payload))
            self.cache.put(endpoint, payload, fresh)
            return fresh
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "intel call failed and no cache available (%s); returning empty: %s",
                method_name, e,
            )
            return {"queried_at": "", "results": []}

    @staticmethod
    def _payload_to_kwargs(method_name: str, payload: dict) -> dict:
        if method_name == "intel_lookup":
            return {"hosts": payload.get("hosts") or [], "ips": payload.get("ips") or []}
        if method_name == "cve_lookup":
            return {"packages": payload.get("packages") or []}
        return payload
