from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from phylax.protocol import SSSA

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS attestations (
    bundle_hash    TEXT PRIMARY KEY,
    sssa_json      TEXT NOT NULL,
    verdict        TEXT NOT NULL,
    risk_score     INTEGER NOT NULL,
    miner_hotkey   TEXT NOT NULL,
    validator_hotkey TEXT,
    round_id       TEXT,
    quality_score  REAL,
    created_at     REAL NOT NULL,
    invalidated_at REAL,
    invalidation_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_attestations_verdict ON attestations(verdict);
CREATE INDEX IF NOT EXISTS idx_attestations_created ON attestations(created_at);
"""


@dataclass
class RegistryEntry:
    bundle_hash: str
    sssa: SSSA
    verdict: str
    risk_score: int
    miner_hotkey: str
    validator_hotkey: str | None
    round_id: str | None
    quality_score: float | None
    created_at: float
    invalidated_at: float | None = None
    invalidation_reason: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.invalidated_at is None


class AttestationRegistry:
    """Thread-safe SQLite-backed consensus attestation store."""

    def __init__(self, db_path: str | Path = "phylax_registry.sqlite3"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA_SQL)

    def _conn(self):
        conn = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ------------------------------------------------------------------

    def put(self, sssa: SSSA, *, round_id: str, quality_score: float) -> None:
        """Insert or upsert a consensus SSSA keyed by ``bundle_hash``."""
        if sssa.attestation is None:
            raise ValueError("cannot store an unsigned SSSA")
        validator_hotkey = sssa.countersignature.validator_hotkey if sssa.countersignature else None
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO attestations (
                    bundle_hash, sssa_json, verdict, risk_score, miner_hotkey,
                    validator_hotkey, round_id, quality_score, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bundle_hash) DO UPDATE SET
                    sssa_json = excluded.sssa_json,
                    verdict = excluded.verdict,
                    risk_score = excluded.risk_score,
                    miner_hotkey = excluded.miner_hotkey,
                    validator_hotkey = excluded.validator_hotkey,
                    round_id = excluded.round_id,
                    quality_score = excluded.quality_score,
                    created_at = excluded.created_at,
                    invalidated_at = NULL,
                    invalidation_reason = NULL
                """,
                (
                    sssa.skill.bundle_hash,
                    json.dumps(sssa.model_dump(mode="json"), sort_keys=True),
                    sssa.verdict.decision.value,
                    sssa.verdict.risk_score,
                    sssa.attestation.miner_hotkey,
                    validator_hotkey,
                    round_id,
                    float(quality_score),
                    time.time(),
                ),
            )

    def get(self, bundle_hash: str, *, only_valid: bool = True) -> RegistryEntry | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                """SELECT bundle_hash, sssa_json, verdict, risk_score, miner_hotkey,
                          validator_hotkey, round_id, quality_score, created_at,
                          invalidated_at, invalidation_reason
                   FROM attestations WHERE bundle_hash = ?""",
                (bundle_hash,),
            ).fetchone()
        if not row:
            return None
        if only_valid and row[9] is not None:
            return None
        sssa = SSSA(**json.loads(row[1]))
        return RegistryEntry(
            bundle_hash=row[0],
            sssa=sssa,
            verdict=row[2],
            risk_score=row[3],
            miner_hotkey=row[4],
            validator_hotkey=row[5],
            round_id=row[6],
            quality_score=row[7],
            created_at=row[8],
            invalidated_at=row[9],
            invalidation_reason=row[10],
        )

    def invalidate(self, bundle_hash: str, reason: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE attestations SET invalidated_at = ?, invalidation_reason = ? "
                "WHERE bundle_hash = ? AND invalidated_at IS NULL",
                (time.time(), reason, bundle_hash),
            )
            return cur.rowcount > 0

    def invalidate_by_publisher(self, miner_hotkey: str, reason: str) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE attestations SET invalidated_at = ?, invalidation_reason = ? "
                "WHERE miner_hotkey = ? AND invalidated_at IS NULL",
                (time.time(), reason, miner_hotkey),
            )
            return cur.rowcount

    def stats(self) -> dict[str, int]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                """SELECT
                       COUNT(*),
                       SUM(CASE WHEN invalidated_at IS NULL THEN 1 ELSE 0 END),
                       SUM(CASE WHEN verdict = 'BLOCK' AND invalidated_at IS NULL THEN 1 ELSE 0 END),
                       SUM(CASE WHEN verdict = 'WARN'  AND invalidated_at IS NULL THEN 1 ELSE 0 END),
                       SUM(CASE WHEN verdict = 'ALLOW' AND invalidated_at IS NULL THEN 1 ELSE 0 END)
                   FROM attestations"""
            ).fetchone()
        return {
            "total": row[0] or 0,
            "active": row[1] or 0,
            "block": row[2] or 0,
            "warn": row[3] or 0,
            "allow": row[4] or 0,
        }
