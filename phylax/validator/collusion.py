from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

WINDOW_ROUNDS = 30
PRIMARY_AGREEMENT_HI = 0.90
AUDITOR_AGREEMENT_LO = 0.60
FLAG_THRESHOLD = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS consensus_history (
    hotkey TEXT NOT NULL,
    skill_type TEXT NOT NULL,
    round_id TEXT NOT NULL,
    aligned_with_primaries REAL NOT NULL,
    aligned_with_auditors REAL NOT NULL,
    recorded_at REAL NOT NULL,
    PRIMARY KEY (hotkey, skill_type, round_id)
);
CREATE INDEX IF NOT EXISTS ix_consensus_recorded ON consensus_history(recorded_at);
CREATE INDEX IF NOT EXISTS ix_consensus_hotkey_type ON consensus_history(hotkey, skill_type, recorded_at);

CREATE TABLE IF NOT EXISTS collusion_flags (
    hotkey TEXT PRIMARY KEY,
    flag_count INTEGER NOT NULL DEFAULT 0,
    last_flag_at REAL,
    last_reason TEXT
);
"""


@dataclass
class CollusionVerdict:
    hotkey: str
    flagged: bool
    primary_agreement: float
    auditor_agreement: float
    samples: int
    flag_count: int


class CollusionTracker:
    def __init__(self, db_path: str | Path) -> None:
        self._lock = threading.Lock()
        self._path = str(db_path)
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=2000")
        return c

    def record(
        self,
        *,
        hotkey: str,
        skill_type: str,
        round_id: str,
        aligned_with_primaries: float,
        aligned_with_auditors: float,
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO consensus_history
                (hotkey, skill_type, round_id, aligned_with_primaries,
                 aligned_with_auditors, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    hotkey, skill_type, round_id,
                    float(aligned_with_primaries),
                    float(aligned_with_auditors),
                    time.time(),
                ),
            )

    def evaluate(self, hotkey: str, skill_type: str) -> CollusionVerdict:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT aligned_with_primaries, aligned_with_auditors
                FROM consensus_history
                WHERE hotkey = ? AND skill_type = ?
                ORDER BY recorded_at DESC
                LIMIT ?
                """,
                (hotkey, skill_type, WINDOW_ROUNDS),
            ).fetchall()
            flag_row = conn.execute(
                "SELECT flag_count FROM collusion_flags WHERE hotkey = ?",
                (hotkey,),
            ).fetchone()
        if not rows:
            return CollusionVerdict(
                hotkey=hotkey, flagged=False,
                primary_agreement=0.0, auditor_agreement=0.0,
                samples=0, flag_count=int(flag_row[0]) if flag_row else 0,
            )
        n = len(rows)
        avg_p = sum(r[0] for r in rows) / n
        avg_a = sum(r[1] for r in rows) / n
        flagged = (
            n >= 5
            and avg_p > PRIMARY_AGREEMENT_HI
            and avg_a < AUDITOR_AGREEMENT_LO
        )
        return CollusionVerdict(
            hotkey=hotkey, flagged=flagged,
            primary_agreement=avg_p, auditor_agreement=avg_a,
            samples=n,
            flag_count=int(flag_row[0]) if flag_row else 0,
        )

    def add_flag(self, hotkey: str, reason: str = "") -> int:
        now = time.time()
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT flag_count FROM collusion_flags WHERE hotkey = ?",
                (hotkey,),
            ).fetchone()
            new_count = (int(row[0]) if row else 0) + 1
            conn.execute(
                """
                INSERT OR REPLACE INTO collusion_flags
                (hotkey, flag_count, last_flag_at, last_reason)
                VALUES (?, ?, ?, ?)
                """,
                (hotkey, new_count, now, reason[:200]),
            )
        return new_count

    def flagged_hotkeys(self) -> dict[str, int]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT hotkey, flag_count FROM collusion_flags WHERE flag_count >= ?",
                (FLAG_THRESHOLD,),
            ).fetchall()
        return {r[0]: int(r[1]) for r in rows}

    def prune_older_than(self, days: int = 7) -> int:
        cutoff = time.time() - days * 86400
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM consensus_history WHERE recorded_at < ?",
                (cutoff,),
            )
            return cur.rowcount
