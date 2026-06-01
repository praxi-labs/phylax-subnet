from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rerun_jobs (
    id TEXT PRIMARY KEY,
    hotkey TEXT NOT NULL,
    skill_type TEXT NOT NULL,
    task_id TEXT NOT NULL,
    bundle_bytes_b64 TEXT NOT NULL,
    nonce TEXT NOT NULL,
    canary_id TEXT NOT NULL,
    canary_val TEXT NOT NULL,
    submitted_hashes_json TEXT NOT NULL,
    miner_records_json TEXT NOT NULL,
    sandbox_image_uri TEXT NOT NULL,
    sandbox_image_hash TEXT NOT NULL,
    timeout_s INTEGER NOT NULL,
    enqueued_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    leased_until REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_rerun_lease ON rerun_jobs(leased_until);
"""


@dataclass
class RerunJob:
    hotkey: str
    skill_type: str
    task_id: str
    bundle_bytes: bytes
    nonce: str
    canary_id: str
    canary_val: str
    submitted_hashes: dict[str, str]
    miner_submitted_records: dict[str, list[dict]]
    sandbox_image_uri: str
    sandbox_image_hash: str
    timeout_s: int
    id: str = field(default_factory=lambda: uuid.uuid4().hex)


class RerunQueue:
    def __init__(self, db_path: str | Path) -> None:
        self._lock = threading.Lock()
        self._path = str(db_path)
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path, timeout=10.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=5000")
        return c

    def enqueue(self, job: RerunJob) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rerun_jobs (
                    id, hotkey, skill_type, task_id, bundle_bytes_b64, nonce,
                    canary_id, canary_val, submitted_hashes_json,
                    miner_records_json, sandbox_image_uri, sandbox_image_hash,
                    timeout_s, enqueued_at, attempts, leased_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    job.id,
                    job.hotkey,
                    job.skill_type,
                    job.task_id,
                    base64.b64encode(job.bundle_bytes).decode("ascii"),
                    job.nonce,
                    job.canary_id,
                    job.canary_val,
                    json.dumps(job.submitted_hashes, sort_keys=True),
                    json.dumps(job.miner_submitted_records, sort_keys=True),
                    job.sandbox_image_uri,
                    job.sandbox_image_hash,
                    int(job.timeout_s),
                    time.time(),
                ),
            )

    def lease(self, lease_seconds: int = 1800) -> RerunJob | None:
        now = time.time()
        with self._lock, self._conn() as conn:
            row = conn.execute(
                """
                SELECT id, hotkey, skill_type, task_id, bundle_bytes_b64, nonce,
                       canary_id, canary_val, submitted_hashes_json,
                       miner_records_json, sandbox_image_uri, sandbox_image_hash,
                       timeout_s, attempts
                FROM rerun_jobs
                WHERE leased_until <= ?
                ORDER BY enqueued_at ASC
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                return None
            (
                job_id, hotkey, skill_type, task_id, bundle_b64, nonce,
                cid, cval, hashes_json, ref_json, image_uri, image_hash,
                timeout_s, attempts,
            ) = row
            conn.execute(
                "UPDATE rerun_jobs SET leased_until = ?, attempts = ? WHERE id = ?",
                (now + lease_seconds, attempts + 1, job_id),
            )
            return RerunJob(
                id=job_id,
                hotkey=hotkey,
                skill_type=skill_type,
                task_id=task_id,
                bundle_bytes=base64.b64decode(bundle_b64),
                nonce=nonce,
                canary_id=cid,
                canary_val=cval,
                submitted_hashes=json.loads(hashes_json),
                miner_submitted_records=json.loads(ref_json),
                sandbox_image_uri=image_uri,
                sandbox_image_hash=image_hash,
                timeout_s=int(timeout_s),
            )

    def complete(self, job_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM rerun_jobs WHERE id = ?", (job_id,))

    def fail(self, job_id: str, max_attempts: int = 3) -> None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT attempts FROM rerun_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                return
            if int(row[0]) >= max_attempts:
                conn.execute("DELETE FROM rerun_jobs WHERE id = ?", (job_id,))
            else:
                conn.execute(
                    "UPDATE rerun_jobs SET leased_until = 0 WHERE id = ?",
                    (job_id,),
                )

    def stats(self) -> dict[str, Any]:
        with self._lock, self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM rerun_jobs").fetchone()[0]
            leased = conn.execute(
                "SELECT COUNT(*) FROM rerun_jobs WHERE leased_until > ?",
                (time.time(),),
            ).fetchone()[0]
        return {"total": int(total), "leased": int(leased)}

    def to_dict(self, job: RerunJob) -> dict[str, Any]:
        d = asdict(job)
        d["bundle_bytes"] = base64.b64encode(job.bundle_bytes).decode("ascii")
        return d
