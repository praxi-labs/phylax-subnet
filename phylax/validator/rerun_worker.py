from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from phylax.harness.trace_normalisation import hash_jsonl_bytes
from phylax.utils.logging import get_logger
from phylax.validator.rerun_queue import RerunJob, RerunQueue
from phylax.validator.trace_verification import (
    _BASE_FILES,
    CANARY_PATH,
    _signatures_for,
)

logger = get_logger(__name__)

_PULL_TIMEOUT_S = 600


@dataclass
class RerunOutcome:
    job_id: str
    hotkey: str
    skill_type: str
    task_id: str
    image_hash: str
    passed: bool
    fs_trace_hash_matched: bool
    semantic_agreement: float
    notes: str


class RerunWorker:
    def __init__(
        self,
        queue: RerunQueue,
        post_outcomes,
        *,
        max_concurrency: int = 1,
        poll_interval_s: int = 5,
    ) -> None:
        self.queue = queue
        self.post_outcomes = post_outcomes
        self.max_concurrency = max_concurrency
        self.poll_interval_s = poll_interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        if not shutil.which("docker"):
            logger.warning(
                "rerun worker: docker not on PATH; rerun verification will be skipped"
            )
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="phylax-rerun")
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self.queue.lease()
            except Exception as e:  # noqa: BLE001
                logger.warning(f"rerun worker: queue lease failed: {e}")
                time.sleep(self.poll_interval_s)
                continue
            if job is None:
                time.sleep(self.poll_interval_s)
                continue
            try:
                outcome = self._verify(job)
                self._post(outcome)
                self.queue.complete(job.id)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"rerun worker: job {job.id} failed: {e}")
                self.queue.fail(job.id)

    def _verify(self, job: RerunJob) -> RerunOutcome:
        if not _pull_image(job.sandbox_image_uri, job.sandbox_image_hash):
            return RerunOutcome(
                job_id=job.id,
                hotkey=job.hotkey,
                skill_type=job.skill_type,
                task_id=job.task_id,
                image_hash=job.sandbox_image_hash,
                passed=False,
                fs_trace_hash_matched=False,
                semantic_agreement=0.0,
                notes="image pull/digest verification failed",
            )

        with tempfile.TemporaryDirectory(prefix="phylax-rerun-") as tmp_root:
            tmp = Path(tmp_root)
            bundle_dir = tmp / "bundle"
            evidence_dir = tmp / "evidence"
            bundle_dir.mkdir()
            evidence_dir.mkdir()
            _materialise_bundle_bytes(job.bundle_bytes, bundle_dir)

            try:
                _run_miner_container(
                    image=job.sandbox_image_uri,
                    bundle_dir=bundle_dir,
                    evidence_dir=evidence_dir,
                    nonce=job.nonce,
                    canary_id=job.canary_id,
                    canary_val=job.canary_val,
                    timeout_s=job.timeout_s,
                )
            except Exception as e:  # noqa: BLE001
                return RerunOutcome(
                    job_id=job.id,
                    hotkey=job.hotkey,
                    skill_type=job.skill_type,
                    task_id=job.task_id,
                    image_hash=job.sandbox_image_hash,
                    passed=False,
                    fs_trace_hash_matched=False,
                    semantic_agreement=0.0,
                    notes=f"container run failed: {e}",
                )

            rerun_records: dict[str, list[dict]] = {}
            rerun_fs_hash: str | None = None
            for fname in _BASE_FILES:
                trace_path = evidence_dir / fname.removesuffix(".gz")
                try:
                    raw = trace_path.read_bytes() if trace_path.exists() else b""
                except OSError:
                    raw = b""
                if raw.strip():
                    rerun_records[fname] = _parse_records(raw)
                    if fname == "fs.jsonl.gz":
                        rerun_fs_hash = hash_jsonl_bytes(raw)
                else:
                    rerun_records[fname] = []

            fs_match = (
                rerun_fs_hash is not None
                and rerun_fs_hash == job.submitted_hashes.get("fs_trace_hash")
            )

            canary_in_rerun = any(
                str(r.get("path", "")) == CANARY_PATH
                for r in rerun_records.get("fs.jsonl.gz", [])
            )

            scores: list[float] = []
            for fname in _BASE_FILES:
                miner_sigs = _signatures_for(fname, job.miner_submitted_records.get(fname, []))
                rerun_sigs = _signatures_for(fname, rerun_records.get(fname, []))
                if not rerun_sigs:
                    scores.append(1.0 if not miner_sigs else 0.0)
                    continue
                overlap = len(rerun_sigs & miner_sigs)
                scores.append(overlap / len(rerun_sigs))
            semantic_agreement = sum(scores) / len(scores) if scores else 0.0

            passed = bool(fs_match and canary_in_rerun and semantic_agreement >= 0.7)
            notes = ""
            if not fs_match:
                notes = "fs_trace_hash mismatch"
            elif not canary_in_rerun:
                notes = "canary not observed in rerun"
            elif semantic_agreement < 0.7:
                notes = f"semantic agreement {semantic_agreement:.2f} below 0.7"

            return RerunOutcome(
                job_id=job.id,
                hotkey=job.hotkey,
                skill_type=job.skill_type,
                task_id=job.task_id,
                image_hash=job.sandbox_image_hash,
                passed=passed,
                fs_trace_hash_matched=fs_match,
                semantic_agreement=semantic_agreement,
                notes=notes,
            )

    def _post(self, outcome: RerunOutcome) -> None:
        try:
            self.post_outcomes([outcome])
        except Exception as e:  # noqa: BLE001
            logger.warning(f"rerun worker: post outcomes failed: {e}")


def _pull_image(image_uri: str, expected_digest: str) -> bool:
    try:
        proc = subprocess.run(  # noqa: S603
            ["docker", "pull", image_uri],
            capture_output=True,
            text=True,
            timeout=_PULL_TIMEOUT_S,
        )
        if proc.returncode != 0:
            logger.warning(f"docker pull failed for {image_uri}: {proc.stderr[:200]}")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning(f"docker pull error for {image_uri}: {e}")
        return False
    try:
        inspect = subprocess.run(  # noqa: S603
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", image_uri],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if inspect.returncode != 0:
            return False
        line = inspect.stdout.strip()
        if "@" in line:
            actual_digest = line.split("@", 1)[1]
        else:
            actual_digest = ""
        return actual_digest == expected_digest
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _materialise_bundle_bytes(bundle_bytes: bytes, dest: Path) -> None:
    if not bundle_bytes:
        return
    buf = io.BytesIO(bundle_bytes)
    try:
        with zipfile.ZipFile(buf) as zf:
            zf.extractall(dest)
    except zipfile.BadZipFile:
        (dest / "skill.bin").write_bytes(bundle_bytes)


def _run_miner_container(
    *,
    image: str,
    bundle_dir: Path,
    evidence_dir: Path,
    nonce: str,
    canary_id: str,
    canary_val: str,
    timeout_s: int,
) -> None:
    cmd = [
        "docker", "run", "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--read-only",
        "--memory", "512m",
        "--cpus", "1.0",
        "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
        "-v", f"{bundle_dir.resolve()}:/skill:ro",
        "-v", f"{evidence_dir.resolve()}:/evidence",
        "-e", f"CANARY_ID={canary_id}",
        "-e", f"CANARY_VAL={canary_val}",
        "-e", f"PHYLAX_NONCE={nonce}",
        "-e", f"AGENT_TIMEOUT={timeout_s}",
        image,
        "/skill", str(nonce),
    ]
    proc = subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, timeout=timeout_s + 30,
    )
    if proc.returncode not in (0, 124):
        raise RuntimeError(
            f"miner container exited {proc.returncode}: {proc.stderr[:200]}"
        )


def _parse_records(raw: bytes) -> list[dict]:
    import json
    out: list[dict] = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                out.append(obj)
        except (ValueError, TypeError):
            continue
    return out


