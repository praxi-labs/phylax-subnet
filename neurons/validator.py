from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import bittensor as bt

from phylax import rounds, screening
from phylax.analysis import common, quality, scoring, tracks
from phylax.analysis import proof as proofmod
from phylax.harness.corpus import fetch_corpus, load_corpus
from phylax.harness.detonate import detonate_artifact_bytes
from phylax.harness.runner import InfraFailure, run_task
from phylax.server_client import PhylaxServerClient, ServerRejected, ServerUnreachable
from phylax.utils.hashing import sssa_digest

POLL_INTERVAL_S: int = int(os.getenv("PHYLAX_POLL_INTERVAL", "30"))
MAX_AGENT_BYTES: int = 512 * 1024
DEADLINE_MARGIN_BLOCKS: int = 20
EMA_ALPHA: float = 0.3
TRACK_EVAL_ORDER: tuple[str, ...] = ("repositories", "packages", "mcp_servers", "skills")
AGENT_CONCURRENCY: int = max(1, int(os.getenv("PHYLAX_AGENT_CONCURRENCY", "2")))
REQUIRE_INFERENCE: bool = os.getenv("PHYLAX_REQUIRE_INFERENCE", "1") != "0"
SCORING_POLICY_VERSION: str = os.getenv("PHYLAX_SCORING_POLICY", "2026.07.31")
WEIGHT_REFRESH_S: int = 1200
WEIGHT_RETRY_S: int = 180
MIN_SCORED_FRACTION: float = 0.5

_VERDICT_ORDINAL = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
_ORDINAL_VERDICT = {v: k for k, v in _VERDICT_ORDINAL.items()}

log = logging.getLogger("phylax.validator")


class AbstainRound(Exception):
    pass


def _parse_contributors(raw: str) -> set[str]:
    text = raw.strip()
    if not text:
        return set()
    if text.startswith("["):
        try:
            return {str(h).strip() for h in json.loads(text) if str(h).strip()}
        except (ValueError, TypeError):
            return set()
    return {h.strip() for h in text.split(",") if h.strip()}


class PhylaxValidator:
    neuron_type: str = "ValidatorNeuron"

    def __init__(self, netuid: int, network: str, wallet: bt.Wallet, subtensor: bt.Subtensor):
        self.netuid = netuid
        self.network = network
        self.wallet = wallet
        self.subtensor = subtensor
        self.metagraph = self._fetch_metagraph()
        self.round_blocks = rounds.ROUND_BLOCKS
        self.corpora = {track: load_corpus(track) for track in rounds.TRACKS}
        self.last_round_start = -1
        self.should_exit = False
        self._round_running = False
        self._emissions_paused = False
        self._emissions_paused_reason = ""
        self.server = self._init_server()
        self._done_rounds: set[str] = set()
        self._retry_at: float = 0.0
        self._failed_tracks: set[str] = set()
        self._score_lock = threading.Lock()
        self._submit_lock = threading.Lock()
        self._failure_reasons: dict[str, str] = {}
        self._round_attestations: list[dict] = []
        self._round_scores: dict[str, dict[str, dict]] = {}
        self._round_seeds: dict[str, str] = {}
        self._round_tasks: dict[str, list[str]] = {}
        self._traces: dict[str, dict] = {}
        self._last_server_reject: str | None = None
        self._registered_with_server = False
        self._last_weight_set: float = 0.0
        self._rejections: dict[str, int] = {}
        self._track_attempted = 0
        self._track_scored = 0
        if os.getenv("PHYLAX_DEV_UNSAFE_EXECUTOR") == "1":
            log.warning(
                "PHYLAX_DEV_UNSAFE_EXECUTOR=1: agents run unjailed; never use outside development"
            )
        if any(self.corpora.get(t) for t in rounds.TRACKS):
            log.warning(
                "a local corpus is present; it is a development override and is never "
                "used when the backend serves the round task set"
            )

    def _fetch_metagraph(self):
        mg = self.subtensor.subnets.metagraph(self.netuid)
        if mg is None:
            raise RuntimeError(f"netuid {self.netuid} not found on {self.network}")
        return mg

    def _refresh_metagraph(self) -> None:
        try:
            self.metagraph = self._fetch_metagraph()
        except Exception as e:  # noqa: BLE001
            log.warning("metagraph refresh failed; using previous snapshot: %s", e)

    def _is_registered(self, hotkey: str) -> bool:
        """Whether the hotkey still holds a slot, assuming yes when unreadable.

        A miner can deregister after the participant set freezes. Reading the
        metagraph is best effort: an unreadable snapshot must not drop every
        agent from the round.
        """
        hotkeys = getattr(self.metagraph, "hotkeys", None)
        if hotkeys:
            return hotkey in set(hotkeys)
        try:
            return self.metagraph.by_hotkey(hotkey) is not None
        except Exception:  # noqa: BLE001
            return True

    def _init_server(self) -> PhylaxServerClient | None:
        url = os.getenv("PHYLAX_SERVER_URL", "").strip()
        if not url:
            return None
        expected = os.getenv("PHYLAX_SERVER_HOTKEY", "").strip() or None
        try:
            return PhylaxServerClient(
                base_url=url, wallet=self.wallet, expected_server_hotkey=expected
            )
        except Exception as e:  # noqa: BLE001
            log.warning("server client unavailable: %s", e)
            return None

    def _load_contributors(self) -> set[str]:
        raw = os.getenv("PHYLAX_CONTRIBUTORS", "").strip()
        if raw:
            return _parse_contributors(raw)
        authority = os.getenv("PHYLAX_CONTRIBUTOR_AUTHORITY", "").strip()
        if not authority:
            return set()
        try:
            neuron = self.metagraph.by_hotkey(authority)
            commitment = getattr(neuron, "commitment", None)
            if commitment is None:
                commitment = self.metagraph.unregistered_commitments.get(authority)
            value = getattr(commitment, "value", None)
            if value:
                return _parse_contributors(str(value))
        except Exception:  # noqa: BLE001, S110
            pass
        return set()

    def _state_dir(self) -> Path:
        path = Path(os.getenv("PHYLAX_STATE_DIR", "state"))
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _load_prior_weights(self) -> dict[str, float]:
        try:
            raw = json.loads((self._state_dir() / "weights_ema.json").read_text(encoding="utf-8"))
            return {str(k): float(v) for k, v in raw.items()}
        except (OSError, ValueError, AttributeError):
            return {}

    def _save_prior_weights(self, weights: dict[str, float]) -> None:
        try:
            (self._state_dir() / "weights_ema.json").write_text(
                json.dumps(weights, indent=2), encoding="utf-8"
            )
        except OSError as e:
            log.warning("could not persist EMA state: %s", e)

    def _load_prior_scores(self) -> dict[str, list[tuple[str, float]]]:
        try:
            raw = json.loads((self._state_dir() / "track_scores.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, AttributeError):
            return {}
        out: dict[str, list[tuple[str, float]]] = {}
        if not isinstance(raw, dict):
            return out
        for track, rows in raw.items():
            if not isinstance(rows, list):
                continue
            ranked = [
                (str(row[0]), float(row[1]))
                for row in rows
                if isinstance(row, list | tuple) and len(row) == 2
            ]
            if ranked:
                out[str(track)] = ranked
        return out

    def _save_prior_scores(self, scores: dict) -> None:
        try:
            (self._state_dir() / "track_scores.json").write_text(
                json.dumps({t: [[hk, s] for hk, s in rows] for t, rows in scores.items()}, indent=2),
                encoding="utf-8",
            )
        except OSError as e:
            log.warning("could not persist track scores: %s", e)

    def _all_track_scores(self, fresh: dict, from_server: dict | None = None) -> dict:
        """This pass's scores, over the last known scores for every other track.

        A pass covers only the tracks with an open round, so a track evaluated
        earlier is absent here. Absent must not read as "no winners": weights
        are rebuilt from scratch every pass, and a track missing from the input
        loses its emission share entirely and drops its miners to zero. The
        backend keeps each track's last closed round, so tracks that did not
        run this pass carry their standing forward and hold their share.
        """
        carried = self._load_prior_scores()
        if from_server:
            carried.update(from_server)
        merged = {**carried, **fresh}
        skipped = sorted(set(merged) - set(fresh))
        if skipped:
            log.info("carrying %s forward; not evaluated this pass", ", ".join(skipped))
        self._save_prior_scores(merged)
        return merged

    def _fetch_agents(self, track: str, participants: list[dict] | None = None) -> dict[str, dict]:
        if not participants or self.server is None:
            log.info("no frozen participants for track=%s; nothing to evaluate", track)
            return {}

        agents: dict[str, dict] = {}
        codes: dict[str, tuple[str, int]] = {}
        for idx, part in enumerate(participants):
            hotkey = str(part.get("hotkey", "") or "")
            expected = str(part.get("agent_hash", "") or "")
            if not hotkey:
                continue
            if not self._is_registered(hotkey):
                log.info(
                    "skipping agent=%s: hotkey deregistered from netuid %d",
                    hotkey[:10], self.netuid,
                )
                continue
            try:
                data = self.server.get_runnable_agent(hotkey)
            except (ServerUnreachable, ServerRejected) as e:
                raise AbstainRound(f"backend unavailable fetching {hotkey[:10]}: {e}") from e
            code = str((data or {}).get("code") or "")
            if not code:
                continue
            actual = "sha256:" + hashlib.sha256(code.encode("utf-8")).hexdigest()
            if expected and actual != expected:
                log.warning(
                    "agent %s hash mismatch (frozen %s…); skipping", hotkey[:10], expected[:18]
                )
                continue
            reason = self._screen_runnable(track, data, code)
            if reason:
                log.info("screened out agent=%s: %s", hotkey[:10], reason)
                continue
            agents[hotkey] = {
                "code": code,
                "entrypoint": data.get("entrypoint") or "agent_main",
                "execution_api_key": data.get("execution_api_key") or "",
                "inference_provider": data.get("inference_provider")
                or _provider(data.get("execution_api_key") or ""),
                "inference_model": data.get("inference_model") or "",
                "agent_hash": expected or actual,
            }
            codes[hotkey] = (code, idx)

        for hotkey in screening.duplicate_hotkeys(codes):
            log.warning("screened out agent=%s: copied agent code", hotkey[:10])
            agents.pop(hotkey, None)
        return agents

    def _screen_runnable(self, track: str, data: dict, code: str) -> str:
        if str(data.get("track", track)) != track:
            return "wrong track"
        if len(code.encode("utf-8")) > MAX_AGENT_BYTES:
            return "agent exceeds size limit"
        entrypoint = str(data.get("entrypoint") or "agent_main")
        if f"def {entrypoint}" not in code:
            return "missing entrypoint"
        abuse = screening.abuse_reason(code)
        if abuse:
            return f"abuse pattern: {abuse}"
        return ""

    def _corpus_for(self, track: str, round_id: str) -> list[dict]:
        if self.server is not None and round_id:
            try:
                items = fetch_corpus(self.server, round_id, track)
            except ServerUnreachable as e:
                raise AbstainRound(f"task set unreachable for track {track}: {e}") from e
            except ServerRejected as e:
                raise AbstainRound(
                    f"backend declined the {track} task set (HTTP {e.status_code}: {e.detail})"
                ) from e
            return items
        return self.corpora.get(track) or []

    def run_round(
        self,
        start_block: int,
        seeds: dict[str, str] | None = None,
        participants: dict[str, list[dict]] | None = None,
        round_ids: dict[str, str] | None = None,
    ) -> dict[str, list[tuple[str, float]]]:
        self._round_attestations = []
        self._round_scores = {}
        self._round_seeds = {}
        self._round_tasks = {}
        end_block = start_block + self.round_blocks
        info = self.subtensor.block_info(start_block)
        if info is None:
            raise AbstainRound(f"block info unavailable for block {start_block}")
        block_hash = str(info.hash)
        scores_by_track: dict[str, list[tuple[str, float]]] = {}
        self._failed_tracks = set()
        for track in TRACK_EVAL_ORDER:
            try:
                track_scores = self._run_track(
                    track, round_ids or {}, seeds or {}, participants or {},
                    block_hash, start_block, end_block,
                )
            except (AbstainRound, InfraFailure) as e:
                log.warning("track %s failed this pass; retrying later: %s", track, e)
                self._failed_tracks.add(track)
                continue
            if track_scores is None:
                continue
            scores_by_track[track] = track_scores
        if not scores_by_track:
            if self._failed_tracks:
                raise AbstainRound(
                    "every attempted track failed: " + ", ".join(sorted(self._failed_tracks))
                )
            raise AbstainRound("no track had a task set this round")
        self._write_round_record(start_block, scores_by_track)
        return scores_by_track

    def _run_track(
        self,
        track: str,
        round_ids: dict[str, str],
        seeds: dict[str, str],
        participants: dict[str, list[dict]],
        block_hash: str,
        start_block: int,
        end_block: int,
    ) -> list[tuple[str, float]] | None:
        corpus = self._corpus_for(track, str(round_ids.get(track) or ""))
        if not corpus:
            log.info("track %s has no task set this round; skipping it", track)
            return None
        seed = seeds.get(track) or rounds.round_seed(block_hash, track)
        budgets = rounds.budgets_for(track)
        task_set = rounds.select_tasks(corpus, seed, budgets["tasks"])
        self._detonate_task_set(track, task_set, budgets)
        agents = self._fetch_agents(track, participants.get(track))
        self._round_seeds[track] = seed
        self._round_tasks[track] = [item["ref"] for item in task_set]
        log.info(
            "round start=%d end=%d track=%s tasks=%d agents=%d",
            start_block, end_block, track, len(task_set), len(agents),
        )
        track_scores: list[tuple[str, float]] = []
        round_id = str(round_ids.get(track) or "")
        resumed = self._prior_round_results(round_id, agents)
        for done_hotkey, detail in resumed.items():
            track_scores.append((done_hotkey, float(detail["score"])))
            self._round_scores.setdefault(track, {})[done_hotkey] = detail
        if resumed:
            log.info(
                "resuming %s round %s: %d agents already scored",
                track, round_id[:8], len(resumed),
            )
        self._track_attempted = 0
        self._track_scored = 0
        pending = [(hk, run) for hk, run in agents.items() if hk not in resumed]
        done = len(resumed)

        def evaluate(entry: tuple[str, dict]) -> tuple[str, dict, float]:
            hotkey, runnable = entry
            score = self._score_agent(track, hotkey, runnable, task_set, seed, budgets)
            return hotkey, runnable, score

        workers = max(1, min(AGENT_CONCURRENCY, len(pending))) if pending else 1
        if pending:
            log.info(
                "evaluating %d %s agents, %d at a time", len(pending), track, workers
            )
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(evaluate, entry): entry[0] for entry in pending}
            for future in as_completed(futures):
                if self.server is None and self._out_of_window(end_block):
                    for pendingfuture in futures:
                        pendingfuture.cancel()
                    self._report_progress(
                        round_id, track, "abstained", done, len(agents), "",
                        len(task_set), "window closing",
                    )
                    raise AbstainRound(
                        f"window closing at block {end_block} with track {track} incomplete"
                    )
                try:
                    hotkey, runnable, score = future.result()
                except (AbstainRound, InfraFailure):
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning("agent %s failed to score: %s", futures[future][:10], exc)
                    continue
                done += 1
                with self._score_lock:
                    track_scores.append((hotkey, score))
                    self._round_scores.setdefault(track, {})[hotkey] = {
                        "agent_hash": runnable["agent_hash"],
                        "score": round(score, 6),
                    }
                log.info("round score track=%s agent=%s S=%.3f", track, hotkey[:10], score)
                self._report_progress(
                    round_id, track, "evaluating", done, len(agents), hotkey,
                    len(task_set), "",
                )
                self._submit_track_results(round_ids, start_block, track)
        if self._track_attempted and (
            self._track_scored / self._track_attempted < MIN_SCORED_FRACTION
        ):
            self._report_progress(
                round_id, track, "abstained", len(agents), len(agents), "",
                len(task_set), "too few verdicts",
            )
            raise AbstainRound(
                f"only {self._track_scored}/{self._track_attempted} {track} tasks produced "
                "a verdict; this validator cannot evaluate reliably"
            )
        self._report_progress(
            round_id, track, "scored", len(agents), len(agents), "",
            len(task_set), "",
        )
        return track_scores

    def _prior_round_results(self, round_id: str, agents: dict) -> dict[str, dict]:
        if self.server is None or not round_id:
            return {}
        try:
            payload = self.server.get_round_results(round_id) or {}
        except Exception as e:  # noqa: BLE001
            log.debug("no prior results to resume from: %s", e)
            return {}
        out: dict[str, dict] = {}
        for row in payload.get("results") or []:
            hotkey = str(row.get("miner_hotkey") or "")
            if hotkey and hotkey in agents:
                out[hotkey] = {
                    "agent_hash": str(row.get("agent_hash") or ""),
                    "score": float(row.get("score") or 0.0),
                }
        return out

    def _scores_from_server(self) -> dict[str, list[tuple[str, float]]] | None:
        if self.server is None:
            return None
        try:
            payload = self.server.get_my_results() or {}
        except Exception as e:  # noqa: BLE001
            log.debug("could not read back previous results: %s", e)
            return None
        self._emissions_paused = bool(payload.get("emissions_paused"))
        self._emissions_paused_reason = str(payload.get("emissions_paused_reason") or "")
        out: dict[str, list[tuple[str, float]]] = {}
        for track, rows in (payload.get("tracks") or {}).items():
            ranked = [
                (str(r.get("miner_hotkey") or ""), float(r.get("score") or 0.0))
                for r in rows
                if isinstance(r, dict) and r.get("miner_hotkey")
            ]
            if ranked:
                out[track] = ranked
        return out

    def _report_progress(self, round_id: str, track: str, phase: str, done: int,
                         total: int, current: str, tasks: int, note: str) -> None:
        if self.server is None or not round_id:
            return
        try:
            self.server.submit_round_progress(
                round_id=round_id, track=track, phase=phase,
                agents_done=done, agents_total=total, current_agent=current,
                tasks_total=tasks, note=note,
            )
        except Exception as e:  # noqa: BLE001
            log.debug("progress heartbeat failed: %s", e)

    def _detonate_task_set(self, track: str, task_set: list[dict], budgets: dict) -> None:
        if track == "repositories":
            return
        started = time.monotonic()
        detonated = 0
        for item in task_set:
            ref = item["ref"]
            if ref in self._traces:
                item["observed"] = self._traces[ref]
                continue
            trace = detonate_artifact_bytes(
                track, item.get("artifact_b64", ""), timeout_s=budgets["cpu_s"]
            )
            self._traces[ref] = trace
            item["observed"] = trace
            detonated += 1
        log.info(
            "detonated %d/%d %s artifacts in %.1fs",
            detonated, len(task_set), track, time.monotonic() - started,
        )

    def _out_of_window(self, end_block: int) -> bool:
        try:
            block = self.subtensor.block
        except Exception:  # noqa: BLE001
            return False
        return block >= end_block - DEADLINE_MARGIN_BLOCKS

    def _write_round_record(
        self, start_block: int, scores_by_track: dict[str, list[tuple[str, float]]]
    ) -> None:
        try:
            record = {
                "start_block": start_block,
                "tracks": {
                    track: {
                        "seed": self._round_seeds.get(track, ""),
                        "tasks": self._round_tasks.get(track, []),
                        "agents": self._round_scores.get(track, {}),
                    }
                    for track in rounds.TRACKS
                },
            }
            path = self._state_dir() / f"round_{start_block}.json"
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        except OSError as e:
            log.warning("could not write round record: %s", e)

    def _score_agent(
        self,
        track: str,
        hotkey: str,
        runnable: dict,
        task_set: list[dict],
        seed: str,
        budgets: dict[str, int],
    ) -> float:
        if not task_set:
            return 0.0
        wall_cap = rounds.agent_wall_cap_s(track)
        wall_used = 0.0
        if track == "repositories":
            total = 0.0
            for item in task_set:
                score, wall_used = self._score_repo_task(
                    hotkey, runnable, item, seed, budgets, wall_used, wall_cap
                )
                total += score
            return total / len(task_set)
        tp = tn = fp = fn = 0
        attempted = 0
        quality_scores: list[float] = []
        for item in task_set:
            target = common.label_risk(item["label"])
            if target is None:
                continue
            attempted += 1
            verdict, wall_used, findings = self._task_verdict(
                track, hotkey, runnable, item, seed, budgets, wall_used, wall_cap
            )
            if verdict is None:
                continue
            malicious = target >= 0.5
            flagged = verdict in ("BLOCK", "WARN")
            if malicious and flagged:
                tp += 1
            elif malicious:
                fn += 1
            elif verdict == "ALLOW":
                tn += 1
            else:
                fp += 1
            expected = item.get("expected_findings") or []
            if expected:
                trace = self._traces.get(item["ref"]) or {}
                quality_scores.append(
                    quality.finding_quality(
                        expected, findings, trace.get("capabilities")
                    )
                )
        scored = tp + tn + fp + fn
        with self._score_lock:
            self._track_attempted += attempted
            self._track_scored += scored
        if scored == 0:
            log.warning(
                "agent %s produced no verdict on any of %d %s tasks; scoring 0",
                hotkey[:10], attempted, track,
            )
            return 0.0
        if scored < attempted:
            log.info(
                "agent %s produced verdicts on %d/%d %s tasks",
                hotkey[:10], scored, attempted, track,
            )
        correctness = scoring.clamped_mcc(tp, tn, fp, fn)
        if not quality_scores:
            return correctness
        q = sum(quality_scores) / len(quality_scores)
        return scoring.clip01(
            scoring.RUN_W_CORRECTNESS * correctness + scoring.RUN_W_QUALITY * q
        )

    def _proxy_admin(self, path: str, payload: dict | None = None) -> dict:
        base = (
            os.getenv("PHYLAX_PROXY_ADMIN_URL", "")
            or os.getenv("PHYLAX_INFERENCE_PROXY_URL", "")
        ).rstrip("/")
        token = os.getenv("PHYLAX_PROXY_ADMIN_TOKEN", "")
        if not base or not token:
            return {}
        import urllib.request

        data = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(  # noqa: S310
            f"{base}{path}",
            data=data,
            method="POST" if data is not None else "GET",
            headers={"Content-Type": "application/json", "X-Phylax-Admin": token},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8", "replace")) or {}
        except Exception:  # noqa: BLE001
            return {}

    def _open_inference_session(self, nonce: str, runnable: dict) -> None:
        key = str(runnable.get("execution_api_key") or "")
        if not key:
            return
        self._proxy_admin(
            "/session",
            {
                "nonce": nonce,
                "api_key": key,
                "provider": str(runnable.get("inference_provider") or ""),
            },
        )

    def _inference_calls(self, nonce: str) -> int:
        """Calls recorded for this task, or -1 when the meter cannot be read.

        Returning -1 rather than 0 matters: without a proxy admin token the
        validator cannot see usage at all, and treating that as zero would
        refuse every agent instead of every agent that skipped inference.
        """
        if not os.getenv("PHYLAX_PROXY_ADMIN_TOKEN", ""):
            return -1
        metrics = self._proxy_admin(f"/metrics?nonce={nonce}")
        if not metrics:
            return -1
        row = metrics.get(nonce) if isinstance(metrics.get(nonce), dict) else metrics
        try:
            return int((row or {}).get("requests", 0) or 0)
        except (TypeError, ValueError):
            return -1

    def _task_verdict(
        self,
        track: str,
        hotkey: str,
        runnable: dict,
        item: dict,
        seed: str,
        budgets: dict[str, int],
        wall_used: float,
        wall_cap: float,
    ) -> tuple[str | None, float, list]:
        nonce = rounds.task_nonce(seed, item["ref"], hotkey)
        probe = proofmod.derive_probe(nonce)
        self._open_inference_session(nonce, runnable)
        ordinals: list[int] = []
        last_result = None
        for _ in range(budgets["repetitions"]):
            remaining = wall_cap - wall_used
            if remaining <= 0:
                break
            started = time.monotonic()
            ordinal, result = self._run_rep(
                track, runnable, item, nonce, probe, budgets["cpu_s"], remaining
            )
            wall_used += time.monotonic() - started
            if ordinal is None:
                continue
            ordinals.append(ordinal)
            last_result = result
        if not ordinals:
            return None, wall_used, []
        if REQUIRE_INFERENCE and self._inference_calls(nonce) == 0:  # -1 means unreadable
            self._note_rejection("no inference call")
            self._failure_reasons[hotkey] = "no_inference"
            return None, wall_used, []
        ordinals.sort()
        decision = _ORDINAL_VERDICT[ordinals[(len(ordinals) - 1) // 2]]
        findings = []
        if last_result is not None:
            findings = last_result.get("findings") or []
            self._attest(track, hotkey, runnable, item, nonce, last_result)
        return decision, wall_used, findings

    def _note_rejection(self, reason: str) -> None:
        self._rejections[reason] = self._rejections.get(reason, 0) + 1
        if self._rejections[reason] in (1, 10, 100) or self._rejections[reason] % 500 == 0:
            log.warning(
                "repetition rejected (%dx): %s", self._rejections[reason], reason
            )

    def _run_rep(
        self, track: str, runnable: dict, item: dict, nonce: str, probe, cpu_s: int,
        wall_budget_s: float | None = None,
    ) -> tuple[int | None, dict | None]:
        dispatch = {
            "track": track,
            "nonce": nonce,
            "probe": probe.as_inputs(),
            "artifact_ref": item["ref"],
            "artifact_b64": item["artifact_b64"],
            "observed": self._traces.get(item["ref"]),
        }
        result = run_task(
            dispatch, runnable, log=log.warning, cpu_budget_s=cpu_s,
            wall_budget_s=wall_budget_s,
        )
        if result is None:
            self._note_rejection("run produced no result")
            return None, None
        if result.get("observed_probe_file") is not True:
            self._note_rejection(
                f"probe file not observed (error={str(result.get('error', ''))[:120]})"
            )
            return None, result
        poe = proofmod.verify_validator_trace(result.get("validator_trace"), probe)
        if not poe.passed:
            self._note_rejection(f"trace verification failed: {poe.reason}")
            return None, result
        verdict = result["verdict"] if isinstance(result["verdict"], dict) else {}
        decision = str(verdict.get("decision", "")).upper()
        if decision not in _VERDICT_ORDINAL:
            return None, result
        ev = tracks.evaluate(track, result["evidence"], decision, label=item["label"], probe=probe)
        if not ev.result.gate_passed:
            return None, result
        return _VERDICT_ORDINAL[decision], result

    def _score_repo_task(
        self,
        hotkey: str,
        runnable: dict,
        item: dict,
        seed: str,
        budgets: dict[str, int],
        wall_used: float,
        wall_cap: float,
    ) -> tuple[float, float]:
        nonce = rounds.task_nonce(seed, item["ref"], hotkey)
        probe = proofmod.derive_probe(nonce)
        rep_scores: list[float] = []
        last_result = None
        dispatch = {
            "track": "repositories",
            "nonce": nonce,
            "probe": probe.as_inputs(),
            "artifact_ref": item["ref"],
            "artifact_b64": item["artifact_b64"],
        }
        for _ in range(budgets["repetitions"]):
            remaining = wall_cap - wall_used
            if remaining <= 0:
                break
            started = time.monotonic()
            result = run_task(
                dispatch, runnable, log=log.warning, cpu_budget_s=budgets["cpu_s"],
                wall_budget_s=remaining,
            )
            wall_used += time.monotonic() - started
            if result is None:
                continue
            verdict = result["verdict"] if isinstance(result["verdict"], dict) else {}
            decision = str(verdict.get("decision", ""))
            ev = tracks.evaluate(
                "repositories",
                result["evidence"],
                decision,
                label=item["label"],
                probe=probe,
                ground_truth=item.get("ground_truth"),
            )
            if not ev.result.gate_passed:
                continue
            rep_scores.append(scoring.clip01(ev.result.score))
            last_result = result
        if not rep_scores:
            return 0.0, wall_used
        if last_result is not None:
            self._attest("repositories", hotkey, runnable, item, nonce, last_result)
        return sum(rep_scores) / len(rep_scores), wall_used

    def _attest(
        self, track: str, hotkey: str, runnable: dict, item: dict, nonce: str, result: dict
    ) -> None:
        verdict = result["verdict"]
        evidence = dict(result["evidence"] or {})
        trace = self._traces.get(item["ref"])
        if trace is not None:
            evidence["validator_observed"] = {
                "capabilities": trace.get("capabilities", []),
                "detonated": bool(trace.get("detonated")),
                "tool_surface": trace.get("tool_surface", []),
            }
        findings = result.get("findings") or []
        policy = result.get("policy") or {}
        digest = sssa_digest(track, item["ref"], nonce, verdict, evidence, findings, policy)
        signature = "ed25519:" + bytes(self.wallet.hotkey.sign(digest)).hex()
        sssa = {
            "track": track,
            "artifact": {"bundle_hash": item["ref"], "nonce": nonce},
            "verdict": verdict,
            "evidence": evidence,
            "findings": findings,
            "policy": policy,
            "attestation": {
                "agent_hash": runnable["agent_hash"],
                "miner_hotkey": hotkey,
                "validator_hotkey": self.wallet.hotkey.ss58_address,
                "signature": signature,
                "canonical_hash": "sha256:" + digest.hex(),
            },
        }
        self.last_sssa = sssa
        with self._score_lock:
            self._round_attestations.append(sssa)
        log.debug("attested agent=%s artifact=%s hash=%s", hotkey[:10], item["ref"], digest.hex()[:16])

    def set_weights(
        self, scores_by_track: dict[str, list[tuple[str, float]]] | None
    ) -> None:
        carried = self._scores_from_server()
        if self._emissions_paused or self._round_running:
            reserved = scoring.reserved_only_weights()
            if not reserved:
                log.warning("no reserved hotkey set; leaving weights alone")
                self._last_weight_set = time.monotonic()
                return
            if self._emissions_paused:
                log.info(
                    "miner emissions paused by the operator%s; voting the reserved hotkey",
                    f": {self._emissions_paused_reason}" if self._emissions_paused_reason else "",
                )
            else:
                log.info("round in flight; voting the reserved hotkey until results land")
            self._last_weight_set = time.monotonic()
            self._push_weights(reserved)
            return

        prior = self._load_prior_weights()
        if scores_by_track is None:
            if not prior:
                log.warning(
                    "no scores and no prior weights; leaving the previous on chain "
                    "vector alone rather than voting the reserved share alone"
                )
                self._last_weight_set = time.monotonic()
                return
            blended = dict(prior)
        else:
            weight_map = scoring.compute_emission_weights(
                self._all_track_scores(scores_by_track, carried),
                contributor_hotkeys=self._load_contributors(),
                thresholds=scoring.TRACK_THRESHOLDS,
            )
            blended = {
                hk: EMA_ALPHA * w + (1.0 - EMA_ALPHA) * prior.get(hk, 0.0)
                for hk, w in weight_map.items()
            }
            blended = {hk: w for hk, w in blended.items() if w > 1e-9}
            competitive = sum(blended.values())
            if competitive > 0.0:
                blended = {hk: w / competitive for hk, w in blended.items()}
            self._save_prior_weights(blended)

        blended = scoring.apply_reserved_share(blended)
        self._last_weight_set = time.monotonic()
        self._push_weights(blended)

    def _push_weights(self, blended: dict[str, float]) -> None:
        if not blended:
            log.info("set_weights: no agent cleared the quality threshold; skipping")
            return

        uid_by_hotkey = {n.hotkey: n.uid for n in self.metagraph.neurons}
        if scoring.RESERVED_HOTKEY and scoring.RESERVED_HOTKEY not in uid_by_hotkey:
            log.warning(
                "reserved hotkey %s is not registered on netuid %d; its %.0f%% share "
                "will be dropped and redistributed to the remaining miners",
                scoring.RESERVED_HOTKEY[:12], self.netuid, scoring.RESERVED_SHARE * 100,
            )
        uid_weights: dict[int, float] = {}
        for hotkey, w in blended.items():
            uid = uid_by_hotkey.get(hotkey)
            if uid is not None:
                uid_weights[uid] = uid_weights.get(uid, 0.0) + float(w)
        if not uid_weights:
            log.warning("set_weights: no miner hotkeys matched metagraph; skipping")
            return

        try:
            bt.set_weights(
                self.netuid, uid_weights, wallet=self.wallet, network=self.network
            )
        except Exception as e:  # noqa: BLE001
            log.warning("set_weights failed: %s", e)
            self._last_weight_set = time.monotonic() - WEIGHT_REFRESH_S + WEIGHT_RETRY_S
            return
        log.info("weights set | matched %d agents", len(uid_weights))

    def _submit_results(self, round_ids: dict[str, str], start_block: int) -> None:
        for track in list(self._round_scores):
            self._submit_track_results(round_ids, start_block, track)

    def _submit_track_results(
        self, round_ids: dict[str, str], start_block: int, track: str
    ) -> None:
        if self.server is None:
            return
        with self._submit_lock:
            self._submit_track_results_locked(round_ids, start_block, track)

    def _submit_track_results_locked(
        self, round_ids: dict[str, str], start_block: int, track: str
    ) -> None:
        with self._score_lock:
            per_agent = dict(self._round_scores.get(track) or {})
            attestations = [
                a for a in self._round_attestations if a.get("track") == track
            ]
        if per_agent:
            results = [
                {
                    "miner_hotkey": hk,
                    **detail,
                    "policy_version": SCORING_POLICY_VERSION,
                    **(
                        {"failure_reason": self._failure_reasons[hk]}
                        if hk in self._failure_reasons
                        else {}
                    ),
                }
                for hk, detail in per_agent.items()
            ]
            try:
                self.server.submit_round_results(
                    round_id=round_ids.get(track, f"block-{start_block}"),
                    track=track,
                    validator_hotkey=self.wallet.hotkey.ss58_address,
                    start_block=start_block,
                    seed=self._round_seeds.get(track, ""),
                    results=results,
                    attestations=attestations,
                )
                log.debug(
                    "submitted %s results: %d agents, %d attestations",
                    track, len(results), len(attestations),
                )
            except ServerUnreachable as e:
                log.warning("could not submit %s results: %s", track, e)
            except Exception as e:  # noqa: BLE001
                log.warning("%s result submission failed: %s", track, e)

    def _execute_round(
        self,
        round_ids: dict[str, str],
        start_block: int,
        seeds: dict[str, str] | None = None,
        participants: dict[str, list[dict]] | None = None,
    ) -> bool:
        self._refresh_metagraph()
        self._round_running = True
        self.set_weights(None)
        try:
            scores_by_track = self.run_round(
                start_block, seeds=seeds, participants=participants, round_ids=round_ids
            )
        except (AbstainRound, InfraFailure) as e:
            log.warning("abstaining this round: %s", e)
            self._round_running = False
            self.set_weights(None)
            return False
        finally:
            self._round_running = False
        self._submit_results(round_ids, start_block)
        self.set_weights(scores_by_track)
        return True

    def _register_with_server(self) -> None:
        if self.server is None:
            return
        try:
            self.server.register_validator(os.getenv("PHYLAX_VALIDATOR_LABEL", ""))
        except (ServerUnreachable, ServerRejected) as e:
            log.debug("validator self registration deferred: %s", e)
            return
        if not self._registered_with_server:
            log.info("registered with the backend as a validator")
            self._registered_with_server = True

    def _warn_once(self, message: str) -> None:
        if message != self._last_server_reject:
            log.warning("%s", message)
            self._last_server_reject = message
        else:
            log.debug("%s", message)

    def _begin_round(self, start_block: int) -> bool:
        if time.monotonic() < self._retry_at:
            return False
        round_ids: dict[str, str] = {}
        seeds: dict[str, str] = {}
        participants: dict[str, list[dict]] = {}
        if not self._registered_with_server:
            self._register_with_server()
        if self.server is not None:
            for track in rounds.TRACKS:
                try:
                    spec = self.server.next_round(track, self.wallet.hotkey.ss58_address)
                except ServerUnreachable as e:
                    self._warn_once(f"server unreachable ({e}); retrying next poll")
                    return False
                except ServerRejected as e:
                    if e.status_code in (401, 403):
                        self._warn_once(
                            f"server declined the round poll (HTTP {e.status_code}: {e.detail}). "
                            "Expected until this hotkey holds a validator permit "
                            "(stake, then wait an epoch) and its IP is allowlisted; retrying"
                        )
                    else:
                        self._warn_once(
                            f"server rejected the round poll (HTTP {e.status_code}: {e.detail}); retrying"
                        )
                    return False
                if not spec:
                    continue
                if spec.get("phase") == "submission":
                    log.info(
                        "track %s submission window open until %s; waiting",
                        track, spec.get("submission_closes_at", "?"),
                    )
                    return False
                round_id = str(spec.get("round_id") or f"block-{start_block}")
                if round_id in self._done_rounds:
                    continue
                round_ids[track] = round_id
                seed = str(spec.get("seed") or "")
                if seed:
                    seeds[track] = seed
                participants[track] = spec.get("participants") or []
        if self.server is not None and not round_ids:
            log.debug("no unevaluated open round on any track; polling")
            return False
        self._last_server_reject = None
        self._register_with_server()
        if not self._execute_round(
            round_ids, start_block, seeds=seeds or None, participants=participants or None
        ):
            self._retry_at = time.monotonic() + 300.0
            return False
        self._done_rounds.update(
            rid for trk, rid in round_ids.items() if trk not in self._failed_tracks
        )
        if self._failed_tracks:
            self._retry_at = time.monotonic() + 300.0
        return True

    def run(self) -> None:
        log.info(
            "starting Phylax validator on netuid=%d hotkey=%s tracks=%s round_blocks=%d",
            self.netuid, self.wallet.hotkey.ss58_address,
            ",".join(rounds.TRACKS), self.round_blocks,
        )
        self._register_with_server()
        self.set_weights(self._scores_from_server())
        while not self.should_exit:
            try:
                block = self.subtensor.block
                start = rounds.round_start(block, self.round_blocks)
                if self.server is not None:
                    if self._begin_round(start):
                        self.last_round_start = start
                elif start > self.last_round_start and self._begin_round(start):
                    self.last_round_start = start
                if time.monotonic() - self._last_weight_set >= WEIGHT_REFRESH_S:
                    self.set_weights(self._scores_from_server())
                time.sleep(POLL_INTERVAL_S)
            except KeyboardInterrupt:
                log.info("validator stopped by KeyboardInterrupt")
                break
            except Exception as e:  # noqa: BLE001
                log.error("run loop error: %s", e)
                log.debug(traceback.format_exc())
                time.sleep(POLL_INTERVAL_S)


def _provider(api_key: str) -> str:
    if api_key.startswith("cpk_"):
        return "chutes"
    if api_key.startswith("sk-or-"):
        return "openrouter"
    return ""


def _setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else os.getenv("PHYLAX_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if os.getenv("PHYLAX_LOG_TRANSPORT") != "1":
        for noisy in ("httpx", "httpcore", "websockets", "bittensor"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def main() -> None:
    parser = argparse.ArgumentParser(description="Phylax validator neuron")
    parser.add_argument("--netuid", type=int, default=int(os.getenv("PHYLAX_NETUID", "76")))
    parser.add_argument(
        "--subtensor.network", dest="network",
        default=os.getenv("SUBTENSOR_NETWORK", "finney"),
    )
    parser.add_argument(
        "--wallet.name", dest="wallet_name", default=os.getenv("WALLET_NAME", "validator")
    )
    parser.add_argument(
        "--wallet.hotkey", dest="wallet_hotkey", default=os.getenv("WALLET_HOTKEY", "default")
    )
    parser.add_argument("--logging.debug", dest="debug", action="store_true")
    args, extra = parser.parse_known_args()
    _setup_logging(args.debug)
    if extra:
        log.warning("ignoring unrecognised arguments: %s", " ".join(extra))
    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)
    subtensor = bt.Subtensor(args.network)
    validator = PhylaxValidator(
        netuid=args.netuid, network=args.network, wallet=wallet, subtensor=subtensor
    )
    validator.run()


if __name__ == "__main__":
    main()
