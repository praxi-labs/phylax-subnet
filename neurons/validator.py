from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
import traceback
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
        self.server = self._init_server()
        self._round_attestations: list[dict] = []
        self._round_scores: dict[str, dict[str, dict]] = {}
        self._round_seeds: dict[str, str] = {}
        self._round_tasks: dict[str, list[str]] = {}
        self._traces: dict[str, dict] = {}
        self._last_server_reject: str | None = None
        self._registered_with_server = False
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
        for track in rounds.TRACKS:
            corpus = self._corpus_for(track, str((round_ids or {}).get(track) or ""))
            if not corpus:
                log.info("track %s has no task set this round; skipping it", track)
                continue
            seed = (seeds or {}).get(track) or rounds.round_seed(block_hash, track)
            budgets = rounds.budgets_for(track)
            task_set = rounds.select_tasks(corpus, seed, budgets["tasks"])
            self._detonate_task_set(track, task_set, budgets)
            agents = self._fetch_agents(track, (participants or {}).get(track))
            self._round_seeds[track] = seed
            self._round_tasks[track] = [item["ref"] for item in task_set]
            log.info(
                "round start=%d end=%d track=%s tasks=%d agents=%d",
                start_block, end_block, track, len(task_set), len(agents),
            )
            track_scores: list[tuple[str, float]] = []
            round_id = str((round_ids or {}).get(track) or "")
            for index, (hotkey, runnable) in enumerate(agents.items()):
                if self._out_of_window(end_block):
                    self._report_progress(
                        round_id, track, "abstained", index, len(agents), "",
                        len(task_set), "window closing",
                    )
                    raise AbstainRound(
                        f"window closing at block {end_block} with track {track} incomplete"
                    )
                self._report_progress(
                    round_id, track, "evaluating", index, len(agents), hotkey,
                    len(task_set), "",
                )
                score = self._score_agent(track, hotkey, runnable, task_set, seed, budgets)
                track_scores.append((hotkey, score))
                self._round_scores.setdefault(track, {})[hotkey] = {
                    "agent_hash": runnable["agent_hash"],
                    "score": round(score, 6),
                }
                log.info("round score track=%s agent=%s S=%.3f", track, hotkey[:10], score)
            self._report_progress(
                round_id, track, "scored", len(agents), len(agents), "",
                len(task_set), "",
            )
            scores_by_track[track] = track_scores
        if not scores_by_track:
            raise AbstainRound("no track had a task set this round")
        self._write_round_record(start_block, scores_by_track)
        return scores_by_track

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
        quality_scores: list[float] = []
        for item in task_set:
            target = common.label_risk(item["label"])
            if target is None:
                continue
            verdict, wall_used, findings = self._task_verdict(
                track, hotkey, runnable, item, seed, budgets, wall_used, wall_cap
            )
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
        if tp + tn + fp + fn == 0:
            return 0.0
        correctness = scoring.clamped_mcc(tp, tn, fp, fn)
        if not quality_scores:
            return correctness
        q = sum(quality_scores) / len(quality_scores)
        return scoring.clip01(
            scoring.RUN_W_CORRECTNESS * correctness + scoring.RUN_W_QUALITY * q
        )

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
        ordinals: list[int] = []
        last_result = None
        for _ in range(budgets["repetitions"]):
            if wall_used >= wall_cap:
                break
            started = time.monotonic()
            ordinal, result = self._run_rep(track, runnable, item, nonce, probe, budgets["cpu_s"])
            wall_used += time.monotonic() - started
            if ordinal is None:
                continue
            ordinals.append(ordinal)
            last_result = result
        if not ordinals:
            return None, wall_used, []
        ordinals.sort()
        decision = _ORDINAL_VERDICT[ordinals[(len(ordinals) - 1) // 2]]
        findings = []
        if last_result is not None:
            findings = last_result.get("findings") or []
            self._attest(track, hotkey, runnable, item, nonce, last_result)
        return decision, wall_used, findings

    def _run_rep(
        self, track: str, runnable: dict, item: dict, nonce: str, probe, cpu_s: int
    ) -> tuple[int | None, dict | None]:
        dispatch = {
            "track": track,
            "nonce": nonce,
            "probe": probe.as_inputs(),
            "artifact_ref": item["ref"],
            "artifact_b64": item["artifact_b64"],
            "observed": self._traces.get(item["ref"]),
        }
        result = run_task(dispatch, runnable, log=log.warning, cpu_budget_s=cpu_s)
        if result is None:
            return None, None
        if result.get("observed_probe_file") is not True:
            return None, result
        poe = proofmod.verify_validator_trace(result.get("validator_trace"), probe)
        if not poe.passed:
            log.debug("rep rejected: %s", poe.reason)
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
            if wall_used >= wall_cap:
                break
            started = time.monotonic()
            result = run_task(dispatch, runnable, log=log.warning, cpu_budget_s=budgets["cpu_s"])
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
        self._round_attestations.append(sssa)
        log.debug("attested agent=%s artifact=%s hash=%s", hotkey[:10], item["ref"], digest.hex()[:16])

    def set_weights(self, scores_by_track: dict[str, list[tuple[str, float]]]) -> None:
        weight_map = scoring.compute_emission_weights(
            scores_by_track,
            contributor_hotkeys=self._load_contributors(),
            thresholds=scoring.TRACK_THRESHOLDS,
        )
        prior = self._load_prior_weights()
        blended = {
            hk: EMA_ALPHA * weight_map.get(hk, 0.0) + (1.0 - EMA_ALPHA) * prior.get(hk, 0.0)
            for hk in set(weight_map) | set(prior)
        }
        blended = {hk: w for hk, w in blended.items() if w > 1e-9}
        if not blended:
            log.info("set_weights: no agent cleared the quality threshold; skipping")
            return
        self._save_prior_weights(blended)

        uid_by_hotkey = {n.hotkey: n.uid for n in self.metagraph.neurons}
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
            return
        log.info("weights set | matched %d agents", len(uid_weights))

    def _submit_results(self, round_ids: dict[str, str], start_block: int) -> None:
        if self.server is None:
            return
        for track, per_agent in self._round_scores.items():
            results = [
                {"miner_hotkey": hk, **detail} for hk, detail in per_agent.items()
            ]
            attestations = [a for a in self._round_attestations if a.get("track") == track]
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
                log.info(
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
    ) -> None:
        self._refresh_metagraph()
        try:
            scores_by_track = self.run_round(
                start_block, seeds=seeds, participants=participants, round_ids=round_ids
            )
        except (AbstainRound, InfraFailure) as e:
            log.warning("abstaining this round: %s", e)
            return
        self._submit_results(round_ids, start_block)
        self.set_weights(scores_by_track)

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
        round_ids: dict[str, str] = {}
        seeds: dict[str, str] = {}
        participants: dict[str, list[dict]] = {}
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
                round_ids[track] = str(spec.get("round_id") or f"block-{start_block}")
                seed = str(spec.get("seed") or "")
                if seed:
                    seeds[track] = seed
                participants[track] = spec.get("participants") or []
        self._last_server_reject = None
        self._register_with_server()
        self._execute_round(
            round_ids, start_block, seeds=seeds or None, participants=participants or None
        )
        return True

    def run(self) -> None:
        log.info(
            "starting Phylax validator on netuid=%d hotkey=%s tracks=%s round_blocks=%d",
            self.netuid, self.wallet.hotkey.ss58_address,
            ",".join(rounds.TRACKS), self.round_blocks,
        )
        self._register_with_server()
        while not self.should_exit:
            try:
                block = self.subtensor.block
                start = rounds.round_start(block, self.round_blocks)
                if start > self.last_round_start and self._begin_round(start):
                    self.last_round_start = start
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
