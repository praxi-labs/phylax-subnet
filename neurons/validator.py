from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import traceback
from pathlib import Path

import bittensor as bt
import torch

from phylax import rounds, screening
from phylax.analysis import common, scoring, tracks
from phylax.analysis import proof as proofmod
from phylax.harness.corpus import load_corpus
from phylax.harness.runner import InfraFailure, run_task
from phylax.protocol import AgentSynapse
from phylax.server_client import PhylaxServerClient, ServerUnreachable
from phylax.utils.hashing import sha256_bytes, sssa_digest, submission_digest

QUERY_TIMEOUT_S: float = float(os.getenv("PHYLAX_QUERY_TIMEOUT", "60"))
POLL_INTERVAL_S: int = int(os.getenv("PHYLAX_POLL_INTERVAL", "30"))
MAX_AGENT_BYTES: int = 512 * 1024
DEADLINE_MARGIN_BLOCKS: int = 20
EMA_ALPHA: float = 0.3

_VERDICT_ORDINAL = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
_ORDINAL_VERDICT = {v: k for k, v in _VERDICT_ORDINAL.items()}


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


def _keypair_for(ss58: str):
    try:
        return bt.Keypair(ss58_address=ss58)
    except Exception:  # noqa: BLE001, S110
        pass
    try:
        from bittensor_wallet import Keypair

        return Keypair(ss58_address=ss58)
    except Exception:  # noqa: BLE001
        return None


def _metagraph_size(metagraph) -> int:
    if metagraph is None:
        return 0
    val = getattr(metagraph, "n", 0)
    if val is None:
        return 0
    if hasattr(val, "item"):
        try:
            return int(val.item())
        except (ValueError, RuntimeError):
            pass
    try:
        return int(val)
    except (TypeError, ValueError):
        try:
            return len(val)
        except TypeError:
            return 0


class PhylaxValidator:
    neuron_type: str = "ValidatorNeuron"

    def __init__(self, config=None, wallet=None, subtensor=None):
        self.config = config
        if callable(bt.logging):
            bt.logging(config=config)
        elif hasattr(bt.logging, "set_config"):
            bt.logging.set_config(config)
        self.wallet = wallet if wallet is not None else bt.Wallet(config=config)
        self.subtensor = subtensor if subtensor is not None else bt.Subtensor(config=config)
        self.metagraph = self.subtensor.metagraph(netuid=config.netuid)
        self.dendrite = bt.dendrite(wallet=self.wallet)
        self.round_blocks = rounds.ROUND_BLOCKS
        self.corpora = {track: load_corpus(track) for track in rounds.TRACKS}
        self.last_round_start = -1
        self.should_exit = False
        self.server = self._init_server()
        self._round_attestations: list[dict] = []
        self._round_scores: dict[str, dict[str, dict]] = {}
        self._round_seeds: dict[str, str] = {}
        self._round_tasks: dict[str, list[str]] = {}
        if os.getenv("PHYLAX_DEV_UNSAFE_EXECUTOR") == "1":
            bt.logging.warning(
                "PHYLAX_DEV_UNSAFE_EXECUTOR=1: agents run unjailed; never use outside development"
            )
        missing = [t for t in rounds.TRACKS if not self.corpora.get(t)]
        if missing:
            bt.logging.warning(f"no local corpus for tracks: {', '.join(missing)}")

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
            bt.logging.warning(f"server client unavailable: {e}")
            return None

    def _load_contributors(self) -> set[str]:
        raw = os.getenv("PHYLAX_CONTRIBUTORS", "").strip()
        if raw:
            return _parse_contributors(raw)
        authority = os.getenv("PHYLAX_CONTRIBUTOR_AUTHORITY", "").strip()
        if not authority:
            return set()
        try:
            uid = self.metagraph.hotkeys.index(authority)
            commitment = self.subtensor.get_commitment(self.config.netuid, uid)
            if commitment:
                return _parse_contributors(str(commitment))
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
            bt.logging.warning(f"could not persist EMA state: {e}")

    def _serving_uids(self) -> list[int]:
        own = self.wallet.hotkey.ss58_address
        uids: list[int] = []
        for uid, axon in enumerate(self.metagraph.axons):
            if self.metagraph.hotkeys[uid] == own:
                continue
            if getattr(axon, "is_serving", False):
                uids.append(uid)
        return uids

    def _verify_submission(self, hotkey: str, synapse) -> bool:
        code = getattr(synapse, "code", "") or ""
        claimed = str(getattr(synapse, "agent_hash", "") or "")
        sig = str(getattr(synapse, "signature", "") or "").removeprefix("ed25519:")
        if not code or not claimed or not sig:
            return False
        if sha256_bytes(code.encode("utf-8")) != claimed:
            return False
        digest = submission_digest(
            str(getattr(synapse, "track", "") or ""),
            code,
            str(getattr(synapse, "entrypoint", "") or "agent_main"),
            str(getattr(synapse, "sandbox_image", "") or ""),
            str(getattr(synapse, "sandbox_digest", "") or ""),
        )
        keypair = _keypair_for(hotkey)
        if keypair is None:
            return False
        try:
            return bool(keypair.verify(digest, bytes.fromhex(sig)))
        except Exception:  # noqa: BLE001
            return False

    def _screen(self, track: str, synapse) -> str:
        code = getattr(synapse, "code", "") or ""
        if str(getattr(synapse, "track", "")) != track:
            return "wrong track"
        if len(code.encode("utf-8")) > MAX_AGENT_BYTES:
            return "agent exceeds size limit"
        entrypoint = str(getattr(synapse, "entrypoint", "") or "agent_main")
        if f"def {entrypoint}" not in code:
            return "missing entrypoint"
        return ""

    def _fetch_agents(self, track: str, participants: list[dict] | None = None) -> dict[str, dict]:
        if not participants or self.server is None:
            return self._fetch_agents_synapse(track)

        agents: dict[str, dict] = {}
        codes: dict[str, tuple[str, int]] = {}
        for idx, part in enumerate(participants):
            hotkey = str(part.get("hotkey", "") or "")
            expected = str(part.get("agent_hash", "") or "")
            if not hotkey:
                continue
            try:
                data = self.server.get_runnable_agent(hotkey)
            except ServerUnreachable as e:
                raise AbstainRound(f"backend unreachable fetching {hotkey[:10]}: {e}") from e
            code = str((data or {}).get("code") or "")
            if not code:
                continue
            actual = "sha256:" + hashlib.sha256(code.encode("utf-8")).hexdigest()
            if expected and actual != expected:
                bt.logging.warning(
                    f"agent {hotkey[:10]} hash mismatch (frozen {expected[:18]}…); skipping"
                )
                continue
            reason = self._screen_runnable(track, data, code)
            if reason:
                bt.logging.info(f"screened out agent={hotkey[:10]}: {reason}")
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
            bt.logging.warning(f"screened out agent={hotkey[:10]}: copied agent code")
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
        return ""

    def _fetch_agents_synapse(self, track: str) -> dict[str, dict]:
        uids = self._serving_uids()
        if not uids:
            return {}
        axons = [self.metagraph.axons[uid] for uid in uids]
        responses = self.dendrite.query(
            axons=axons, synapse=AgentSynapse(), timeout=QUERY_TIMEOUT_S, deserialize=False
        )
        agents: dict[str, dict] = {}
        uid_by_hotkey: dict[str, int] = {}
        for uid, resp in zip(uids, responses, strict=False):
            hotkey = self.metagraph.hotkeys[uid]
            if not getattr(resp, "code", "") or not self._verify_submission(hotkey, resp):
                continue
            reason = self._screen(track, resp)
            if reason:
                if reason != "wrong track":
                    bt.logging.info(f"screened out agent={hotkey[:10]}: {reason}")
                continue
            uid_by_hotkey[hotkey] = uid
            agents[hotkey] = {
                "code": resp.code,
                "entrypoint": resp.entrypoint or "agent_main",
                "execution_api_key": resp.execution_api_key or "",
                "inference_provider": _provider(resp.execution_api_key or ""),
                "inference_model": resp.inference_model or "",
                "agent_hash": resp.agent_hash,
            }
        copied = screening.duplicate_hotkeys(
            {hk: (agents[hk]["code"], uid_by_hotkey[hk]) for hk in agents}
        )
        for hotkey in copied:
            bt.logging.warning(f"screened out agent={hotkey[:10]}: copied agent code")
            agents.pop(hotkey, None)
        return agents

    def run_round(
        self,
        start_block: int,
        seeds: dict[str, str] | None = None,
        participants: dict[str, list[dict]] | None = None,
    ) -> dict[str, list[tuple[str, float]]]:
        self._round_attestations = []
        self._round_scores = {}
        self._round_seeds = {}
        self._round_tasks = {}
        end_block = start_block + self.round_blocks
        block_hash = str(self.subtensor.get_block_hash(start_block))
        scores_by_track: dict[str, list[tuple[str, float]]] = {}
        for track in rounds.TRACKS:
            corpus = self.corpora.get(track) or []
            if not corpus:
                raise AbstainRound(f"no local corpus for track {track}")
            seed = (seeds or {}).get(track) or rounds.round_seed(block_hash, track)
            budgets = rounds.budgets_for(track)
            task_set = rounds.select_tasks(corpus, seed, budgets["tasks"])
            agents = self._fetch_agents(track, (participants or {}).get(track))
            self._round_seeds[track] = seed
            self._round_tasks[track] = [item["ref"] for item in task_set]
            bt.logging.info(
                f"round start={start_block} end={end_block} track={track} "
                f"tasks={len(task_set)} agents={len(agents)}"
            )
            track_scores: list[tuple[str, float]] = []
            for hotkey, runnable in agents.items():
                if self._out_of_window(end_block):
                    raise AbstainRound(
                        f"window closing at block {end_block} with track {track} incomplete"
                    )
                score = self._score_agent(track, hotkey, runnable, task_set, seed, budgets)
                track_scores.append((hotkey, score))
                self._round_scores.setdefault(track, {})[hotkey] = {
                    "agent_hash": runnable["agent_hash"],
                    "score": round(score, 6),
                }
                bt.logging.info(f"round score track={track} agent={hotkey[:10]} S={score:.3f}")
            scores_by_track[track] = track_scores
        self._write_round_record(start_block, scores_by_track)
        return scores_by_track

    def _out_of_window(self, end_block: int) -> bool:
        try:
            block = self.subtensor.get_current_block()
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
            bt.logging.warning(f"could not write round record: {e}")

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
        for item in task_set:
            target = common.label_risk(item["label"])
            if target is None:
                continue
            verdict, wall_used = self._task_verdict(
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
        if tp + tn + fp + fn == 0:
            return 0.0
        return scoring.clamped_mcc(tp, tn, fp, fn)

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
    ) -> tuple[str | None, float]:
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
            return None, wall_used
        ordinals.sort()
        decision = _ORDINAL_VERDICT[ordinals[(len(ordinals) - 1) // 2]]
        if last_result is not None:
            self._attest(track, hotkey, runnable, item, nonce, last_result)
        return decision, wall_used

    def _run_rep(
        self, track: str, runnable: dict, item: dict, nonce: str, probe, cpu_s: int
    ) -> tuple[int | None, dict | None]:
        dispatch = {
            "track": track,
            "nonce": nonce,
            "probe": probe.as_inputs(),
            "artifact_ref": item["ref"],
            "artifact_b64": item["artifact_b64"],
        }
        result = run_task(dispatch, runnable, log=bt.logging.warning, cpu_budget_s=cpu_s)
        if result is None:
            return None, None
        if result.get("observed_probe_file") is not True:
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
            result = run_task(dispatch, runnable, log=bt.logging.warning, cpu_budget_s=budgets["cpu_s"])
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
        evidence = result["evidence"]
        findings = result.get("findings") or []
        policy = result.get("policy") or {}
        digest = sssa_digest(track, item["ref"], nonce, verdict, evidence, findings, policy)
        signature = "ed25519:" + self.wallet.hotkey.sign(digest).hex()
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
        bt.logging.debug(
            f"attested agent={hotkey[:10]} artifact={item['ref']} hash={digest.hex()[:16]}"
        )

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
            bt.logging.info("set_weights: no agent cleared the quality threshold; skipping")
            return
        self._save_prior_weights(blended)

        n = _metagraph_size(self.metagraph)
        hotkey_to_uid = {hk: uid for uid, hk in enumerate(self.metagraph.hotkeys)}
        weights = torch.zeros(n)
        matched = 0
        for hotkey, w in blended.items():
            uid = hotkey_to_uid.get(hotkey)
            if uid is not None and 0 <= uid < n:
                weights[uid] += float(w)
                matched += 1

        total = weights.sum().item()
        if total <= 0.0:
            bt.logging.warning("set_weights: no miner hotkeys matched metagraph; skipping")
            return
        weights = weights / total
        bt.logging.info(f"set_weights | matched {matched} agents")

        try:
            result, msg = self.subtensor.set_weights(
                netuid=self.config.netuid,
                wallet=self.wallet,
                uids=torch.arange(n),
                weights=weights,
                wait_for_inclusion=False,
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"set_weights raised: {e}")
            return
        if result:
            bt.logging.success("weights set")
        else:
            bt.logging.warning(f"set_weights returned False: {msg}")

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
                bt.logging.success(
                    f"submitted {track} results: {len(results)} agents, "
                    f"{len(attestations)} attestations"
                )
            except ServerUnreachable as e:
                bt.logging.warning(f"could not submit {track} results: {e}")
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"{track} result submission failed: {e}")

    def _execute_round(
        self,
        round_ids: dict[str, str],
        start_block: int,
        seeds: dict[str, str] | None = None,
        participants: dict[str, list[dict]] | None = None,
    ) -> None:
        self.metagraph.sync(subtensor=self.subtensor, lite=True)
        try:
            scores_by_track = self.run_round(start_block, seeds=seeds, participants=participants)
        except (AbstainRound, InfraFailure) as e:
            bt.logging.warning(f"abstaining this round: {e}")
            return
        self._submit_results(round_ids, start_block)
        self.set_weights(scores_by_track)

    def _begin_round(self, start_block: int) -> bool:
        round_ids: dict[str, str] = {}
        seeds: dict[str, str] = {}
        participants: dict[str, list[dict]] = {}
        if self.server is not None:
            for track in rounds.TRACKS:
                try:
                    spec = self.server.next_round(track, self.wallet.hotkey.ss58_address)
                except ServerUnreachable as e:
                    bt.logging.warning(f"server unreachable for {track}: {e}; retrying next poll")
                    return False
                if not spec:
                    continue
                if spec.get("phase") == "submission":
                    bt.logging.info(
                        f"track {track} submission window open "
                        f"until {spec.get('submission_closes_at', '?')}; waiting"
                    )
                    return False
                round_ids[track] = str(spec.get("round_id") or f"block-{start_block}")
                seed = str(spec.get("seed") or "")
                if seed:
                    seeds[track] = seed
                participants[track] = spec.get("participants") or []
        self._execute_round(
            round_ids, start_block, seeds=seeds or None, participants=participants or None
        )
        return True

    def run(self) -> None:
        corpus_sizes = {t: len(self.corpora.get(t) or []) for t in rounds.TRACKS}
        bt.logging.info(
            f"starting Phylax validator on netuid={self.config.netuid} "
            f"hotkey={self.wallet.hotkey.ss58_address} corpora={corpus_sizes} "
            f"round_blocks={self.round_blocks}"
        )
        while not self.should_exit:
            try:
                block = self.subtensor.get_current_block()
                start = rounds.round_start(block, self.round_blocks)
                if start > self.last_round_start and self._begin_round(start):
                    self.last_round_start = start
                time.sleep(POLL_INTERVAL_S)
            except KeyboardInterrupt:
                bt.logging.info("validator stopped by KeyboardInterrupt")
                break
            except Exception as e:  # noqa: BLE001
                bt.logging.error(f"run loop error: {e}")
                bt.logging.debug(traceback.format_exc())
                time.sleep(POLL_INTERVAL_S)


def _provider(api_key: str) -> str:
    if api_key.startswith("cpk_"):
        return "chutes"
    if api_key.startswith("sk-or-"):
        return "openrouter"
    return ""


_NETWORK_ENDPOINTS = {
    "finney":  "wss://entrypoint-finney.opentensor.ai:443",
    "test":    "wss://test.finney.opentensor.ai:443",
    "archive": "wss://archive.chain.opentensor.ai:443",
    "local":   "ws://127.0.0.1:9944",
}


def _resolve_endpoint(network: str | None) -> str:
    if not network:
        return _NETWORK_ENDPOINTS["finney"]
    if network.startswith(("ws://", "wss://")):
        return network
    return _NETWORK_ENDPOINTS.get(network, _NETWORK_ENDPOINTS["finney"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Phylax validator neuron")
    parser.add_argument("--netuid", type=int, required=True, help="Subnet netuid to validate on")
    bt.Wallet.add_args(parser)
    bt.Subtensor.add_args(parser)
    bt.logging.add_args(parser)
    config = bt.Config(parser)
    config.subtensor.chain_endpoint = _resolve_endpoint(config.subtensor.network)
    wallet = bt.Wallet(config=config)
    subtensor = bt.Subtensor(config=config)
    validator = PhylaxValidator(config=config, wallet=wallet, subtensor=subtensor)
    validator.run()


if __name__ == "__main__":
    main()
