from __future__ import annotations

import argparse
import json
import math
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
from phylax.harness.runner import run_task
from phylax.protocol import AgentSynapse
from phylax.server_client import PhylaxServerClient, ServerUnreachable
from phylax.utils.hashing import sha256_bytes, sssa_digest, submission_digest

QUERY_TIMEOUT_S: float = float(os.getenv("PHYLAX_QUERY_TIMEOUT", "60"))
POLL_INTERVAL_S: int = int(os.getenv("PHYLAX_POLL_INTERVAL", "30"))
MAX_AGENT_BYTES: int = int(os.getenv("PHYLAX_MAX_AGENT_BYTES", str(512 * 1024)))
SCORE_THRESHOLD: float = float(os.getenv("PHYLAX_SCORE_THRESHOLD", "0.6"))
RELIABILITY_FRACTION: float = float(os.getenv("PHYLAX_RELIABILITY_FRACTION", "0.5"))
CORRECTNESS_FLOOR: float = float(os.getenv("PHYLAX_CORRECTNESS_FLOOR", "0.5"))
DEADLINE_MARGIN_BLOCKS: int = int(os.getenv("PHYLAX_DEADLINE_MARGIN_BLOCKS", "20"))


def _parse_contributors(raw: str) -> set[str]:
    text = raw.strip()
    if not text:
        return set()
    if text.startswith("["):
        try:
            import json

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
        self.track = os.getenv("PHYLAX_TRACK", "skills")
        params = rounds.params_for(self.track)
        self.round_blocks = params["blocks"]
        self.tasks_per_round = params["tasks"]
        self.repetitions = params["repetitions"]
        self.task_timeout = params["timeout_s"]
        self.corpus = load_corpus(self.track)
        self.last_round_start = -1
        self.should_exit = False
        self.server = self._init_server()
        self._round_attestations: list[dict] = []
        self._round_scores: dict[str, dict] = {}
        if os.getenv("PHYLAX_EXECUTOR", "sandbox") != "docker":
            bt.logging.warning(
                "PHYLAX_EXECUTOR is not docker; agents will not be evaluated until the jail is enabled"
            )
        if not self.corpus:
            bt.logging.warning(f"no local corpus found for track={self.track}")

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

    def _screen(self, synapse) -> str:
        code = getattr(synapse, "code", "") or ""
        if str(getattr(synapse, "track", "")) != self.track:
            return "wrong track"
        if len(code.encode("utf-8")) > MAX_AGENT_BYTES:
            return "agent exceeds size limit"
        entrypoint = str(getattr(synapse, "entrypoint", "") or "agent_main")
        if f"def {entrypoint}" not in code:
            return "missing entrypoint"
        return ""

    def _fetch_agents(self) -> dict[str, dict]:
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
            reason = self._screen(resp)
            if reason:
                bt.logging.info(f"screened out agent={hotkey[:10]}: {reason}")
                continue
            uid_by_hotkey[hotkey] = uid
            agents[hotkey] = {
                "code": resp.code,
                "entrypoint": resp.entrypoint or "agent_main",
                "execution_api_key": resp.execution_api_key or "",
                "inference_provider": _provider(resp.execution_api_key or ""),
                "inference_model": resp.inference_model or "",
                "sandbox_image": resp.sandbox_image,
                "sandbox_digest": resp.sandbox_digest,
                "agent_hash": resp.agent_hash,
            }
        copied = screening.duplicate_hotkeys(
            {hk: (agents[hk]["code"], uid_by_hotkey[hk]) for hk in agents}
        )
        for hotkey in copied:
            bt.logging.warning(f"screened out agent={hotkey[:10]}: copied agent code")
            agents.pop(hotkey, None)
        return agents

    def run_round(self, start_block: int, seed: str | None = None) -> dict[str, float]:
        if os.getenv("PHYLAX_EXECUTOR", "sandbox") != "docker":
            bt.logging.error(
                "refusing to evaluate: PHYLAX_EXECUTOR must be docker so agents never run unjailed"
            )
            return {}
        self._round_attestations = []
        self._round_scores = {}
        # A server-scheduled round carries the seed so every validator derives the
        # identical task set; the block-timed fallback derives it from the chain.
        if not seed:
            block_hash = str(self.subtensor.get_block_hash(start_block))
            seed = rounds.round_seed(block_hash, self.track)
        task_set = rounds.select_tasks(self.corpus, seed, self.tasks_per_round)
        agents = self._fetch_agents()
        end_block = start_block + self.round_blocks
        bt.logging.info(
            f"round start={start_block} end={end_block} track={self.track} "
            f"tasks={len(task_set)} agents={len(agents)}"
        )
        scores: dict[str, float] = {}
        for hotkey, runnable in agents.items():
            if self._out_of_window(end_block):
                bt.logging.warning(
                    f"round window closing at block {end_block}; "
                    f"{len(agents) - len(scores)} agents left unevaluated"
                )
                break
            scores[hotkey] = self._score_agent(hotkey, runnable, task_set, seed)
            self._round_scores[hotkey] = {
                "agent_hash": agents[hotkey]["agent_hash"],
                "score": round(scores[hotkey], 6),
            }
            bt.logging.info(f"round score agent={hotkey[:10]} S={scores[hotkey]:.3f}")
        self._write_round_record(start_block, seed, task_set, agents, scores)
        return scores

    def _out_of_window(self, end_block: int) -> bool:
        try:
            block = self.subtensor.get_current_block()
        except Exception:  # noqa: BLE001
            return False
        return block >= end_block - DEADLINE_MARGIN_BLOCKS

    def _write_round_record(
        self, start_block: int, seed: str,
        task_set: list[dict], agents: dict[str, dict], scores: dict[str, float],
    ) -> None:
        state_dir = Path(os.getenv("PHYLAX_STATE_DIR", "state"))
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            record = {
                "track": self.track,
                "start_block": start_block,
                "seed": seed,
                "tasks": [item["ref"] for item in task_set],
                "agents": {
                    hk: {
                        "agent_hash": agents[hk]["agent_hash"],
                        "score": round(scores.get(hk, 0.0), 6),
                        "evaluated": hk in scores,
                    }
                    for hk in agents
                },
            }
            path = state_dir / f"round_{self.track}_{start_block}.json"
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        except OSError as e:
            bt.logging.warning(f"could not write round record: {e}")

    def _score_agent(self, hotkey: str, runnable: dict, task_set: list[dict], seed: str) -> float:
        if not task_set:
            return 0.0
        total = 0.0
        for item in task_set:
            total += self._score_task(hotkey, runnable, item, seed)
        return total / len(task_set)

    def _score_task(self, hotkey: str, runnable: dict, item: dict, seed: str) -> float:
        nonce = rounds.task_nonce(seed, item["ref"], hotkey)
        probe = proofmod.derive_probe(nonce)
        run_scores: list[float] = []
        last_result = None
        for _ in range(self.repetitions):
            score, result = self._score_run(runnable, item, nonce, probe)
            run_scores.append(score)
            if result is not None:
                last_result = result
        # Reliability counts runs the agent got CORRECT (score clears the floor),
        # not merely nonzero — a partially-right run is not a reliable one.
        passing = sum(1 for s in run_scores if s >= CORRECTNESS_FLOOR)
        needed = math.ceil(RELIABILITY_FRACTION * self.repetitions)
        task_score = sum(run_scores) / len(run_scores) if passing >= needed else 0.0
        if last_result is not None and task_score > 0.0:
            self._attest(hotkey, runnable, item, nonce, last_result)
        return task_score

    def _liveness_ok(self, result: dict, nonce: str) -> bool:
        if result.get("observed_probe_file") is True:
            return True
        return self._inference_seen(nonce)

    def _inference_seen(self, nonce: str) -> bool:
        url = os.getenv("PHYLAX_INFERENCE_PROXY_URL", "").strip()
        token = os.getenv("PHYLAX_PROXY_ADMIN_TOKEN", "").strip()
        if not url or not token or not nonce:
            return False
        try:
            import httpx

            r = httpx.get(
                f"{url.rstrip('/')}/metrics",
                params={"nonce": nonce},
                headers={"X-Phylax-Admin": token},
                timeout=5.0,
            )
            usage = (r.json() or {}).get("usage") or {}
            return int(usage.get("requests", 0) or 0) > 0
        except Exception:  # noqa: BLE001
            return False

    def _score_run(self, runnable: dict, item: dict, nonce: str, probe) -> tuple[float, dict | None]:
        dispatch = {
            "track": self.track,
            "nonce": nonce,
            "probe": probe.as_inputs(),
            "artifact_ref": item["ref"],
            "artifact_b64": item["artifact_b64"],
        }
        result = run_task(
            dispatch, runnable, log=bt.logging.warning, timeout=self.task_timeout
        )
        if result is None:
            return 0.0, None
        # Liveness: a behavioural-track run must show it actually executed — either
        # the probe was observed or the agent made real inference calls this task.
        # Correctness (below) still dominates; this only rejects no-op runs.
        if self.track != "repositories" and not self._liveness_ok(result, nonce):
            return 0.0, result
        verdict = result["verdict"] if isinstance(result["verdict"], dict) else {}
        decision = str(verdict.get("decision", ""))
        ev = tracks.evaluate(
            self.track,
            result["evidence"],
            decision,
            label=item["label"],
            probe=probe,
            ground_truth=item.get("ground_truth"),
        )
        if not ev.result.gate_passed:
            return 0.0, result
        if self.track == "repositories":
            return scoring.clip01(ev.result.score), result
        correctness = common.risk_correctness(verdict, item["label"])
        if correctness is None:
            correctness = ev.result.components.verdict_correctness
        quality = ev.result.components.solution_quality
        base = scoring.RUN_W_CORRECTNESS * correctness + scoring.RUN_W_QUALITY * quality
        return scoring.clip01(base), result

    def _attest(self, hotkey: str, runnable: dict, item: dict, nonce: str, result: dict) -> None:
        verdict = result["verdict"]
        evidence = result["evidence"]
        findings = result.get("findings") or []
        policy = result.get("policy") or {}
        digest = sssa_digest(self.track, item["ref"], nonce, verdict, evidence, findings, policy)
        signature = "ed25519:" + self.wallet.hotkey.sign(digest).hex()
        sssa = {
            "track": self.track,
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

    def set_weights(self, scores: dict[str, float]) -> None:
        ranked = list(scores.items())
        weight_map = scoring.compute_emission_weights(
            {self.track: ranked},
            contributor_hotkeys=self._load_contributors(),
            threshold=SCORE_THRESHOLD,
        )
        if not weight_map:
            bt.logging.info("set_weights: no agent cleared the quality threshold; skipping")
            return

        n = _metagraph_size(self.metagraph)
        hotkey_to_uid = {hk: uid for uid, hk in enumerate(self.metagraph.hotkeys)}
        weights = torch.zeros(n)
        matched = 0
        for hotkey, w in weight_map.items():
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

    def _submit_results(self, round_id: str, start_block: int, seed: str) -> None:
        if self.server is None:
            return
        results = [
            {"miner_hotkey": hk, **detail} for hk, detail in self._round_scores.items()
        ]
        try:
            self.server.submit_round_results(
                round_id=round_id,
                track=self.track,
                validator_hotkey=self.wallet.hotkey.ss58_address,
                start_block=start_block,
                seed=seed,
                results=results,
                attestations=self._round_attestations,
            )
            bt.logging.success(
                f"submitted round results: {len(results)} agents, "
                f"{len(self._round_attestations)} attestations"
            )
        except ServerUnreachable as e:
            bt.logging.warning(f"could not submit round results: {e}")
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"round result submission failed: {e}")

    def _execute_round(self, round_id: str, start_block: int, seed: str | None = None) -> None:
        self.metagraph.sync(subtensor=self.subtensor, lite=True)
        if not seed:
            seed = rounds.round_seed(str(self.subtensor.get_block_hash(start_block)), self.track)
        scores = self.run_round(start_block, seed=seed)
        self._submit_results(round_id, start_block, seed)
        self.set_weights(scores)

    def _server_round_loop(self) -> None:
        while not self.should_exit:
            try:
                spec = self.server.next_round(self.track, self.wallet.hotkey.ss58_address)
                if spec and self.corpus:
                    start_block = int(spec.get("start_block") or self.subtensor.get_current_block())
                    round_id = str(spec["round_id"])
                    seed = str(spec.get("seed") or "") or None
                    bt.logging.info(f"server scheduled round {round_id} track={self.track}")
                    self._execute_round(round_id, start_block, seed=seed)
                time.sleep(POLL_INTERVAL_S)
            except KeyboardInterrupt:
                bt.logging.info("validator stopped by KeyboardInterrupt")
                break
            except ServerUnreachable as e:
                bt.logging.warning(f"server unreachable: {e}")
                time.sleep(POLL_INTERVAL_S)
            except Exception as e:  # noqa: BLE001
                bt.logging.error(f"run loop error: {e}")
                bt.logging.debug(traceback.format_exc())
                time.sleep(POLL_INTERVAL_S)

    def _block_timed_loop(self) -> None:
        while not self.should_exit:
            try:
                block = self.subtensor.get_current_block()
                start = rounds.round_start(block, self.round_blocks)
                if start > self.last_round_start and self.corpus:
                    self._execute_round(f"block-{start}", start)
                    self.last_round_start = start
                time.sleep(POLL_INTERVAL_S)
            except KeyboardInterrupt:
                bt.logging.info("validator stopped by KeyboardInterrupt")
                break
            except Exception as e:  # noqa: BLE001
                bt.logging.error(f"run loop error: {e}")
                bt.logging.debug(traceback.format_exc())
                time.sleep(POLL_INTERVAL_S)

    def run(self) -> None:
        mode = "server-scheduled" if self.server is not None else "block-timed"
        bt.logging.info(
            f"starting Phylax validator on netuid={self.config.netuid} track={self.track} "
            f"hotkey={self.wallet.hotkey.ss58_address} corpus={len(self.corpus)} "
            f"rounds={mode}"
        )
        if self.server is not None:
            self._server_round_loop()
        else:
            self._block_timed_loop()


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
