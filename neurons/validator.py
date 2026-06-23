from __future__ import annotations

import argparse
import os
import random
import time
import traceback

import bittensor as bt
import torch

from phylax.analysis import proof as proofmod
from phylax.analysis import scoring, tracks
from phylax.harness.corpus import load_corpus
from phylax.harness.runner import run_task
from phylax.protocol import AgentSynapse, TaskSynapse

ROUND_INTERVAL_S: int = int(os.getenv("PHYLAX_TRACK_INTERVAL", "20"))
QUERY_TIMEOUT_S: float = float(os.getenv("PHYLAX_QUERY_TIMEOUT", "150"))
SCORE_ALPHA = 0.2
RERUN_ALPHA = 0.3


def _provider(api_key: str) -> str:
    if api_key.startswith("cpk_"):
        return "chutes"
    if api_key.startswith("sk-or-"):
        return "openrouter"
    return ""


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

    WEIGHT_UPDATE_INTERVAL: int = int(os.getenv("WEIGHT_UPDATE_INTERVAL", "360"))

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
        self.rerun_limit = int(os.getenv("PHYLAX_RERUN_LIMIT", "3"))
        self.detonation = self.track != "repositories"
        self.corpus = load_corpus(self.track)
        self.scores: dict[str, float] = {}
        self.rerun_pass: dict[str, float] = {}
        self.should_exit = False
        self.step = 0
        if not self.corpus:
            bt.logging.warning(f"no local corpus found for track={self.track}")

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

    def _verify_sig(self, hotkey: str, sssa: dict) -> bool:
        att = sssa.get("attestation") or {}
        if str(att.get("miner_hotkey", "")) != hotkey:
            return False
        canonical_hash = str(att.get("canonical_hash", "")).removeprefix("sha256:")
        sig = str(att.get("signature", "")).removeprefix("ed25519:")
        if not canonical_hash or not sig:
            return False
        keypair = _keypair_for(hotkey)
        if keypair is None:
            return True
        try:
            return bool(keypair.verify(bytes.fromhex(canonical_hash), bytes.fromhex(sig)))
        except Exception:  # noqa: BLE001
            return True

    def _score_response(self, hotkey: str, sssa: dict, label: str, probe) -> str | None:
        if not sssa or not self._verify_sig(hotkey, sssa):
            self._update_score(hotkey, 0.0)
            return None
        verdict = sssa.get("verdict") or {}
        decision = verdict.get("decision", "") if isinstance(verdict, dict) else str(verdict)
        evidence = sssa.get("evidence") or {}
        ev = tracks.evaluate(self.track, evidence, decision, label=label, probe=probe)
        self._update_score(hotkey, ev.result.score)
        return decision

    def _update_score(self, hotkey: str, task_score: float) -> None:
        prev = self.scores.get(hotkey, 0.0)
        self.scores[hotkey] = SCORE_ALPHA * task_score + (1.0 - SCORE_ALPHA) * prev

    def _update_rerun(self, hotkey: str, reproduced: bool) -> None:
        prev = self.rerun_pass.get(hotkey, 1.0)
        self.rerun_pass[hotkey] = RERUN_ALPHA * (1.0 if reproduced else 0.0) + (1.0 - RERUN_ALPHA) * prev

    def run_round(self) -> None:
        if not self.corpus:
            return
        uids = self._serving_uids()
        if not uids:
            bt.logging.info("no serving miners to query")
            return
        item = random.choice(self.corpus)  # noqa: S311
        nonce = proofmod.new_nonce()
        probe = proofmod.derive_probe(nonce)
        synapse = TaskSynapse(
            track=self.track,
            artifact_ref=item["ref"],
            artifact_b64=item["artifact_b64"],
            nonce=nonce,
            probe=probe.as_inputs(),
        )
        axons = [self.metagraph.axons[uid] for uid in uids]
        responses = self.dendrite.query(
            axons=axons, synapse=synapse, timeout=QUERY_TIMEOUT_S, deserialize=False
        )

        answered: list[tuple[str, str]] = []
        for uid, resp in zip(uids, responses, strict=False):
            hotkey = self.metagraph.hotkeys[uid]
            sssa = getattr(resp, "sssa", None) or {}
            decision = self._score_response(hotkey, sssa, item["label"], probe)
            if decision is not None:
                answered.append((hotkey, decision))

        bt.logging.info(
            f"round track={self.track} artifact={item['ref']} queried={len(uids)} "
            f"answered={len(answered)}"
        )
        self._run_reruns(answered, item, probe)

    def _run_reruns(self, answered: list[tuple[str, str]], item: dict, probe) -> None:
        if not answered:
            return
        sample = random.sample(answered, min(self.rerun_limit, len(answered)))  # noqa: S311
        for hotkey, miner_decision in sample:
            uid = self.metagraph.hotkeys.index(hotkey)
            runnable = self._fetch_agent(self.metagraph.axons[uid])
            if runnable is None:
                continue
            dispatch = {
                "track": self.track,
                "nonce": probe.nonce,
                "probe": probe.as_inputs(),
                "artifact_ref": item["ref"],
                "artifact_b64": item["artifact_b64"],
            }
            result = run_task(dispatch, runnable, log=bt.logging.warning)
            reproduced = result is not None and (
                result["verdict"].get("decision", "") == miner_decision
            )
            self._update_rerun(hotkey, reproduced)
            bt.logging.success(
                f"L2 rerun agent={hotkey[:10]} reproduced={reproduced} "
                f"pass_rate={self.rerun_pass.get(hotkey):.3f}"
            )

    def _fetch_agent(self, axon) -> dict | None:
        try:
            resp = self.dendrite.query(
                axons=[axon], synapse=AgentSynapse(), timeout=QUERY_TIMEOUT_S, deserialize=False
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"agent fetch failed: {e}")
            return None
        if not resp:
            return None
        agent = resp[0]
        code = getattr(agent, "code", "") or ""
        if not code:
            return None
        return {
            "code": code,
            "entrypoint": getattr(agent, "entrypoint", "") or "agent_main",
            "execution_api_key": getattr(agent, "execution_api_key", "") or "",
            "inference_provider": _provider(getattr(agent, "execution_api_key", "") or ""),
            "inference_model": getattr(agent, "inference_model", "") or "",
            "sandbox_image": getattr(agent, "sandbox_image", "") or "",
            "sandbox_digest": getattr(agent, "sandbox_digest", "") or "",
        }

    def set_weights(self) -> None:
        ranked = [
            (hk, self.scores.get(hk, 0.0) * self.rerun_pass.get(hk, 1.0))
            for hk in self.scores
        ]
        weight_map = scoring.compute_emission_weights(
            {self.track: ranked}, contributor_hotkeys=self._load_contributors()
        )
        if not weight_map:
            bt.logging.info("set_weights: no miner weights computed yet; skipping")
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
        bt.logging.info(f"set_weights | matched {matched} miners")

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

    def run(self) -> None:
        bt.logging.info(
            f"starting Phylax validator on netuid={self.config.netuid} track={self.track} "
            f"hotkey={self.wallet.hotkey.ss58_address} corpus={len(self.corpus)}"
        )
        last_weight_block = 0
        while not self.should_exit:
            try:
                self.metagraph.sync(subtensor=self.subtensor, lite=False)
                self.run_round()

                current_block = self.subtensor.get_current_block()
                if current_block - last_weight_block >= self.WEIGHT_UPDATE_INTERVAL:
                    self.set_weights()
                    last_weight_block = current_block

                self.step += 1
                time.sleep(ROUND_INTERVAL_S)
            except KeyboardInterrupt:
                bt.logging.info("validator stopped by KeyboardInterrupt")
                break
            except Exception as e:  # noqa: BLE001
                bt.logging.error(f"run loop error: {e}")
                bt.logging.debug(traceback.format_exc())
                time.sleep(ROUND_INTERVAL_S)


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
