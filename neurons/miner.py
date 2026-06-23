from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

import bittensor as bt

from phylax.harness.runner import run_task
from phylax.server_client import PhylaxServerClient

MINER_INTERVAL_S: int = int(os.getenv("PHYLAX_MINER_INTERVAL", "20"))


def _reference_agent_path() -> str:
    return str(
        Path(__file__).resolve().parent.parent
        / "phylax" / "harness" / "skills_reference_agent.py"
    )


class PhylaxMiner:
    neuron_type: str = "MinerNeuron"

    def __init__(self, config=None, wallet=None, subtensor=None):
        self.config = config
        if callable(bt.logging):
            bt.logging(config=config)
        elif hasattr(bt.logging, "set_config"):
            bt.logging.set_config(config)
        self.wallet = wallet if wallet is not None else bt.Wallet(config=config)
        self.subtensor = subtensor if subtensor is not None else bt.Subtensor(config=config)
        self.metagraph = self.subtensor.metagraph(netuid=config.netuid)
        self.track = os.getenv("PHYLAX_TRACK", "skills")
        self.should_exit = False

        self.agent_path = os.getenv("PHYLAX_AGENT_PATH", "") or _reference_agent_path()
        self.entrypoint = os.getenv("PHYLAX_AGENT_ENTRYPOINT", "agent_main")
        self.execution_api_key = os.getenv("PHYLAX_EXECUTION_API_KEY", "")
        self.inference_model = os.getenv("PHYLAX_INFERENCE_MODEL", "")
        self.sandbox_image = os.getenv("PHYLAX_SANDBOX_IMAGE", "")
        self.sandbox_digest = os.getenv("PHYLAX_SANDBOX_DIGEST", "")

        server_url = os.getenv("PHYLAX_SERVER_URL", "")
        expected_server_hotkey = os.getenv("PHYLAX_SERVER_HOTKEY", "").strip() or None
        self.server_client: PhylaxServerClient | None = None
        if server_url:
            self.server_client = PhylaxServerClient(
                base_url=server_url,
                wallet=self.wallet,
                expected_server_hotkey=expected_server_hotkey,
            )
        else:
            bt.logging.warning("PHYLAX_SERVER_URL not configured — miner cannot fetch tasks")

    def _provider(self) -> str:
        if self.execution_api_key.startswith("cpk_"):
            return "chutes"
        if self.execution_api_key.startswith("sk-or-"):
            return "openrouter"
        return ""

    def _local_runnable(self) -> dict:
        return {
            "code": Path(self.agent_path).read_text(encoding="utf-8"),
            "entrypoint": self.entrypoint,
            "execution_api_key": self.execution_api_key,
            "inference_provider": self._provider(),
            "inference_model": self.inference_model,
            "sandbox_image": self.sandbox_image,
            "sandbox_digest": self.sandbox_digest,
        }

    def _sign_sssa(self, dispatch: dict, verdict: dict, evidence: dict) -> str:
        body = json.dumps(
            {
                "track": dispatch.get("track", ""),
                "bundle_hash": dispatch.get("artifact_ref", ""),
                "nonce": dispatch.get("nonce", ""),
                "verdict": verdict,
                "evidence": evidence,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(body).digest()
        return "ed25519:" + self.wallet.hotkey.sign(digest).hex()

    def _run_one(self) -> None:
        if self.server_client is None:
            return
        try:
            dispatch = self.server_client.dispatch_track_task(self.track)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"task dispatch failed: {e}")
            return
        if not dispatch:
            bt.logging.info(f"no task available for {self.track}")
            return

        runnable = self._local_runnable()
        result = run_task(dispatch, runnable, log=bt.logging.warning)
        if result is None:
            return

        verdict = result["verdict"]
        evidence = result["evidence"]
        signature = self._sign_sssa(dispatch, verdict, evidence)
        try:
            resp = self.server_client.submit_track_attestation(
                dispatch["task_id"],
                verdict=verdict.get("decision", "ALLOW"),
                evidence=evidence,
                risk_score=int(verdict.get("risk_score", 0) or 0),
                miner_signature=signature,
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"submit attestation failed task={dispatch['task_id'][:8]}: {e}")
            return

        bt.logging.success(
            f"task={dispatch['task_id'][:8]} verdict={verdict.get('decision')} "
            f"score={resp.get('score')} gate={resp.get('evidence_gate_passed')}"
        )

    def run(self):
        bt.logging.info(
            f"Starting Phylax miner on subnet {self.config.netuid} track={self.track} "
            f"| hotkey: {self.wallet.hotkey.ss58_address}"
        )
        step = 0
        while not self.should_exit:
            try:
                if step % 10 == 0:
                    self.metagraph.sync(subtensor=self.subtensor)
                self._run_one()
                step += 1
                time.sleep(MINER_INTERVAL_S)
            except KeyboardInterrupt:
                bt.logging.info("Miner stopped by KeyboardInterrupt")
                break
            except Exception as e:  # noqa: BLE001
                bt.logging.error(f"run loop error: {e}")
                time.sleep(MINER_INTERVAL_S)


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


def main():
    parser = argparse.ArgumentParser(description="Phylax miner neuron")
    parser.add_argument("--netuid", type=int, required=True, help="Subnet netuid to mine on")
    bt.Wallet.add_args(parser)
    bt.Subtensor.add_args(parser)
    bt.logging.add_args(parser)
    bt.Axon.add_args(parser)
    config = bt.Config(parser)
    config.subtensor.chain_endpoint = _resolve_endpoint(config.subtensor.network)
    wallet = bt.Wallet(config=config)
    subtensor = bt.Subtensor(config=config)
    miner = PhylaxMiner(config=config, wallet=wallet, subtensor=subtensor)
    miner.run()


if __name__ == "__main__":
    main()
