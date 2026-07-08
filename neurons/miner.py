from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import bittensor as bt

from phylax.harness.runner import run_task
from phylax.protocol import AgentSynapse, TaskSynapse
from phylax.server_client import PhylaxServerClient
from phylax.utils.hashing import sssa_digest

MINER_INTERVAL_S: int = int(os.getenv("PHYLAX_MINER_INTERVAL", "20"))
MIN_VALIDATOR_STAKE: float = float(os.getenv("PHYLAX_MIN_VALIDATOR_STAKE", "0"))


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

        axon_kwargs: dict = {"wallet": self.wallet, "config": config}
        axon_port = os.getenv("PHYLAX_AXON_PORT", "").strip()
        if axon_port:
            axon_kwargs["port"] = int(axon_port)
        axon_external_ip = os.getenv("PHYLAX_AXON_EXTERNAL_IP", "").strip()
        if axon_external_ip:
            axon_kwargs["external_ip"] = axon_external_ip
        self.axon = bt.axon(**axon_kwargs)
        self.axon.attach(
            forward_fn=self.handle_task,
            blacklist_fn=self.blacklist_task,
            priority_fn=self.priority,
        ).attach(
            forward_fn=self.handle_agent,
            blacklist_fn=self.blacklist_agent,
            priority_fn=self.priority,
        )

        self._register_agent_for_marketplace()

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

    def _register_agent_for_marketplace(self) -> None:
        server_url = os.getenv("PHYLAX_SERVER_URL", "")
        if not server_url:
            return
        expected = os.getenv("PHYLAX_SERVER_HOTKEY", "").strip() or None
        try:
            client = PhylaxServerClient(
                base_url=server_url, wallet=self.wallet, expected_server_hotkey=expected
            )
            client.register_track(
                self.wallet.hotkey.ss58_address, self.track,
                label=os.getenv("PHYLAX_MINER_LABEL", ""),
            )
            client.submit_agent(
                hotkey=self.wallet.hotkey.ss58_address,
                code=Path(self.agent_path).read_text(encoding="utf-8"),
                execution_api_key=self.execution_api_key,
                sandbox_image=self.sandbox_image,
                sandbox_digest=self.sandbox_digest,
                entrypoint=self.entrypoint,
                name=os.getenv("PHYLAX_MINER_LABEL", ""),
                inference_model=self.inference_model,
            )
            bt.logging.success("registered agent with marketplace")
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"marketplace registration skipped: {e}")

    def _sign(
        self, track: str, bundle_hash: str, nonce: str,
        verdict: dict, evidence: dict, findings: list,
    ):
        digest = sssa_digest(track, bundle_hash, nonce, verdict, evidence, findings)
        return "sha256:" + digest.hex(), "ed25519:" + self.wallet.hotkey.sign(digest).hex()

    def handle_task(self, synapse: TaskSynapse) -> TaskSynapse:
        if synapse.track and synapse.track != self.track:
            return synapse
        dispatch = {
            "track": self.track,
            "nonce": synapse.nonce,
            "probe": synapse.probe or {},
            "artifact_ref": synapse.artifact_ref,
            "artifact_b64": synapse.artifact_b64,
        }
        result = run_task(dispatch, self._local_runnable(), log=bt.logging.warning)
        if result is None:
            return synapse
        verdict = result["verdict"]
        evidence = result["evidence"]
        findings = result.get("findings") or []
        canonical_hash, signature = self._sign(
            self.track, synapse.artifact_ref, synapse.nonce, verdict, evidence, findings
        )
        synapse.sssa = {
            "track": self.track,
            "artifact": {"bundle_hash": synapse.artifact_ref, "nonce": synapse.nonce},
            "verdict": verdict,
            "evidence": evidence,
            "findings": findings,
            "attestation": {
                "miner_hotkey": self.wallet.hotkey.ss58_address,
                "signature": signature,
                "canonical_hash": canonical_hash,
            },
        }
        return synapse

    def handle_agent(self, synapse: AgentSynapse) -> AgentSynapse:
        synapse.track = self.track
        synapse.code = Path(self.agent_path).read_text(encoding="utf-8")
        synapse.entrypoint = self.entrypoint
        synapse.execution_api_key = self.execution_api_key
        synapse.inference_model = self.inference_model
        synapse.sandbox_image = self.sandbox_image
        synapse.sandbox_digest = self.sandbox_digest
        return synapse

    def blacklist_task(self, synapse: TaskSynapse) -> tuple[bool, str]:
        return self._blacklist(synapse)

    def blacklist_agent(self, synapse: AgentSynapse) -> tuple[bool, str]:
        return self._blacklist(synapse)

    def _blacklist(self, synapse) -> tuple[bool, str]:
        hotkey = getattr(synapse.dendrite, "hotkey", None)
        if hotkey is None or hotkey not in self.metagraph.hotkeys:
            return True, "unrecognised hotkey"
        uid = self.metagraph.hotkeys.index(hotkey)
        try:
            permit = bool(self.metagraph.validator_permit[uid])
        except (IndexError, TypeError, AttributeError):
            permit = False
        if not permit:
            return True, "caller lacks a validator permit"
        if float(self.metagraph.S[uid]) < MIN_VALIDATOR_STAKE:
            return True, "caller stake below validator minimum"
        return False, ""

    def priority(self, synapse) -> float:
        hotkey = getattr(synapse.dendrite, "hotkey", None)
        if hotkey in self.metagraph.hotkeys:
            uid = self.metagraph.hotkeys.index(hotkey)
            return float(self.metagraph.S[uid])
        return 0.0

    def run(self):
        bt.logging.info(
            f"Starting Phylax miner on subnet {self.config.netuid} track={self.track} "
            f"| hotkey: {self.wallet.hotkey.ss58_address}"
        )
        self.axon.serve(netuid=self.config.netuid, subtensor=self.subtensor).start()
        step = 0
        while not self.should_exit:
            try:
                if step % 10 == 0:
                    self.metagraph.sync(subtensor=self.subtensor)
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
