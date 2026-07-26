from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path

import bittensor as bt

from phylax.server_client import PhylaxServerClient

MINER_INTERVAL_S: int = int(os.getenv("PHYLAX_MINER_INTERVAL", "20"))

log = logging.getLogger("phylax.miner")


def _reference_agent_path() -> str:
    return str(
        Path(__file__).resolve().parent.parent
        / "phylax" / "harness" / "reference_agent.py"
    )


class PhylaxMiner:
    neuron_type: str = "MinerNeuron"

    def __init__(self, wallet: bt.Wallet):
        self.wallet = wallet
        self.track = os.getenv("PHYLAX_TRACK", "skills")
        self.should_exit = False
        self.agent_path = (
            os.getenv("PHYLAX_AGENT_CODE_PATH", "")
            or os.getenv("PHYLAX_AGENT_PATH", "")
            or _reference_agent_path()
        )
        self.entrypoint = os.getenv("PHYLAX_AGENT_ENTRYPOINT", "agent_main")
        self.execution_api_key = os.getenv("PHYLAX_EXECUTION_API_KEY", "")
        self.inference_model = os.getenv("PHYLAX_INFERENCE_MODEL", "")

    def _agent_code(self) -> str:
        return Path(self.agent_path).read_text(encoding="utf-8")

    def submit(self) -> bool:
        server_url = os.getenv("PHYLAX_SERVER_URL", "")
        if not server_url:
            log.warning("PHYLAX_SERVER_URL unset; nothing to submit")
            return False
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
                code=self._agent_code(),
                execution_api_key=self.execution_api_key,
                entrypoint=self.entrypoint,
                name=os.getenv("PHYLAX_MINER_LABEL", ""),
                inference_model=self.inference_model,
            )
            log.info("agent submitted to the backend for track=%s", self.track)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("agent submission failed: %s", e)
            return False

    def run(self) -> None:
        log.info(
            "Phylax mining is submit only: validators fetch your agent from the "
            "backend at round start. This process idles and resubmits on restart; "
            "it is safe to stop it."
        )
        while not self.should_exit:
            try:
                time.sleep(MINER_INTERVAL_S)
            except KeyboardInterrupt:
                log.info("miner stopped by KeyboardInterrupt")
                break


def _setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else os.getenv("PHYLAX_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Phylax miner (submit only)")
    parser.add_argument("--netuid", type=int, default=int(os.getenv("PHYLAX_NETUID", "76")))
    parser.add_argument(
        "--subtensor.network", dest="network",
        default=os.getenv("SUBTENSOR_NETWORK", "finney"),
    )
    parser.add_argument(
        "--wallet.name", dest="wallet_name", default=os.getenv("WALLET_NAME", "miner")
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
    miner = PhylaxMiner(wallet)
    miner.submit()
    miner.run()


if __name__ == "__main__":
    main()
