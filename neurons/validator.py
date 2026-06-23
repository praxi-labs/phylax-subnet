from __future__ import annotations

import argparse
import asyncio
import os
import time
import traceback

import bittensor as bt
import torch

from phylax.harness.runner import run_task
from phylax.server_client import PhylaxServerClient

ROUND_INTERVAL_S: int = int(os.getenv("PHYLAX_TRACK_INTERVAL", "20"))


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
        self.track = os.getenv("PHYLAX_TRACK", "skills")
        self.rerun_limit = int(os.getenv("PHYLAX_RERUN_LIMIT", "3"))
        self.should_exit = False
        self.step = 0
        self.current_epoch = 0

        server_url = os.getenv("PHYLAX_SERVER_URL", "")
        expected_server_hotkey = os.getenv("PHYLAX_SERVER_HOTKEY", "").strip() or None
        self.server_client: PhylaxServerClient | None = None
        if server_url:
            self.server_client = PhylaxServerClient(
                base_url=server_url,
                wallet=self.wallet,
                expected_server_hotkey=expected_server_hotkey,
            )
            try:
                self.server_client.register(label=os.getenv("PHYLAX_VALIDATOR_LABEL", ""))
                bt.logging.success(
                    f"registered with phylax-server at {server_url} "
                    f"(server_hotkey={(self.server_client.server_hotkey or '')[:16]}…)"
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.error(
                    f"phylax-server registration failed: {e} — set_weights will be "
                    f"blocked until this succeeds"
                )
        else:
            bt.logging.warning(
                "PHYLAX_SERVER_URL not configured — validator cannot audit or set weights"
            )

    async def run_rerun_round(self) -> None:
        if self.server_client is None:
            return
        try:
            data = await asyncio.to_thread(
                self.server_client.fetch_rerun_sample, self.track, self.rerun_limit
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"rerun-sample fetch failed: {e}")
            return
        tasks = (data or {}).get("tasks") or []
        if not tasks:
            bt.logging.info(f"no rerun sample for {self.track}")
            return
        for entry in tasks:
            await self._audit_one(entry)

    async def _audit_one(self, entry: dict) -> None:
        task_id = entry.get("task_id", "")
        agent_hotkey = entry.get("agent_hotkey", "")
        try:
            runnable = await asyncio.to_thread(
                self.server_client.get_runnable_agent, agent_hotkey
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"fetch runnable agent failed {agent_hotkey[:10]}: {e}")
            return

        result = await asyncio.to_thread(run_task, entry, runnable, log=bt.logging.warning)
        reproduced = result is not None and (
            result["verdict"].get("decision", "") == entry.get("verdict", "")
        )
        try:
            resp = await asyncio.to_thread(
                self.server_client.report_rerun, task_id, reproduced=reproduced
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"rerun report failed task={task_id[:8]}: {e}")
            return
        bt.logging.success(
            f"L2 rerun task={task_id[:8]} agent={agent_hotkey[:10]} "
            f"reproduced={reproduced} pass_rate={resp.get('rerun_pass_rate')}"
        )

    def set_weights(self) -> None:
        if self.server_client is None:
            bt.logging.error("set_weights: phylax-server client not initialised; skipping")
            return
        try:
            data = self.server_client.fetch_track_weights()
        except Exception as e:  # noqa: BLE001
            bt.logging.error(f"set_weights: fetch track weights failed: {e}")
            return

        weight_map = (data or {}).get("weights") or {}
        if not weight_map:
            bt.logging.info("set_weights: no agent weights computed yet; skipping")
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
            bt.logging.warning("set_weights: no agent hotkeys matched metagraph; skipping")
            return
        weights = weights / total
        bt.logging.info(
            f"set_weights | matched {matched} agents | "
            f"non-zero={int((weights > 0).sum().item())}"
        )

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
            self.current_epoch += 1
        else:
            bt.logging.warning(f"set_weights returned False: {msg}")

    def run(self) -> None:
        bt.logging.info(
            f"starting Phylax validator on netuid={self.config.netuid} track={self.track} "
            f"hotkey={self.wallet.hotkey.ss58_address}"
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        last_weight_block = 0
        try:
            while not self.should_exit:
                try:
                    self.metagraph.sync(subtensor=self.subtensor, lite=False)
                    loop.run_until_complete(self.run_rerun_round())

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
        finally:
            loop.close()


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
