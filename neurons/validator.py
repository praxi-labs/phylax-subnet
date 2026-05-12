"""
neurons/validator.py

Phylax subnet validator — sends skill bundles to miners, scores their
Signed Skill Safety Attestations, and sets weights on-chain.

Run with:
    python neurons/validator.py \
        --netuid <NETUID> \
        --subtensor.network test \
        --wallet.name validator \
        --wallet.hotkey default \
        --logging.debug
"""

import asyncio
import json
import os
import random
import time
import traceback
from pathlib import Path
from typing import List, Optional

import bittensor as bt
import numpy as np
import torch

from phylax.protocol import PhylaxSynapse, SkillBundle, SSSA, TestProfile
from phylax.scoring.rewards import compute_total_score
from phylax.scoring.metrics import score_all_axes
from phylax.utils.logging import get_logger

logger = get_logger(__name__)

CORPORA_DIR = Path(__file__).parent.parent / "corpora"


class PhylaxValidator(bt.BaseNeuron):
    """
    Phylax validator neuron.

    Each epoch:
      1. Sample a batch of tasks from the corpora
      2. Send skill bundles to all active miners via dendrite
      3. Collect and score SSSA responses on 4 axes
      4. Set weights on-chain via Yuma Consensus
    """

    neuron_type: str = "ValidatorNeuron"

    # How many tasks to send per scoring round
    TASKS_PER_ROUND: int = int(os.getenv("TASKS_PER_ROUND", "10"))
    # How long to wait for miner responses (seconds)
    QUERY_TIMEOUT: int   = int(os.getenv("QUERY_TIMEOUT", "120"))
    # Blocks between weight updates
    WEIGHT_UPDATE_INTERVAL: int = 100

    def __init__(self, config=None):
        super().__init__(config=config)
        self.corpora   = self._load_corpora()
        self.scores    = torch.zeros(self.metagraph.n)
        self.step      = 0

    # -----------------------------------------------------------------------
    # Corpora
    # -----------------------------------------------------------------------

    def _load_corpora(self) -> List[dict]:
        """
        Load task definitions from the corpora directory.
        Each task is a JSON file describing a skill bundle + ground truth verdict.
        """
        tasks = []
        families = ["known_bad", "known_good", "near_miss", "adversarial"]

        for family in families:
            family_dir = CORPORA_DIR / family
            if not family_dir.exists():
                bt.logging.warning(f"Corpora family missing: {family}")
                continue
            for task_file in family_dir.glob("*.json"):
                try:
                    with open(task_file) as f:
                        task = json.load(f)
                    task["_family"] = family
                    task["_path"]   = str(task_file)
                    tasks.append(task)
                except Exception as e:
                    bt.logging.warning(f"Failed to load task {task_file}: {e}")

        bt.logging.info(f"Loaded {len(tasks)} tasks from {len(families)} corpora families")
        return tasks

    def _sample_tasks(self, n: int) -> List[dict]:
        """
        Sample n tasks with stratified sampling across families.
        Always include at least one canary equivalent (adversarial task).
        """
        if not self.corpora:
            bt.logging.error("No tasks loaded from corpora — cannot score miners")
            return []

        by_family = {}
        for task in self.corpora:
            by_family.setdefault(task["_family"], []).append(task)

        sampled = []
        per_family = max(1, n // len(by_family))
        for family, tasks in by_family.items():
            sampled.extend(random.sample(tasks, min(per_family, len(tasks))))

        # Shuffle and trim to n
        random.shuffle(sampled)
        return sampled[:n]

    # -----------------------------------------------------------------------
    # Scoring round
    # -----------------------------------------------------------------------

    async def forward(self):
        """
        Main validator loop — one scoring round.
        Called each epoch.
        """
        tasks = self._sample_tasks(self.TASKS_PER_ROUND)
        if not tasks:
            return

        # Get all miner UIDs with active axons
        miner_uids = self._get_active_miner_uids()
        if not miner_uids:
            bt.logging.warning("No active miners found on metagraph")
            return

        bt.logging.info(
            f"Scoring round | miners={len(miner_uids)} tasks={len(tasks)}"
        )

        # Accumulate per-miner scores across all tasks
        miner_scores = {uid: [] for uid in miner_uids}

        for task in tasks:
            synapse = self._task_to_synapse(task)
            responses = await self._query_miners(miner_uids, synapse)

            for uid, response in zip(miner_uids, responses):
                score = self._score_response(response, task)
                miner_scores[uid].append(score)
                bt.logging.debug(
                    f"  UID {uid} | task={task.get('name','?')} | score={score:.3f}"
                )

        # Average across tasks, update running score with EMA
        new_scores = torch.zeros(self.metagraph.n)
        for uid, task_scores in miner_scores.items():
            if task_scores:
                new_scores[uid] = float(np.mean(task_scores))

        alpha = 0.1  # EMA decay — smooth out single-round variance
        self.scores = alpha * new_scores + (1 - alpha) * self.scores

        bt.logging.info(
            f"Round complete | top miner score: {self.scores.max().item():.3f}"
        )

    # -----------------------------------------------------------------------
    # Miner querying
    # -----------------------------------------------------------------------

    def _get_active_miner_uids(self) -> List[int]:
        """Return UIDs of miners that have registered axons."""
        return [
            uid for uid, axon in enumerate(self.metagraph.axons)
            if axon.ip != "0.0.0.0"
            and not self.metagraph.validator_permit[uid]
        ]

    async def _query_miners(
        self, uids: List[int], synapse: PhylaxSynapse
    ) -> List[Optional[PhylaxSynapse]]:
        """
        Send the synapse to all miners and collect responses.
        Returns None for miners that time out or return errors.
        """
        axons = [self.metagraph.axons[uid] for uid in uids]
        responses = await self.dendrite(
            axons=axons,
            synapse=synapse,
            deserialize=False,
            timeout=self.QUERY_TIMEOUT,
        )
        return responses

    def _task_to_synapse(self, task: dict) -> PhylaxSynapse:
        """Convert a corpora task dict into a PhylaxSynapse."""
        bundle = SkillBundle(
            bundle_hash=task["bundle_hash"],
            bundle_url=task.get("bundle_url"),
            metadata=task.get("metadata", {}),
            test_profile=TestProfile(task.get("test_profile", "standard")),
        )
        return PhylaxSynapse(skill_bundle=bundle)

    # -----------------------------------------------------------------------
    # Scoring
    # -----------------------------------------------------------------------

    def _score_response(
        self, response: Optional[PhylaxSynapse], task: dict
    ) -> float:
        """
        Score a single miner response against the task's ground truth.
        Returns 0.0 for null/error/unparseable responses.
        """
        if response is None or not response.is_valid_response():
            bt.logging.debug("  → Invalid/null response → score 0.0")
            return 0.0

        try:
            sssa = response.get_sssa()
            axis_scores = score_all_axes(sssa, task)
            total = compute_total_score(axis_scores)
            return total
        except Exception as e:
            bt.logging.warning(f"Scoring error: {e}")
            return 0.0

    # -----------------------------------------------------------------------
    # Weight setting
    # -----------------------------------------------------------------------

    def set_weights(self):
        """
        Push current miner scores as weights to the Bittensor chain.
        Called every WEIGHT_UPDATE_INTERVAL blocks.
        """
        weights = self.scores.clone()

        # Normalise to [0, 1]
        w_sum = weights.sum()
        if w_sum > 0:
            weights = weights / w_sum
        else:
            weights = torch.ones(self.metagraph.n) / self.metagraph.n

        bt.logging.info(f"Setting weights | non-zero: {(weights > 0).sum().item()}")

        result, msg = self.subtensor.set_weights(
            netuid=self.config.netuid,
            wallet=self.wallet,
            uids=torch.arange(self.metagraph.n),
            weights=weights,
            wait_for_inclusion=False,
        )

        if result:
            bt.logging.success("Weights set successfully")
        else:
            bt.logging.warning(f"Failed to set weights: {msg}")

    # -----------------------------------------------------------------------
    # Run loop
    # -----------------------------------------------------------------------

    def run(self):
        bt.logging.info(
            f"Starting Phylax validator on subnet {self.config.netuid} "
            f"| hotkey: {self.wallet.hotkey.ss58_address}"
        )

        last_weight_block = 0

        while not self.should_exit:
            try:
                # Sync metagraph
                self.metagraph.sync(subtensor=self.subtensor)

                # Run a scoring round
                asyncio.run(self.forward())

                # Periodically push weights on-chain
                current_block = self.subtensor.get_current_block()
                if current_block - last_weight_block >= self.WEIGHT_UPDATE_INTERVAL:
                    self.set_weights()
                    last_weight_block = current_block

                self.step += 1
                time.sleep(12)  # one block

            except KeyboardInterrupt:
                bt.logging.info("Validator stopped by KeyboardInterrupt")
                break
            except Exception as e:
                bt.logging.error(f"Run loop error: {e}")
                bt.logging.debug(traceback.format_exc())
                time.sleep(12)


def main():
    validator = PhylaxValidator()
    validator.run()


if __name__ == "__main__":
    main()
