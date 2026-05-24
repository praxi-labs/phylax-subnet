from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import time
import traceback
import uuid
from pathlib import Path

import bittensor as bt
import torch

from phylax.attestation import (
    ValidatorCountersigner,
    VerificationResult,
    verify_attestation,
)
from phylax.protocol import SSSA, PhylaxSynapse, SkillBundle, TestProfile
from phylax.scoring import (
    aggregate_epoch,
    compute_total_score,
    round_median_latency,
    score_all_axes,
)
from phylax.server_client import (
    PhylaxServerClient,
    ServerIdentityMismatch,
    ServerUnreachable,
)
from phylax.utils.logging import get_logger
from phylax.validator.baseline import BaselineRunner, GroundTruth
from phylax.validator.consensus import ConsensusAggregator, MinerSubmission
from phylax.validator.corpus import CorpusLoader, CorpusTask
from phylax.validator.registry import AttestationRegistry
from phylax.validator.synth import SyntheticGenerator

logger = get_logger(__name__)

CORPORA_DIR = Path(__file__).parent.parent / "corpora"
DEFAULT_REGISTRY_PATH = Path(__file__).parent.parent / "phylax_registry.sqlite3"


def _metagraph_size(metagraph) -> int:
    """Return neuron count as a Python int. bittensor 10.x's metagraph.n can be
    a multi-element tensor (especially when sync hasn't populated it yet),
    which breaks a naive int() cast."""
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
    """Phylax validator neuron."""

    neuron_type: str = "ValidatorNeuron"

    TASKS_PER_ROUND: int = int(os.getenv("TASKS_PER_ROUND", "8"))
    SYNTHETIC_TASKS_PER_ROUND: int = int(os.getenv("SYNTHETIC_TASKS_PER_ROUND", "2"))
    QUERY_TIMEOUT: int = int(os.getenv("QUERY_TIMEOUT", "180"))
    WEIGHT_UPDATE_INTERVAL: int = int(os.getenv("WEIGHT_UPDATE_INTERVAL", "100"))
    EMA_ALPHA: float = float(os.getenv("EMA_ALPHA", "0.2"))

    def __init__(self, config=None, wallet=None, subtensor=None):
        # bt.BaseNeuron does not exist in the bittensor SDK (9.x or 10.x);
        # it's a subnet-template concept. We wire everything up ourselves
        # from the wallet/subtensor main() built (which already resolved
        # --subtensor.network correctly).
        self.config = config
        if callable(bt.logging):
            bt.logging(config=config)
        elif hasattr(bt.logging, "set_config"):
            bt.logging.set_config(config)
        self.wallet = wallet if wallet is not None else bt.Wallet(config=config)
        self.subtensor = subtensor if subtensor is not None else bt.Subtensor(config=config)
        self.metagraph = self.subtensor.metagraph(netuid=config.netuid)
        self.dendrite = bt.Dendrite(wallet=self.wallet)
        self.should_exit = False
        self.corpus = CorpusLoader(CORPORA_DIR).load()
        for err in self.corpus.errors:
            bt.logging.warning(f"corpus: {err}")

        self.baseline = BaselineRunner(
            sandbox_image=os.getenv("PHYLAX_SANDBOX_IMAGE", "phylax-sandbox:latest"),
            sandbox_timeout_seconds=int(os.getenv("SANDBOX_TIMEOUT", "120")),
        )
        self.synth = SyntheticGenerator()
        self.consensus = ConsensusAggregator()
        self.registry = AttestationRegistry(
            os.getenv("PHYLAX_REGISTRY_PATH", str(DEFAULT_REGISTRY_PATH))
        )
        self.countersigner: ValidatorCountersigner | None = None
        if hasattr(self, "wallet") and self.wallet is not None:
            self.countersigner = ValidatorCountersigner(wallet=self.wallet)

        n = _metagraph_size(getattr(self, "metagraph", None))
        self.scores = torch.zeros(n)
        self.step = 0

        # phylax-server integration (control plane)
        server_url = os.getenv("PHYLAX_SERVER_URL", "")
        expected_server_hotkey = os.getenv("PHYLAX_SERVER_HOTKEY", "").strip() or None
        self.server_client: PhylaxServerClient | None = None
        if server_url and hasattr(self, "wallet") and self.wallet is not None:
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
                    f"phylax-server registration failed: {e} — set_weights will be blocked "
                    f"until this succeeds"
                )
        else:
            bt.logging.warning(
                "PHYLAX_SERVER_URL not configured — validator will not be able to set_weights"
            )

        # Offline fallback policy:
        #   PHYLAX_OFFLINE_FALLBACK=true   → keep scoring miners on local corpus
        #                                     when the server is unreachable.
        #                                     Weight pushes are still blocked
        #                                     because no fresh attestation is
        #                                     obtainable.
        #   PHYLAX_OFFLINE_FALLBACK=false  → skip the round entirely.
        # Default is FALSE because the whole point of phylax-server is
        # consistent task allocation across validators; running on local
        # corpus drifts your scoring away from the consensus.
        self.allow_offline_fallback = (
            os.getenv("PHYLAX_OFFLINE_FALLBACK", "false").lower() == "true"
        )

        # Track the latest server-owned round so set_weights can request an
        # attestation against it. Reset to None whenever a round runs offline.
        self.last_completed_round_id: str | None = None

    # ------------------------------------------------------------------
    # Round driver
    # ------------------------------------------------------------------

    async def run_round(self) -> None:
        miner_uids = self._get_active_miner_uids()
        if not miner_uids:
            bt.logging.warning("no active miners on metagraph")
            return

        # ---- 1. Curated tasks: phylax-server is the source of truth ----
        round_id, corpus_tasks, server_owned_round = await self._fetch_curated_batch()
        if round_id is None:
            return  # offline-fallback disabled; nothing to do this round

        # ---- 2. Synthetic tasks: always validator-local (hybrid decision) ----
        synth_skills = [self.synth.generate() for _ in range(self.SYNTHETIC_TASKS_PER_ROUND)]

        bt.logging.info(
            f"round {round_id[:8]} | miners={len(miner_uids)} "
            f"server_curated={len(corpus_tasks)} local_synth={len(synth_skills)} "
            f"server_owned={server_owned_round}"
        )

        per_uid_task_scores: dict[int, list[float]] = {uid: [] for uid in miner_uids}
        # Per-axis breakdown collected alongside the composite quality. Used by
        # _push_round_results so the public leaderboard shows real accuracy /
        # evidence / policy / efficiency columns instead of zeros.
        per_uid_task_axes: dict[int, list] = {uid: [] for uid in miner_uids}

        for task in corpus_tasks:
            await self._run_task_for_corpus(
                task, miner_uids, per_uid_task_scores, per_uid_task_axes,
                round_id=round_id,
            )

        for synth in synth_skills:
            await self._run_task_for_synthetic(
                synth, miner_uids, per_uid_task_scores, per_uid_task_axes,
                round_id=round_id,
            )

        # ---- 3. Aggregate epoch scores into the running EMA vector. ----
        new_scores = torch.zeros_like(self.scores)
        for uid, ts in per_uid_task_scores.items():
            new_scores[uid] = float(aggregate_epoch(ts))
        self.scores = self.EMA_ALPHA * new_scores + (1.0 - self.EMA_ALPHA) * self.scores

        top = float(self.scores.max().item()) if self.scores.numel() else 0.0
        bt.logging.info(f"round {round_id[:8]} done | top_score={top:.3f}")

        # ---- 4. Report results to phylax-server. ----
        # Only server-owned rounds qualify; offline rounds carry a synthetic
        # round_id the server doesn't recognise, and reporting them would 404.
        if server_owned_round and self.server_client is not None:
            try:
                self._push_round_results(round_id, per_uid_task_scores, per_uid_task_axes, new_scores)
                # Only mark the round as eligible for weight attestation once
                # the server has accepted the results.
                self.last_completed_round_id = round_id
            except ServerUnreachable as e:
                bt.logging.warning(
                    f"phylax-server unreachable while reporting results: {e} — "
                    f"set_weights will be blocked until next successful round"
                )
                self.last_completed_round_id = None
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"phylax-server round push failed: {e}")
                self.last_completed_round_id = None
        else:
            # Offline rounds don't grant a weight attestation.
            self.last_completed_round_id = None

    # ------------------------------------------------------------------
    # Server-curated batch fetch (with offline fallback)
    # ------------------------------------------------------------------

    async def _fetch_curated_batch(self):
        """Return ``(round_id, corpus_tasks, server_owned_round)``.

        ``round_id`` is None when the round should be skipped entirely.
        """
        if self.server_client is not None:
            try:
                batch = await asyncio.to_thread(
                    self.server_client.fetch_task_batch,
                    self.TASKS_PER_ROUND,
                    include_canaries=True,
                )
                tasks = [self._server_task_to_corpus_task(t) for t in batch.get("tasks", [])]
                return batch["round_id"], tasks, True
            except ServerUnreachable as e:
                bt.logging.warning(f"phylax-server unreachable for task batch: {e}")
            except ServerIdentityMismatch as e:
                # This is a hard fail — refuse to proceed.
                bt.logging.error(f"phylax-server identity mismatch: {e}; skipping round")
                return None, [], False
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"phylax-server task fetch failed: {e}")

        # Server unreachable / not configured.
        if not self.allow_offline_fallback:
            bt.logging.error(
                "phylax-server task fetch failed and PHYLAX_OFFLINE_FALLBACK=false — skipping round"
            )
            return None, [], False

        bt.logging.warning(
            "running OFFLINE round from local corpus (set_weights will be blocked)"
        )
        local_tasks = self.corpus.sample_stratified(self.TASKS_PER_ROUND)
        return f"offline-{uuid.uuid4().hex}", local_tasks, False

    @staticmethod
    def _server_task_to_corpus_task(server_task: dict) -> CorpusTask:
        """Adapt a phylax-server TaskItem payload into the validator's CorpusTask shape."""
        bundle_hash = server_task["bundle_hash"]
        return CorpusTask(
            name=server_task.get("name", "unnamed"),
            family=server_task.get("family", "known_good"),
            path=f"server://{bundle_hash}",
            bundle_hash=bundle_hash,
            bundle_url=server_task.get("bundle_url"),
            bundle_bytes_b64=server_task.get("bundle_bytes_b64"),
            metadata=server_task.get("metadata") or {},
            test_profile=server_task.get("test_profile", "standard"),
            expected_verdict=server_task.get("expected_verdict") or "ALLOW",
            expected_risk_score=(
                int(server_task["expected_risk_score"])
                if server_task.get("expected_risk_score") is not None
                else None
            ),
            expected_capabilities=server_task.get("expected_capabilities") or {},
            expected_policy=server_task.get("expected_policy") or {},
            expected_findings=server_task.get("expected_findings") or [],
            tags=server_task.get("tags") or [],
        )

    # ------------------------------------------------------------------
    # Server round-results push
    # ------------------------------------------------------------------

    def _push_round_results(
        self,
        round_id: str,
        per_uid_task_scores: dict[int, list[float]],
        per_uid_task_axes: dict[int, list],
        new_scores,
    ) -> None:
        """Submit per-miner scores to /v1/rounds/{round_id}/results."""
        assert self.server_client is not None

        def _axis_mean(axes_list, attr: str) -> float:
            if not axes_list:
                return 0.0
            return float(sum(getattr(a, attr) for a in axes_list) / len(axes_list))

        miner_scores_payload = []
        for uid in per_uid_task_scores:
            axes = per_uid_task_axes.get(uid, [])
            miner_scores_payload.append(
                {
                    "miner_uid": int(uid),
                    "miner_hotkey": self.metagraph.hotkeys[uid]
                    if uid < len(self.metagraph.hotkeys)
                    else "",
                    "bundle_hash": "sha256:" + "0" * 64,
                    "quality_score": float(new_scores[uid].item()),
                    "detection_score": _axis_mean(axes, "detection"),
                    "evidence_score": _axis_mean(axes, "evidence"),
                    "policy_score": _axis_mean(axes, "policy"),
                    "efficiency_score": _axis_mean(axes, "efficiency"),
                    "submission_latency_ms": 0,
                    "verdict": "ALLOW",
                    "risk_score": 0,
                }
            )
        self.server_client.submit_round_results(
            round_id=round_id, miner_scores=miner_scores_payload
        )

    # ------------------------------------------------------------------
    # Per-task drivers
    # ------------------------------------------------------------------

    async def _run_task_for_corpus(
        self,
        task: CorpusTask,
        miner_uids: list[int],
        per_uid_task_scores: dict[int, list[float]],
        per_uid_task_axes: dict[int, list],
        *,
        round_id: str,
    ) -> None:
        # Validator baseline: where possible, compute fresh GT under each
        # miner's nonce. For corpus tasks without retrievable bytes we fall
        # back to the corpus-authored labels (no evidence GT available).
        task_dict = task.as_scoring_dict()

        responses = await self._query_miners_per_nonce(miner_uids, task)
        latencies = [r.submission_latency_ms for r in responses if r is not None]
        median_latency = round_median_latency(latencies)

        for resp in responses:
            uid = resp.uid
            if not resp.ok:
                per_uid_task_scores[uid].append(0.0)
                continue

            evaluation_task = dict(task_dict)
            evaluation_task["submission_latency_ms"] = resp.submission_latency_ms
            evaluation_task["median_latency_ms"] = median_latency

            gt = await self._baseline_for_corpus_task(task, resp.nonce)
            if gt is not None:
                evaluation_task.update(gt.as_task_dict())

            axes = score_all_axes(resp.sssa, evaluation_task)
            quality = compute_total_score(axes)
            per_uid_task_scores[uid].append(quality)
            per_uid_task_axes[uid].append(axes)
            resp.quality = quality

        await self._consense_and_publish(task_dict, responses, round_id=round_id)

    async def _run_task_for_synthetic(
        self,
        synth_skill,
        miner_uids: list[int],
        per_uid_task_scores: dict[int, list[float]],
        per_uid_task_axes: dict[int, list],
        *,
        round_id: str,
    ) -> None:
        bundle = SkillBundle(
            bundle_hash=synth_skill.bundle_hash,
            bundle_bytes=synth_skill.bundle_bytes,
            metadata=synth_skill.task.get("metadata", {}),
            test_profile=TestProfile(synth_skill.task.get("test_profile", "standard")),
        )
        task_dict = dict(synth_skill.task)
        task_dict["_family"] = "synthetic"
        task_dict["_path"] = "synth://" + synth_skill.name
        task_dict["test_profile"] = bundle.test_profile.value

        responses = await self._query_miners_per_nonce(miner_uids, _SyntheticTaskAdapter(bundle, task_dict))
        latencies = [r.submission_latency_ms for r in responses if r is not None]
        median_latency = round_median_latency(latencies)

        for resp in responses:
            uid = resp.uid
            if not resp.ok:
                per_uid_task_scores[uid].append(0.0)
                continue
            evaluation_task = dict(task_dict)
            evaluation_task["submission_latency_ms"] = resp.submission_latency_ms
            evaluation_task["median_latency_ms"] = median_latency

            gt = await asyncio.to_thread(
                self.baseline.run_from_bytes, synth_skill.bundle_bytes, resp.nonce
            )
            evaluation_task.update(gt.as_task_dict())

            axes = score_all_axes(resp.sssa, evaluation_task)
            quality = compute_total_score(axes)
            per_uid_task_scores[uid].append(quality)
            per_uid_task_axes[uid].append(axes)
            resp.quality = quality

        await self._consense_and_publish(task_dict, responses, round_id=round_id)

    # ------------------------------------------------------------------
    # Querying with per-miner nonces
    # ------------------------------------------------------------------

    async def _query_miners_per_nonce(
        self,
        miner_uids: list[int],
        task,
    ) -> list[MinerResponse]:
        """One synapse per miner, each with its own nonce. Returns ordered list."""

        if hasattr(task, "_synapse_bundle"):
            bundle = task._synapse_bundle  # type: ignore[attr-defined]
        else:
            ct: CorpusTask = task
            bundle = SkillBundle(
                bundle_hash=ct.bundle_hash,
                bundle_url=ct.bundle_url,
                metadata=ct.metadata,
                test_profile=TestProfile(ct.test_profile),
            )

        deadline_unix = time.time() + self.QUERY_TIMEOUT
        round_id = uuid.uuid4().hex

        async def query_one(uid: int) -> MinerResponse:
            axon = self.metagraph.axons[uid]
            nonce = secrets.randbits(63)
            synapse = PhylaxSynapse(
                skill_bundle=bundle,
                nonce=nonce,
                round_id=round_id,
                deadline_unix=deadline_unix,
            )
            sent_at = time.time()
            try:
                resp = await self.dendrite(
                    axons=[axon],
                    synapse=synapse,
                    deserialize=False,
                    timeout=self.QUERY_TIMEOUT,
                )
                returned = resp[0] if isinstance(resp, list) else resp
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"uid {uid}: dendrite error: {e}")
                return MinerResponse(uid=uid, nonce=nonce, ok=False, reason=str(e))

            latency_ms = int((time.time() - sent_at) * 1000)
            if returned is None or not returned.is_valid_response():
                return MinerResponse(uid=uid, nonce=nonce, ok=False, reason="invalid response")

            sssa = returned.get_sssa()
            if sssa is None or sssa.attestation is None:
                return MinerResponse(uid=uid, nonce=nonce, ok=False, reason="missing attestation")

            # Signature + identity check
            v = verify_attestation(sssa, local_bundle_hash=bundle.bundle_hash)
            if not v.ok:
                return MinerResponse(uid=uid, nonce=nonce, ok=False, reason=f"verify: {v.reason}")

            hotkey = self.metagraph.hotkeys[uid] if uid < len(self.metagraph.hotkeys) else None
            if hotkey and sssa.attestation.miner_hotkey != hotkey:
                return MinerResponse(uid=uid, nonce=nonce, ok=False, reason="hotkey mismatch")

            return MinerResponse(
                uid=uid,
                nonce=nonce,
                ok=True,
                sssa=sssa,
                submission_latency_ms=latency_ms,
                verification=v,
            )

        return await asyncio.gather(*(query_one(u) for u in miner_uids))

    # ------------------------------------------------------------------
    # Baseline + GT
    # ------------------------------------------------------------------

    async def _baseline_for_corpus_task(
        self, task: CorpusTask, nonce: int
    ) -> GroundTruth | None:
        """Run validator baseline if bundle bytes are retrievable."""
        bundle_bytes = await self._fetch_bundle_bytes(task)
        if not bundle_bytes:
            return None
        try:
            return await asyncio.to_thread(self.baseline.run_from_bytes, bundle_bytes, nonce)
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"baseline error for {task.name}: {e}")
            return None

    async def _fetch_bundle_bytes(self, task: CorpusTask) -> bytes | None:
        if task.bundle_bytes_b64:
            import base64

            try:
                return base64.b64decode(task.bundle_bytes_b64)
            except Exception:  # noqa: BLE001
                return None
        if task.bundle_url:
            # Defense-in-depth against a compromised server feeding us a URL
            # that points at cloud-metadata or LAN services. ``safe_get_bytes``
            # rejects private-IP hosts on the initial request and on every
            # redirect, and caps body size.
            from phylax.utils.safe_http import safe_get_bytes

            return await asyncio.to_thread(safe_get_bytes, task.bundle_url)
        return None

    # ------------------------------------------------------------------
    # Consensus + registry
    # ------------------------------------------------------------------

    async def _consense_and_publish(
        self,
        task_dict: dict,
        responses: list[MinerResponse],
        *,
        round_id: str,
    ) -> None:
        submissions: list[MinerSubmission] = []
        for r in responses:
            if not r.ok or r.sssa is None:
                continue
            hotkey = (
                self.metagraph.hotkeys[r.uid]
                if r.uid < len(self.metagraph.hotkeys)
                else r.sssa.attestation.miner_hotkey
            )
            submissions.append(
                MinerSubmission(
                    uid=r.uid,
                    hotkey=hotkey,
                    sssa=r.sssa,
                    quality_score=r.quality,
                    submission_latency_ms=r.submission_latency_ms,
                )
            )

        result = self.consensus.aggregate(submissions)
        if result is None or result.winning_submission is None:
            return

        sssa = result.winning_submission.sssa
        if self.countersigner is not None:
            try:
                sssa = self.countersigner.countersign(
                    sssa, round_id=round_id, quality_score=result.quality_score
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"countersign failed: {e}")

        try:
            self.registry.put(sssa, round_id=round_id, quality_score=result.quality_score)
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"registry write failed: {e}")

        # Push the consensus SSSA to phylax-server, which picks the
        # cross-validator canonical one for the public registry.
        if self.server_client is not None and not round_id.startswith("offline-"):
            try:
                sssa_payload = sssa.model_dump(mode="json")
                await asyncio.to_thread(
                    self.server_client.push_attestation,
                    bundle_hash=sssa.skill.bundle_hash,
                    sssa=sssa_payload,
                    quality_score=float(result.quality_score),
                    round_id=round_id,
                )
            except ServerUnreachable as e:
                bt.logging.debug(f"server attestation push skipped (unreachable): {e}")
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"server attestation push failed: {e}")

    # ------------------------------------------------------------------
    # Metagraph + weights
    # ------------------------------------------------------------------

    def _get_active_miner_uids(self) -> list[int]:
        out: list[int] = []
        for uid, axon in enumerate(self.metagraph.axons):
            if axon.ip == "0.0.0.0":
                continue
            if self.metagraph.validator_permit[uid]:
                continue
            out.append(uid)
        return out

    def set_weights(self) -> None:
        """Push current scores on-chain — gated by a phylax-server weight attestation.

        The canonical validator software refuses to call
        ``subtensor.set_weights`` without a fresh, valid WeightAttestation
        from phylax-server. If the server is unreachable or has revoked
        this validator, the call is aborted before it touches the chain.
        Operators running modified validator code can bypass this — that's
        a chain-level concern (see docs/chain-level-controls.md).
        """
        if self.scores.sum().item() <= 0.0:
            bt.logging.info("set_weights: all-zero scores; skipping")
            return
        weights = self.scores.clone()
        weights = weights / weights.sum()
        bt.logging.info(f"set_weights | non-zero={int((weights > 0).sum().item())}")

        # Pre-flight: weight attestation from phylax-server
        server_client = getattr(self, "server_client", None)
        last_round_id = getattr(self, "last_completed_round_id", None)
        if server_client is None:
            bt.logging.error(
                "set_weights: phylax-server client not initialised; refusing to push weights"
            )
            return
        if last_round_id is None:
            bt.logging.warning(
                "set_weights: no completed round to attest to; skipping this push"
            )
            return

        weights_dict = {int(uid): float(w) for uid, w in enumerate(weights.tolist()) if w > 0.0}
        try:
            attestation = server_client.request_and_verify_weight_attestation(
                last_round_id, weights_dict
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.error(f"set_weights: weight attestation request failed: {e}")
            return
        if attestation is None:
            bt.logging.error(
                "set_weights: phylax-server refused to issue a weight attestation; "
                "operator likely de-allowlisted or weights inconsistent with reported round"
            )
            return

        bt.logging.info(
            f"set_weights | attestation {attestation.attestation_id[:8]} "
            f"expires {attestation.expires_at}"
        )

        try:
            result, msg = self.subtensor.set_weights(
                netuid=self.config.netuid,
                wallet=self.wallet,
                uids=torch.arange(_metagraph_size(self.metagraph)),
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

    # ------------------------------------------------------------------
    # Run loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        bt.logging.info(
            f"starting Phylax validator on netuid={self.config.netuid} "
            f"hotkey={self.wallet.hotkey.ss58_address}"
        )
        # Single persistent event loop across rounds. asyncio.run() per
        # iteration would close the loop each time, and bittensor's
        # dendrite caches an aiohttp ClientSession bound to whichever
        # loop was alive at first use — subsequent rounds then crash
        # with "Event loop is closed" on every query.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        last_weight_block = 0
        try:
            while not getattr(self, "should_exit", False):
                try:
                    self.metagraph.sync(subtensor=self.subtensor)
                    # Re-init countersigner if wallet was just set on first iteration.
                    if self.countersigner is None and hasattr(self, "wallet"):
                        self.countersigner = ValidatorCountersigner(wallet=self.wallet)
                    mg_n = _metagraph_size(self.metagraph)
                    if self.scores.numel() != mg_n:
                        new = torch.zeros(mg_n)
                        n = min(new.numel(), self.scores.numel())
                        new[:n] = self.scores[:n]
                        self.scores = new

                    loop.run_until_complete(self.run_round())

                    current_block = self.subtensor.get_current_block()
                    if current_block - last_weight_block >= self.WEIGHT_UPDATE_INTERVAL:
                        self.set_weights()
                        last_weight_block = current_block

                    self.step += 1
                    time.sleep(12)

                except KeyboardInterrupt:
                    bt.logging.info("validator stopped by KeyboardInterrupt")
                    break
                except Exception as e:  # noqa: BLE001
                    bt.logging.error(f"run loop error: {e}")
                    bt.logging.debug(traceback.format_exc())
                    time.sleep(12)
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MinerResponse:
    __slots__ = ("uid", "nonce", "ok", "sssa", "submission_latency_ms", "quality", "reason", "verification")

    def __init__(
        self,
        *,
        uid: int,
        nonce: int,
        ok: bool,
        sssa: SSSA | None = None,
        submission_latency_ms: int = 0,
        reason: str = "",
        verification: VerificationResult | None = None,
    ):
        self.uid = uid
        self.nonce = nonce
        self.ok = ok
        self.sssa = sssa
        self.submission_latency_ms = submission_latency_ms
        self.quality = 0.0
        self.reason = reason
        self.verification = verification


class _SyntheticTaskAdapter:
    """Lightweight task wrapper used to feed synthetic skills through the same
    query path the corpus tasks use."""

    def __init__(self, bundle: SkillBundle, task_dict: dict):
        self._synapse_bundle = bundle
        self.task_dict = task_dict


_NETWORK_ENDPOINTS = {
    "finney":  "wss://entrypoint-finney.opentensor.ai:443",
    "test":    "wss://test.finney.opentensor.ai:443",
    "archive": "wss://archive.chain.opentensor.ai:443",
    "local":   "ws://127.0.0.1:9944",
}


def _resolve_endpoint(network: str | None) -> str:
    """Resolve a bittensor network name to its WebSocket endpoint.

    bittensor 9.x's bt.Subtensor(network=...) and bt.Subtensor(config=...)
    both honour config.subtensor.chain_endpoint whose default is the
    mainnet finney URL — so passing network='test' silently ends up on
    finney. Bypass that magic by translating the known names ourselves
    and handing bt.Subtensor a chain_endpoint directly. If `network` is
    already a ws:// or wss:// URL, use it as-is.
    """
    if not network:
        return _NETWORK_ENDPOINTS["finney"]
    if network.startswith(("ws://", "wss://")):
        return network
    return _NETWORK_ENDPOINTS.get(network, _NETWORK_ENDPOINTS["finney"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Phylax validator neuron")
    parser.add_argument("--netuid", type=int, required=True,
                        help="Subnet netuid to validate on")
    bt.Wallet.add_args(parser)
    bt.Subtensor.add_args(parser)
    bt.logging.add_args(parser)
    config = bt.Config(parser)
    # The CLI default for --subtensor.chain_endpoint is the mainnet URL,
    # and chain_endpoint wins over network inside bt.Subtensor. Overwrite
    # it from the network name so --subtensor.network test actually lands
    # on the test chain.
    config.subtensor.chain_endpoint = _resolve_endpoint(config.subtensor.network)
    wallet = bt.Wallet(config=config)
    subtensor = bt.Subtensor(config=config)
    validator = PhylaxValidator(config=config, wallet=wallet, subtensor=subtensor)
    validator.run()


if __name__ == "__main__":
    main()
