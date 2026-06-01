from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import time
import traceback
import uuid

import bittensor as bt
import torch

from phylax.protocol import (
    SSSA,
    BundleMetadata,
    InferenceConfig,
    LLMAllowedUse,
    PhylaxSynapse,
    SkillBundle,
    SkillType,
    TaskMetadata,
    TaskType,
    TestProfile,
    Verdict,
)
from phylax.scoring import (
    TaskContext,
    classify_tier,
    compute_Q,
    compute_task_emissions_score,
    score_all_axes,
)
from phylax.server_client import (
    PhylaxServerClient,
    ServerIdentityMismatch,
    ServerUnreachable,
)
from phylax.utils.logging import get_logger

logger = get_logger(__name__)


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

    TASKS_PER_ROUND: int = int(os.getenv("TASKS_PER_ROUND", "8"))
    QUERY_TIMEOUT: int = int(os.getenv("QUERY_TIMEOUT", "150"))
    WEIGHT_UPDATE_INTERVAL: int = int(os.getenv("WEIGHT_UPDATE_INTERVAL", "100"))
    EMA_ALPHA: float = float(os.getenv("EMA_ALPHA", "0.2"))
    THRESHOLD_CACHE_TTL_S: int = 300

    def __init__(self, config=None, wallet=None, subtensor=None):
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

        n = _metagraph_size(self.metagraph)
        self.scores = torch.zeros(n)
        self.step = 0
        self.last_completed_round_id: str | None = None

        self._threshold_cache: dict[str, float] = {}
        self._threshold_cached_at: float = 0.0

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
                    f"phylax-server registration failed: {e} — set_weights will be blocked "
                    f"until this succeeds"
                )
        else:
            bt.logging.warning(
                "PHYLAX_SERVER_URL not configured — validator will not be able to set_weights"
            )

    async def run_round(self) -> None:
        if self.server_client is None:
            bt.logging.warning("no server client; skipping round")
            return

        try:
            batch = await asyncio.to_thread(
                self.server_client.fetch_task_batch,
                self.TASKS_PER_ROUND,
                include_canaries=True,
            )
        except ServerUnreachable as e:
            bt.logging.warning(f"phylax-server unreachable for task batch: {e}")
            return
        except ServerIdentityMismatch as e:
            bt.logging.error(f"phylax-server identity mismatch: {e}; skipping round")
            return
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"phylax-server task fetch failed: {e}")
            return

        tasks = batch.get("tasks", []) or []
        round_id = batch.get("round_id") or uuid.uuid4().hex
        if not tasks:
            bt.logging.info(f"round {round_id[:8]}: server returned no tasks")
            return

        bt.logging.info(
            f"round {round_id[:8]} | metagraph_n={_metagraph_size(self.metagraph)} "
            f"tasks={len(tasks)}"
        )

        per_uid_q: dict[int, list[float]] = {}
        per_miner_payload: list[dict] = []

        for task in tasks:
            raw_type = task.get("skill_type") or task.get("metadata", {}).get("skill_type")
            if raw_type not in {t.value for t in SkillType}:
                bt.logging.debug(f"round {round_id[:8]}: unknown skill_type={raw_type!r}; skipping")
                continue
            skill_type = SkillType(raw_type)
            miners = await self._route_miners_for_skill_type(skill_type)
            if not miners:
                bt.logging.info(
                    f"round {round_id[:8]} {skill_type.value}: no routed miners"
                )
                continue
            bundle = self._bundle_from_task(task, skill_type)
            ctx = self._task_context(task, skill_type)

            for hotkey, uid in miners:
                resp = await self._dial_miner(uid, bundle, task, skill_type)
                if resp is None or resp.error or resp.attestation is None:
                    continue
                try:
                    sssa = SSSA(**resp.attestation)
                except Exception as e:  # noqa: BLE001
                    bt.logging.warning(f"SSSA parse failed for uid={uid}: {e}")
                    continue
                ctx.submission_latency_ms = getattr(resp, "latency_ms", 0)
                axes = score_all_axes(sssa, ctx)
                q = compute_Q(axes, skill_type)
                threshold = self._novel_thresholds().get(skill_type.value, 0.6)
                tier = classify_tier(q, skill_type, threshold)
                emission = compute_task_emissions_score(q, skill_type, tier)
                per_uid_q.setdefault(uid, []).append(q)
                per_miner_payload.append(
                    {
                        "miner_uid": int(uid),
                        "miner_hotkey": hotkey,
                        "bundle_hash": bundle.bundle_hash,
                        "skill_type": skill_type.value,
                        "composite_q": float(q),
                        "tier": tier.value,
                        "emission_score": float(emission),
                        "verdict": sssa.verdict.decision.value,
                        "risk_score": int(sssa.verdict.risk_score),
                        "submission_latency_ms": int(getattr(resp, "latency_ms", 0)),
                    }
                )
                bt.logging.info(
                    f"{skill_type.value} hk={hotkey[:10]} Q={q:.3f} "
                    f"tier={tier.value} emission={emission:.3f}"
                )

        if not per_uid_q:
            bt.logging.info(f"round {round_id[:8]} produced no scores; not publishing")
            return

        new_scores = torch.zeros_like(self.scores)
        for uid, qs in per_uid_q.items():
            if uid < new_scores.numel():
                new_scores[uid] = float(sum(qs) / len(qs))

        reputation = self._fetch_miner_reputation()
        if reputation:
            for uid in range(min(new_scores.numel(), len(self.metagraph.hotkeys))):
                rep = reputation.get(self.metagraph.hotkeys[uid], 1.0)
                if rep < 1.0:
                    new_scores[uid] = float(new_scores[uid]) * rep

        self.scores = self.EMA_ALPHA * new_scores + (1.0 - self.EMA_ALPHA) * self.scores
        top = float(self.scores.max().item()) if self.scores.numel() else 0.0
        bt.logging.info(f"round {round_id[:8]} done | top_score={top:.3f}")

        self._publish_round_results(round_id, per_miner_payload)
        self.last_completed_round_id = round_id

    async def _route_miners_for_skill_type(
        self, skill_type: SkillType
    ) -> list[tuple[str, int]]:
        routed: list[tuple[str, int]] = []
        if self.server_client is not None:
            try:
                routing = await asyncio.to_thread(
                    self.server_client.get,
                    "/v1/specialization/routing",
                    params={"skill_type": skill_type.value},
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"routing fetch failed: {e}")
                routing = {}
            miners_payload = routing.get("miners", []) if isinstance(routing, dict) else []
            hotkey_to_uid = {h: i for i, h in enumerate(self.metagraph.hotkeys)}
            for entry in miners_payload:
                hotkey = entry.get("hotkey", "")
                uid = hotkey_to_uid.get(hotkey)
                if uid is None:
                    continue
                axon = self.metagraph.axons[uid]
                if axon.ip == "0.0.0.0":
                    continue
                routed.append((hotkey, uid))
        if routed:
            return routed
        for uid in self._get_active_miner_uids():
            if uid >= len(self.metagraph.hotkeys):
                continue
            routed.append((self.metagraph.hotkeys[uid], uid))
        return routed

    def _bundle_from_task(self, task: dict, skill_type: SkillType) -> SkillBundle:
        metadata = task.get("metadata") or {}
        profile_str = (metadata.get("profile") or metadata.get("test_profile") or "standard").lower()
        return SkillBundle(
            bundle_hash=task["bundle_hash"],
            bundle_url=task.get("bundle_url"),
            bundle_bytes=task.get("bundle_bytes"),
            metadata=BundleMetadata(
                skill_name=metadata.get("skill_name") or task.get("name") or "unknown",
                skill_version=metadata.get("skill_version") or "unknown",
                skill_type=skill_type,
                profile=TestProfile(profile_str),
                composition_depth=metadata.get("composition_depth"),
                child_skill_hashes=metadata.get("child_skill_hashes") or [],
            ),
        )

    def _task_context(self, task: dict, skill_type: SkillType) -> TaskContext:
        metadata = task.get("metadata") or {}
        expected_verdict_str = task.get("expected_verdict") or metadata.get("expected_verdict")
        expected_verdict = Verdict(expected_verdict_str) if expected_verdict_str else None
        return TaskContext(
            skill_type=skill_type,
            expected_verdict=expected_verdict,
            expected_risk=task.get("expected_risk_score") or metadata.get("expected_risk_score"),
            annotated_by=task.get("annotated_by") or metadata.get("annotated_by"),
            expected_evidence=task.get("ground_truth_evidence") or {},
            expected_policy=task.get("expected_policy") or {},
            ground_truth=task.get("ground_truth") or {},
            deadline_s=int(metadata.get("deadline_s") or metadata.get("deadline_seconds") or 150),
            t_min_s=int(metadata.get("t_min_s") or metadata.get("t_min_seconds") or 15),
        )

    async def _dial_miner(
        self, uid: int, bundle: SkillBundle, task: dict, skill_type: SkillType,
    ) -> PhylaxSynapse | None:
        axon = self.metagraph.axons[uid]
        metadata = task.get("metadata") or {}
        task_id = task.get("task_id") or uuid.uuid4().hex
        deadline_s = int(metadata.get("deadline_s") or metadata.get("deadline_seconds") or 150)
        t_min_s = int(metadata.get("t_min_s") or metadata.get("t_min_seconds") or 15)
        nonce = secrets.token_hex(16)
        synapse = PhylaxSynapse(
            skill_bundle=bundle,
            nonce=nonce,
            task_metadata=TaskMetadata(
                task_id=task_id,
                task_type=TaskType(task.get("task_type", "server_curated")),
                deadline_s=deadline_s,
                t_min_s=t_min_s,
            ),
            inference_config=InferenceConfig(
                proxy_url=task.get("inference_proxy_url"),
                allowed_models=task.get("allowed_models", []),
                allowed_uses=[
                    LLMAllowedUse.FINDING_ENRICHMENT,
                    LLMAllowedUse.MITRE_OWASP_MAPPING,
                    LLMAllowedUse.CVE_EXPLANATION,
                ],
            ),
        )
        sent_at = time.time()
        try:
            resp = await self.dendrite(
                axons=[axon],
                synapse=synapse,
                deserialize=False,
                timeout=min(deadline_s, self.QUERY_TIMEOUT),
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"uid={uid} dendrite error: {e}")
            return None
        returned = resp[0] if isinstance(resp, list) else resp
        if returned is None:
            return None
        returned.latency_ms = int((time.time() - sent_at) * 1000)
        return returned

    def _novel_thresholds(self) -> dict[str, float]:
        if self.server_client is None:
            return {}
        if self._threshold_cache and (time.time() - self._threshold_cached_at) < self.THRESHOLD_CACHE_TTL_S:
            return self._threshold_cache
        try:
            data = self.server_client.get("/v1/specialization/tier-table")
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"tier-table fetch failed: {e}")
            return self._threshold_cache
        out = (data or {}).get("novel_thresholds", {}) if isinstance(data, dict) else {}
        self._threshold_cache = out
        self._threshold_cached_at = time.time()
        return out

    def _publish_round_results(self, round_id: str, per_miner_payload: list[dict]) -> None:
        if self.server_client is None or not per_miner_payload:
            return
        try:
            self.server_client.submit_round_results(
                round_id=round_id, miner_scores=per_miner_payload,
            )
        except ServerUnreachable as e:
            bt.logging.warning(
                f"phylax-server unreachable while reporting results: {e} — "
                f"set_weights will be blocked until next successful round"
            )
            self.last_completed_round_id = None
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"round results submit failed: {e}")
            self.last_completed_round_id = None

    def _fetch_miner_reputation(self) -> dict[str, float]:
        if self.server_client is None:
            return {}
        try:
            payload = self.server_client.fetch_miner_reputation()
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"reputation fetch failed: {e}")
            return {}
        out: dict[str, float] = {}
        for entry in payload.get("miners", []) or []:
            hk = entry.get("miner_hotkey")
            rep = entry.get("reputation")
            if hk and isinstance(rep, int | float):
                out[hk] = float(rep)
        clusters = payload.get("collusion_clusters") or []
        if clusters:
            bt.logging.warning(
                f"reputation: {len(clusters)} active collusion cluster(s) "
                f"flagged by server; affected miners de-weighted"
            )
        return out

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
        if self.scores.sum().item() <= 0.0:
            bt.logging.info("set_weights: all-zero scores; skipping")
            return
        weights = self.scores.clone()
        weights = weights / weights.sum()
        bt.logging.info(f"set_weights | non-zero={int((weights > 0).sum().item())}")

        if self.server_client is None:
            bt.logging.error(
                "set_weights: phylax-server client not initialised; refusing to push weights"
            )
            return
        if self.last_completed_round_id is None:
            bt.logging.warning(
                "set_weights: no completed round to attest to; skipping this push"
            )
            return

        weights_dict = {int(uid): float(w) for uid, w in enumerate(weights.tolist()) if w > 0.0}
        try:
            attestation = self.server_client.request_and_verify_weight_attestation(
                self.last_completed_round_id, weights_dict
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

    def run(self) -> None:
        bt.logging.info(
            f"starting Phylax validator on netuid={self.config.netuid} "
            f"hotkey={self.wallet.hotkey.ss58_address}"
        )
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        last_weight_block = 0
        try:
            while not self.should_exit:
                try:
                    self.metagraph.sync(subtensor=self.subtensor, lite=False)
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
