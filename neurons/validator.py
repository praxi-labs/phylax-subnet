from __future__ import annotations

import argparse
import asyncio
import os
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
    Verdict,
)
from phylax.scoring import (
    REFERENCE_BASELINES,
    TaskContext,
    Tier,
    classify_tier,
    compute_Q,
    compute_round_score,
    recalibrate_novel_threshold,
    score_all_axes,
)
from phylax.server_client import (
    PhylaxServerClient,
    ServerIdentityMismatch,
    ServerUnreachable,
)
from phylax.utils.logging import get_logger
from phylax.validator import (
    RoundTask,
    compose_round,
    prepare_bundle,
    resolve_timing,
)

logger = get_logger(__name__)

PERMITTED_LLM_USES: set[str | None] = {
    None,
    LLMAllowedUse.FINDING_ENRICHMENT.value,
    LLMAllowedUse.MITRE_OWASP_MAPPING.value,
    LLMAllowedUse.CVE_EXPLANATION.value,
}


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

    SERVER_CURATED_PULL: int = int(os.getenv("SERVER_CURATED_PULL", "18"))
    WEIGHT_UPDATE_INTERVAL: int = int(os.getenv("WEIGHT_UPDATE_INTERVAL", "100"))
    EMA_ALPHA: float = float(os.getenv("EMA_ALPHA", "0.2"))
    THRESHOLD_CACHE_TTL_S: int = 300
    REPUTATION_CACHE_TTL_S: int = 60

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
        self.current_epoch: int = 0
        self._epoch_q_scores: dict[str, list[float]] = {}

        self._threshold_cache: dict[str, float] = {}
        self._threshold_cached_at: float = 0.0
        self._per_type_rep_cache: dict[str, dict[str, float]] = {}
        self._per_type_rep_cached_at: float = 0.0

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

        server_tasks = await self._fetch_server_tasks()
        round_tasks = compose_round(server_tasks)
        if not round_tasks:
            bt.logging.info("round produced no tasks (corpus + canary generation both empty)")
            return

        round_id = uuid.uuid4().hex
        bt.logging.info(
            f"round {round_id[:8]} | tasks={len(round_tasks)} "
            f"types={ {t.skill_type.value for t in round_tasks} }"
        )

        prepared: list[tuple[RoundTask, object]] = []
        for task in round_tasks:
            try:
                prep = await asyncio.to_thread(
                    prepare_bundle, task.skill_type, task.bundle_bytes or b"", task.metadata.get("nonce"),
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(
                    f"bundle preparation failed for {task.skill_type.value} task {task.task_id[:8]}: {e}"
                )
                continue
            prepared.append((task, prep))

        if not prepared:
            bt.logging.info(f"round {round_id[:8]}: every task failed preparation; skipping")
            return

        per_uid_results: dict[int, list[dict]] = {}
        round_results: list[dict] = []
        per_miner_payload: list[dict] = []

        for task, prep in prepared:
            miners = await self._route_miners_for_skill_type(task.skill_type)
            if not miners:
                bt.logging.info(
                    f"round {round_id[:8]} {task.skill_type.value}: no routed miners"
                )
                continue
            bundle = self._bundle_from_prepared(task, prep)
            ctx = self._task_context(task, prep)
            t_min_s, deadline_s = resolve_timing(task.skill_type, task.profile)

            for hotkey, uid in miners:
                resp = await self._dial_miner(uid, bundle, task, prep, t_min_s, deadline_s)
                if resp is None or resp.error or resp.attestation is None:
                    continue
                try:
                    sssa = SSSA(**resp.attestation)
                except Exception as e:  # noqa: BLE001
                    bt.logging.warning(f"SSSA parse failed for uid={uid}: {e}")
                    continue
                if not self._validate_sssa(sssa, task, hotkey):
                    round_results.append(self._failure_record(hotkey, task))
                    continue
                ctx.submission_latency_ms = getattr(resp, "latency_ms", 0)
                axes = score_all_axes(sssa, ctx)
                q = compute_Q(axes, task.skill_type)
                threshold = self._novel_thresholds().get(task.skill_type.value, 0.6)
                tier = classify_tier(q, task.skill_type, threshold)
                self._epoch_q_scores.setdefault(task.skill_type.value, []).append(float(q))
                per_uid_results.setdefault(uid, []).append(
                    {
                        "composite_q": float(q),
                        "skill_type": task.skill_type,
                        "tier": tier,
                        "task_type": task.task_type,
                        "epsilon": float(axes.epsilon),
                    }
                )
                round_results.append(
                    {
                        "hotkey": hotkey,
                        "skill_type": task.skill_type.value,
                        "task_type": task.task_type.value,
                        "epsilon": float(axes.epsilon),
                        "composite_q": float(q),
                        "tier": tier.value,
                    }
                )
                per_miner_payload.append(
                    {
                        "miner_uid": int(uid),
                        "miner_hotkey": hotkey,
                        "bundle_hash": prep.bundle_hash,
                        "skill_type": task.skill_type.value,
                        "composite_q": float(q),
                        "tier": tier.value,
                        "emission_score": float(q),
                        "verdict": sssa.verdict.decision.value,
                        "risk_score": int(sssa.verdict.risk_score),
                        "submission_latency_ms": int(getattr(resp, "latency_ms", 0)),
                    }
                )
                bt.logging.info(
                    f"{task.skill_type.value} hk={hotkey[:10]} Q={q:.3f} "
                    f"tier={tier.value} ε={axes.epsilon:.2f}"
                )

        if not per_uid_results:
            bt.logging.info(f"round {round_id[:8]} produced no scores; not publishing")
            return

        per_type_rep_by_hotkey = self._fetch_per_type_reputation()
        new_scores = torch.zeros_like(self.scores)
        for uid, results in per_uid_results.items():
            if uid >= new_scores.numel() or uid >= len(self.metagraph.hotkeys):
                continue
            hotkey = self.metagraph.hotkeys[uid]
            rep = per_type_rep_by_hotkey.get(hotkey, {})
            new_scores[uid] = float(
                compute_round_score(results, rep, current_epoch=self.current_epoch)
            )

        self.scores = self.EMA_ALPHA * new_scores + (1.0 - self.EMA_ALPHA) * self.scores
        top = float(self.scores.max().item()) if self.scores.numel() else 0.0
        bt.logging.info(
            f"round {round_id[:8]} done | top_score={top:.3f} epoch={self.current_epoch}"
        )

        self._publish_round_results(round_id, per_miner_payload)
        self._push_reputation_updates(round_results)
        self.last_completed_round_id = round_id

    async def _fetch_server_tasks(self) -> list[dict]:
        if self.server_client is None:
            return []
        try:
            batch = await asyncio.to_thread(
                self.server_client.fetch_task_batch,
                self.SERVER_CURATED_PULL,
                include_canaries=False,
            )
        except ServerUnreachable as e:
            bt.logging.warning(f"phylax-server unreachable for task batch: {e}")
            return []
        except ServerIdentityMismatch as e:
            bt.logging.error(f"phylax-server identity mismatch: {e}; skipping round")
            return []
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"phylax-server task fetch failed: {e}")
            return []
        return batch.get("tasks", []) or []

    async def _route_miners_for_skill_type(
        self, skill_type: SkillType
    ) -> list[tuple[str, int]]:
        routed: list[tuple[str, int]] = []
        hotkey_to_uid = {h: i for i, h in enumerate(self.metagraph.hotkeys)}
        if self.server_client is not None:
            for fallback_type in self._fallback_chain(skill_type):
                try:
                    routing = await asyncio.to_thread(
                        self.server_client.get,
                        "/v1/specialization/routing",
                        params={"skill_type": fallback_type.value},
                    )
                except Exception as e:  # noqa: BLE001
                    bt.logging.debug(f"routing fetch failed for {fallback_type.value}: {e}")
                    routing = {}
                payload = routing.get("miners", []) if isinstance(routing, dict) else []
                for entry in payload:
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

    @staticmethod
    def _fallback_chain(skill_type: SkillType) -> list[SkillType]:
        adjacents: dict[SkillType, list[SkillType]] = {
            SkillType.AGENT_COMPOSITION: [SkillType.MCP_SERVER],
            SkillType.MCP_SERVER: [SkillType.EXECUTABLE_PYTHON],
            SkillType.EXECUTABLE_SCRIPT: [SkillType.EXECUTABLE_PYTHON],
            SkillType.EXECUTABLE_PYTHON: [SkillType.DECLARATIVE],
            SkillType.DECLARATIVE: [SkillType.RAG_KNOWLEDGE],
            SkillType.RAG_KNOWLEDGE: [],
        }
        return [skill_type, *adjacents.get(skill_type, [])]

    def _bundle_from_prepared(self, task: RoundTask, prep) -> SkillBundle:
        metadata = task.metadata or {}
        return SkillBundle(
            bundle_hash=prep.bundle_hash,
            bundle_url=task.bundle_url,
            bundle_bytes=prep.bundle_bytes,
            metadata=BundleMetadata(
                skill_name=metadata.get("skill_name") or "unknown",
                skill_version=metadata.get("skill_version") or "unknown",
                skill_type=task.skill_type,
                profile=task.profile,
                composition_depth=metadata.get("composition_depth"),
                child_skill_hashes=metadata.get("child_skill_hashes") or [],
            ),
        )

    def _task_context(self, task: RoundTask, prep) -> TaskContext:
        expected_verdict_str = task.expected_verdict
        expected_verdict = Verdict(expected_verdict_str) if expected_verdict_str else None
        merged_evidence = dict(task.ground_truth_evidence)
        for k, v in prep.ground_truth.items():
            merged_evidence.setdefault(k, v)
        merged_truth = dict(task.ground_truth)
        for k, v in prep.ground_truth.items():
            merged_truth.setdefault(k, v)
        t_min_s, deadline_s = resolve_timing(task.skill_type, task.profile)
        return TaskContext(
            skill_type=task.skill_type,
            expected_verdict=expected_verdict,
            expected_risk=task.expected_risk_score,
            annotated_by=task.annotated_by,
            expected_evidence=merged_evidence,
            expected_policy=task.expected_policy,
            ground_truth=merged_truth,
            deadline_s=deadline_s,
            t_min_s=t_min_s,
        )

    async def _dial_miner(
        self,
        uid: int,
        bundle: SkillBundle,
        task: RoundTask,
        prep,
        t_min_s: int,
        deadline_s: int,
    ) -> PhylaxSynapse | None:
        axon = self.metagraph.axons[uid]
        synapse = PhylaxSynapse(
            skill_bundle=bundle,
            nonce=prep.nonce,
            task_metadata=TaskMetadata(
                task_id=task.task_id,
                task_type=task.task_type,
                deadline_s=deadline_s,
                t_min_s=t_min_s,
            ),
            inference_config=InferenceConfig(
                proxy_url=task.metadata.get("inference_proxy_url"),
                allowed_models=task.metadata.get("allowed_models", []),
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
                timeout=deadline_s,
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"uid={uid} dendrite error: {e}")
            return None
        returned = resp[0] if isinstance(resp, list) else resp
        if returned is None:
            return None
        returned.latency_ms = int((time.time() - sent_at) * 1000)
        return returned

    def _validate_sssa(self, sssa: SSSA, task: RoundTask, hotkey: str) -> bool:
        if sssa.skill.skill_type != task.skill_type:
            bt.logging.warning(
                f"skill_type mismatch from {hotkey[:10]}: "
                f"expected {task.skill_type.value}, got {sssa.skill.skill_type.value}"
            )
            return False
        llm_block = sssa.evidence.llm_evidence
        if llm_block is not None:
            allowed_use = llm_block.allowed_use.value if llm_block.allowed_use else None
            if allowed_use not in PERMITTED_LLM_USES:
                bt.logging.warning(
                    f"forbidden LLM use from {hotkey[:10]}: {allowed_use}; flagging"
                )
                self._flag_forbidden_llm(hotkey, task.skill_type)
                return False
        return True

    @staticmethod
    def _failure_record(hotkey: str, task: RoundTask) -> dict:
        return {
            "hotkey": hotkey,
            "skill_type": task.skill_type.value,
            "task_type": task.task_type.value,
            "epsilon": 0.0,
            "composite_q": 0.0,
            "tier": Tier.BELOW_REFERENCE.value,
            "violation": True,
        }

    def _novel_thresholds(self) -> dict[str, float]:
        if self.server_client is None:
            return {st.value: REFERENCE_BASELINES[st] * 1.5 for st in SkillType}
        if self._threshold_cache and (time.time() - self._threshold_cached_at) < self.THRESHOLD_CACHE_TTL_S:
            return self._threshold_cache
        try:
            data = self.server_client.get("/v1/specialization/tier-table")
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"tier-table fetch failed: {e}")
            return self._threshold_cache or {st.value: REFERENCE_BASELINES[st] * 1.5 for st in SkillType}
        out = (data or {}).get("novel_thresholds", {}) if isinstance(data, dict) else {}
        if out:
            self._threshold_cache = out
            self._threshold_cached_at = time.time()
        return out or self._threshold_cache or {st.value: REFERENCE_BASELINES[st] * 1.5 for st in SkillType}

    def _fetch_per_type_reputation(self) -> dict[str, dict[str, float]]:
        if self.server_client is None:
            return {}
        if self._per_type_rep_cache and (time.time() - self._per_type_rep_cached_at) < self.REPUTATION_CACHE_TTL_S:
            return self._per_type_rep_cache
        try:
            data = self.server_client.get("/v1/reputation/per-type")
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"per-type reputation fetch failed: {e}")
            return self._per_type_rep_cache
        out: dict[str, dict[str, float]] = {}
        if isinstance(data, dict):
            for entry in data.get("miners", []) or []:
                hotkey = entry.get("hotkey") or entry.get("miner_hotkey")
                rep_map = entry.get("per_type_reputation") or {}
                if hotkey and isinstance(rep_map, dict):
                    out[hotkey] = {k: float(v) for k, v in rep_map.items() if isinstance(v, int | float)}
        if out:
            self._per_type_rep_cache = out
            self._per_type_rep_cached_at = time.time()
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

    def _push_reputation_updates(self, round_results: list[dict]) -> None:
        if self.server_client is None or not round_results:
            return
        updates = []
        for r in round_results:
            if r.get("violation"):
                updates.append(
                    {
                        "hotkey": r["hotkey"],
                        "skill_type": r["skill_type"],
                        "update_type": "violation",
                        "epsilon": 0.0,
                    }
                )
                continue
            if r["task_type"] == TaskType.CANARY.value:
                updates.append(
                    {
                        "hotkey": r["hotkey"],
                        "skill_type": r["skill_type"],
                        "update_type": "canary",
                        "canary_passed": r["epsilon"] >= 0.8,
                    }
                )
            else:
                updates.append(
                    {
                        "hotkey": r["hotkey"],
                        "skill_type": r["skill_type"],
                        "update_type": "standard",
                        "epsilon": r["epsilon"],
                    }
                )
        try:
            self.server_client.post("/v1/reputation/updates", {"updates": updates})
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"reputation updates push failed: {e}")

    def _flag_forbidden_llm(self, hotkey: str, skill_type: SkillType) -> None:
        if self.server_client is None:
            return
        try:
            self.server_client.post(
                "/v1/reputation/updates",
                {
                    "updates": [
                        {
                            "hotkey": hotkey,
                            "skill_type": skill_type.value,
                            "update_type": "violation",
                            "violation_type": "forbidden_llm_use",
                        }
                    ]
                },
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"forbidden-LLM flag push failed: {e}")

    def _get_active_miner_uids(self) -> list[int]:
        out: list[int] = []
        for uid, axon in enumerate(self.metagraph.axons):
            if axon.ip == "0.0.0.0":
                continue
            if self.metagraph.validator_permit[uid]:
                continue
            out.append(uid)
        return out

    def _maybe_recalibrate_thresholds(self) -> None:
        if self.server_client is None or not self._epoch_q_scores:
            return
        new_thresholds = {}
        for skill_type_value, scores in self._epoch_q_scores.items():
            try:
                st = SkillType(skill_type_value)
            except ValueError:
                continue
            current = self._novel_thresholds().get(skill_type_value, REFERENCE_BASELINES[st] * 1.5)
            new_thresholds[skill_type_value] = recalibrate_novel_threshold(st, scores, current)
        if not new_thresholds:
            return
        try:
            self.server_client.post(
                "/v1/specialization/novel-thresholds",
                {"thresholds": new_thresholds, "epoch": self.current_epoch},
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"novel threshold push failed: {e}")
        self._threshold_cache = {}
        self._threshold_cached_at = 0.0
        self._epoch_q_scores = {}

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
            self.current_epoch += 1
            self._maybe_recalibrate_thresholds()
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
