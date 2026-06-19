from __future__ import annotations

import argparse
import asyncio
import os
import random as _random
import time
import traceback
import uuid
from collections import deque
from pathlib import Path

import bittensor as bt
import torch

from phylax.protocol import (
    REQUIRED_TRACE_FILES,
    SSSA,
    BundleMetadata,
    ClassifySynapse,
    InferenceConfig,
    LLMAllowedUse,
    MinerRole,
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
    compute_task_emissions_score,
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
    ROUND_COMPOSITION,
    AuditorRotationTracker,
    CollusionTracker,
    GroupMember,
    RerunJob,
    RerunQueue,
    RerunWorker,
    RoundTask,
    compose_round,
    compute_consensus,
    prepare_bundle,
    resolve_timing,
    select_verification_group,
    verify_trace_bundle,
)
from phylax.validator.trace_verification import verify_probe

logger = get_logger(__name__)

PERMITTED_LLM_USES: set[str | None] = {
    None,
    LLMAllowedUse.FINDING_ENRICHMENT.value,
    LLMAllowedUse.MITRE_OWASP_MAPPING.value,
    LLMAllowedUse.CVE_EXPLANATION.value,
}

EVOLVE_SHARE = 0.05
ROUND_INTERVAL_S: int = 720  # one round every 60 blocks (~12 min) → 6 rounds per epoch
_ADOPTIONS_CACHE_TTL = 600.0

CLASSIFY_GROUP_SIZE = 3
CLASSIFY_BATCH_MIN = int(os.getenv("PHYLAX_CLASSIFY_BATCH_MIN", "12"))
CLASSIFY_BATCH_MAX = 200
CLASSIFY_DEADLINE_S = int(os.getenv("PHYLAX_CLASSIFY_DEADLINE", "180"))
CLASSIFY_SCORE_ALPHA = float(os.getenv("PHYLAX_CLASSIFY_SCORE_ALPHA", "0.05"))


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
    WEIGHT_UPDATE_INTERVAL: int = int(os.getenv("WEIGHT_UPDATE_INTERVAL", "360"))
    EMA_ALPHA: float = float(os.getenv("EMA_ALPHA", "0.2"))
    THRESHOLD_CACHE_TTL_S: int = 300
    REPUTATION_CACHE_TTL_S: int = 60
    INFERENCE_PROXY_URL: str | None = os.getenv("PHYLAX_INFERENCE_PROXY_URL") or None
    ALLOWED_MODELS: list[str] = [
        m.strip() for m in os.getenv("PHYLAX_ALLOWED_MODELS", "").split(",") if m.strip()
    ]
    DEFAULT_COMPOSITION_DEPTH: int = int(os.getenv("PHYLAX_COMPOSITION_DEPTH", "5"))

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
        self._adoptions_cache: dict[str, str] = {}
        self._adoptions_cached_at: float = 0.0
        self._per_type_rep_cache: dict[str, dict[str, float]] = {}
        self._per_type_rep_cached_at: float = 0.0
        self._recent_bundle_hashes: list[str] = []
        self._declared_types_by_hotkey: dict[str, set[str]] = {}
        self._sandbox_images_by_hotkey: dict[str, dict[str, dict[str, str]]] = {}
        self._active_tasks_by_hotkey: dict[str, dict[str, dict[str, float]]] = {}
        self._per_miner_recent_bundles: dict[str, deque[str]] = {}
        self._bounty_eligible_by_hotkey: dict[str, dict[str, bool]] = {}

        rerun_db = os.getenv(
            "PHYLAX_RERUN_QUEUE_PATH",
            str(Path(os.path.expanduser("~/.phylax/rerun_queue.sqlite3"))),
        )
        self.rerun_queue = RerunQueue(rerun_db)
        self.rerun_worker = RerunWorker(self.rerun_queue, self._submit_rerun_outcomes)

        collusion_db = os.getenv(
            "PHYLAX_COLLUSION_DB_PATH",
            str(Path(os.path.expanduser("~/.phylax/collusion.sqlite3"))),
        )
        self.collusion_tracker = CollusionTracker(collusion_db)
        self.rotation_tracker = AuditorRotationTracker()

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

    async def run_classify_round(self) -> None:
        if self.server_client is None:
            return
        uids = self._get_active_miner_uids()
        if len(uids) < CLASSIFY_GROUP_SIZE:
            return
        count = min(CLASSIFY_BATCH_MAX, max(CLASSIFY_BATCH_MIN, len(uids) // CLASSIFY_GROUP_SIZE))
        try:
            payload = await asyncio.to_thread(
                self.server_client.post, "/v1/tasks/classify-batch", {"count": count}
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"classify-batch fetch failed: {e}")
            return
        tasks = (payload or {}).get("tasks", []) if isinstance(payload, dict) else []
        if not tasks:
            return
        bt.logging.info(f"classify round | tasks={len(tasks)} miners={len(uids)}")

        _random.shuffle(uids)
        groups = [
            [uids[(i * CLASSIFY_GROUP_SIZE + j) % len(uids)] for j in range(CLASSIFY_GROUP_SIZE)]
            for i in range(len(tasks))
        ]
        credits: dict[int, float] = {}

        async def _classify_one(task: dict, group: list[int]) -> None:
            synapse = ClassifySynapse(
                skill_id=task.get("skill_id") or "",
                slug=task.get("slug") or "",
                source_url=task.get("source_url") or "",
                pinned_commit=task.get("pinned_commit") or "",
                deadline_s=CLASSIFY_DEADLINE_S,
            )
            axons = [self.metagraph.axons[uid] for uid in group]
            try:
                responses = await self.dendrite(
                    axons=axons,
                    synapse=synapse,
                    deserialize=False,
                    timeout=CLASSIFY_DEADLINE_S,
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"classify dial failed for {task.get('slug')}: {e}")
                responses = []
            if not isinstance(responses, list):
                responses = [responses]

            votes: dict[tuple[str, str], list[int]] = {}
            for uid, resp in zip(group, responses, strict=False):
                if resp is None or not isinstance(resp, ClassifySynapse):
                    continue
                if not resp.is_valid_response():
                    continue
                key = (resp.bundle_hash.removeprefix("sha256:"), resp.skill_type)
                votes.setdefault(key, []).append(uid)

            winner = max(votes.items(), key=lambda kv: len(kv[1]), default=None)
            report: dict = {"skill_id": task.get("skill_id"), "consensus": False}
            if winner is not None and len(winner[1]) >= 2:
                (bundle_hash, skill_type), agreeing = winner
                report = {
                    "skill_id": task.get("skill_id"),
                    "consensus": True,
                    "skill_type": skill_type,
                    "bundle_hash": bundle_hash,
                    "pinned_commit": task.get("pinned_commit") or None,
                    "classifier_hotkeys": [self.metagraph.hotkeys[u] for u in agreeing],
                }
                for u in agreeing:
                    credits[u] = credits.get(u, 0.0) + 1.0
            try:
                await asyncio.to_thread(
                    self.server_client.post, "/v1/tasks/classify-report", report
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"classify-report failed for {task.get('slug')}: {e}")

        await asyncio.gather(*(_classify_one(t, g) for t, g in zip(tasks, groups, strict=True)))

        if credits:
            credit = torch.zeros_like(self.scores)
            for uid, c in credits.items():
                if uid < credit.numel():
                    credit[uid] = c / len(tasks)
            self.scores = self.scores + CLASSIFY_SCORE_ALPHA * credit
            bt.logging.info(
                f"classify round done | consensus_credits={len(credits)} miners"
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
        if self.server_client is not None:
            try:
                await asyncio.to_thread(
                    self.server_client.open_round,
                    round_id=round_id,
                    task_count=len(round_tasks),
                    bundle_hashes=[t.bundle_hash for t in round_tasks if t.bundle_hash],
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(f"round {round_id[:8]} open failed: {e}; skipping round")
                return

        async def _prep_one(_task: RoundTask) -> tuple[RoundTask, object] | None:
            depth = int(_task.metadata.get("composition_depth") or self.DEFAULT_COMPOSITION_DEPTH)
            bundle_bytes = _task.bundle_bytes
            if not bundle_bytes and _task.bundle_url:
                bundle_bytes = await self._fetch_bundle_bytes(_task.bundle_url)
                if bundle_bytes is None:
                    bt.logging.warning(
                        f"bundle fetch returned no bytes for {_task.skill_type.value} "
                        f"task {_task.task_id[:8]} url={_task.bundle_url}"
                    )
                    return None
                _task.bundle_bytes = bundle_bytes
            try:
                _prep = await asyncio.to_thread(
                    prepare_bundle,
                    _task.skill_type,
                    bundle_bytes or b"",
                    _task.metadata.get("nonce"),
                    depth,
                )
            except Exception as e:  # noqa: BLE001
                bt.logging.warning(
                    f"bundle preparation failed for {_task.skill_type.value} "
                    f"task {_task.task_id[:8]}: {e}"
                )
                return None
            return _task, _prep

        prep_results = await asyncio.gather(*(_prep_one(t) for t in round_tasks))
        prepared: list[tuple[RoundTask, object]] = [r for r in prep_results if r is not None]

        if not prepared:
            bt.logging.info(f"round {round_id[:8]}: every task failed preparation; skipping")
            return

        per_uid_results: dict[int, list[dict]] = {}
        round_results: list[dict] = []
        per_miner_payload: list[dict] = []

        miner_types_responded: dict[str, set[str]] = {}
        per_type_rep = self._fetch_per_type_reputation()
        for task, prep in prepared:
            self._recent_bundle_hashes.append(prep.bundle_hash)
            if len(self._recent_bundle_hashes) > 256:
                self._recent_bundle_hashes = self._recent_bundle_hashes[-256:]
            candidate_miners = await self._route_miners_for_skill_type(task.skill_type, task.task_type)
            flagged = self.collusion_tracker.flagged_hotkeys()
            if flagged:
                candidate_miners = [
                    (hk, uid) for hk, uid in candidate_miners if hk not in flagged
                ]
            filtered = self._filter_dispatchable_miners(
                candidate_miners, task, prep, per_type_rep,
            )
            if not filtered:
                bt.logging.info(
                    f"round {round_id[:8]} {task.skill_type.value}: no dispatchable miners "
                    f"({len(candidate_miners)} routed, filtered to 0)"
                )
                continue
            group = select_verification_group(
                filtered,
                skill_type=task.skill_type,
                per_type_reputation=per_type_rep,
                rotation=self.rotation_tracker,
            )
            if not group.primaries:
                bt.logging.info(
                    f"round {round_id[:8]} {task.skill_type.value}: group selection produced no primaries"
                )
                continue
            bundle = self._bundle_from_prepared(task, prep)
            primary_t_min, primary_deadline = resolve_timing(task.skill_type, task.profile, MinerRole.PRIMARY)
            auditor_t_min, auditor_deadline = resolve_timing(task.skill_type, task.profile, MinerRole.AUDITOR)

            members = group.all_members()
            for hotkey, _uid, role in members:
                deadline = primary_deadline if role == MinerRole.PRIMARY else auditor_deadline
                self._mark_task_active(hotkey, task.skill_type, task.task_id, deadline)
                self._record_dispatch_history(hotkey, prep.bundle_hash)
                self.rotation_tracker.record(hotkey, task.skill_type, role)

            dial_coros = []
            for _hotkey, uid, role in members:
                t_min = primary_t_min if role == MinerRole.PRIMARY else auditor_t_min
                deadline = primary_deadline if role == MinerRole.PRIMARY else auditor_deadline
                dial_coros.append(
                    self._dial_miner_with_role(uid, bundle, task, prep, role, t_min, deadline),
                )
            responses = await asyncio.gather(*dial_coros, return_exceptions=True)
            miners = [(hotkey, uid) for hotkey, uid, _role in members]
            member_roles = [role for _, _, role in members]

            scored_members: list[dict] = []
            for (hotkey, uid), resp, role in zip(miners, responses, member_roles, strict=True):
                deadline_s = primary_deadline if role == MinerRole.PRIMARY else auditor_deadline
                t_min_s = primary_t_min if role == MinerRole.PRIMARY else auditor_t_min
                if isinstance(resp, BaseException) or resp is None:
                    bt.logging.warning(
                        f"no response from {hotkey[:10]} ({role.value}) {task.skill_type.value}: "
                        f"{type(resp).__name__}={repr(resp)[:160]}"
                    )
                    continue
                latency_ms = int(getattr(resp, "latency_ms", 0) or 0)
                if latency_ms > deadline_s * 1000:
                    bt.logging.warning(
                        f"late response from {hotkey[:10]} ({role.value}) {task.skill_type.value}: "
                        f"{latency_ms}ms > {deadline_s}s"
                    )
                    continue
                if resp.error or resp.attestation is None:
                    bt.logging.warning(
                        f"empty response from {hotkey[:10]} ({role.value}) {task.skill_type.value}: "
                        f"error={resp.error!r} attestation_present={resp.attestation is not None} "
                        f"trace_bundle_present={resp.trace_bundle is not None}"
                    )
                    continue
                self._mark_task_complete(hotkey, task.skill_type, task.task_id)
                try:
                    sssa = SSSA(**resp.attestation)
                except Exception as e:  # noqa: BLE001
                    bt.logging.warning(f"SSSA parse failed for uid={uid}: {e}")
                    continue
                if not self._validate_sssa(sssa, task, hotkey):
                    round_results.append(self._failure_record(hotkey, task))
                    continue
                if role == MinerRole.PRIMARY and REQUIRED_TRACE_FILES.get(task.skill_type):
                    if not self._sandbox_digest_matches_registration(
                        hotkey, task.skill_type, resp.sandbox_manifest,
                    ):
                        bt.logging.warning(
                            f"sandbox digest mismatch for {hotkey[:10]} "
                            f"{task.skill_type.value}: manifest digest != registered image_hash"
                        )
                        round_results.append(self._failure_record(hotkey, task))
                        continue
                submitted_hashes = self._extract_submitted_hashes(sssa)
                fs_records: list[dict] = []
                network_records: list[dict] = []
                process_records: list[dict] = []
                semantic_subset = 1.0
                depth_ratio = 1.0
                if role == MinerRole.PRIMARY and REQUIRED_TRACE_FILES.get(task.skill_type):
                    verification = verify_trace_bundle(
                        task.skill_type,
                        resp.trace_bundle,
                        resp.sandbox_manifest,
                        submitted_hashes,
                        prep.reference_records,
                    )
                    if not verification.passed:
                        bt.logging.warning(
                            f"trace verification failed for {hotkey[:10]} "
                            f"({role.value}) {task.skill_type.value}: {verification.reason}"
                        )
                        round_results.append(self._failure_record(hotkey, task))
                        continue
                    fs_records = verification.decoded_records.get("fs.jsonl.gz", [])
                    network_records = verification.decoded_records.get("network.jsonl.gz", [])
                    process_records = verification.decoded_records.get("process.jsonl.gz", [])
                    semantic_subset = verification.semantic_subset
                    depth_ratio = verification.depth_ratio
                runtime_check = role == MinerRole.PRIMARY and bool(REQUIRED_TRACE_FILES.get(task.skill_type))
                probe_ok, probe_reason, _ = verify_probe(
                    prep.nonce,
                    resp.probe_evidence,
                    fs_records=fs_records,
                    network_records=network_records,
                    process_records=process_records,
                    runtime_type=runtime_check,
                )
                if not probe_ok:
                    bt.logging.warning(
                        f"probe verification failed for {hotkey[:10]} "
                        f"({role.value}) {task.skill_type.value}: {probe_reason}"
                    )
                    round_results.append(self._failure_record(hotkey, task))
                    continue
                ctx = self._task_context(task, prep)
                ctx.trace_semantic_subset = semantic_subset
                ctx.trace_depth_ratio = depth_ratio
                ctx.submission_latency_ms = latency_ms
                axes = score_all_axes(sssa, ctx)
                q = compute_Q(axes, task.skill_type)
                tier = classify_tier(q, task.skill_type, self._novel_thresholds())
                if role == MinerRole.PRIMARY:
                    self._epoch_q_scores.setdefault(task.skill_type.value, []).append(float(q))
                miner_types_responded.setdefault(hotkey, set()).add(task.skill_type.value)
                scored_members.append({
                    "hotkey": hotkey,
                    "uid": uid,
                    "role": role,
                    "sssa": sssa,
                    "submitted_hashes": submitted_hashes,
                    "decoded_records": {
                        "fs.jsonl.gz": fs_records,
                        "network.jsonl.gz": network_records,
                        "process.jsonl.gz": process_records,
                    },
                    "resp": resp,
                    "axes": axes,
                    "q": float(q),
                    "tier": tier,
                    "latency_ms": latency_ms,
                    "t_min_s": t_min_s,
                    "deadline_s": deadline_s,
                })

            consensus_report = None
            if group.consensus_enabled and len(scored_members) >= 2:
                consensus_report = compute_consensus([
                    GroupMember(hotkey=m["hotkey"], role=m["role"], sssa=m["sssa"])
                    for m in scored_members
                ])
            consensus_by_hotkey = {
                pmc.hotkey: pmc for pmc in (consensus_report.per_miner if consensus_report else [])
            }

            for m in scored_members:
                hotkey = m["hotkey"]
                uid = m["uid"]
                role = m["role"]
                axes = m["axes"]
                q = m["q"]
                tier = m["tier"]
                latency_ms = m["latency_ms"]
                t_min_s = m["t_min_s"]
                deadline_s = m["deadline_s"]
                sssa = m["sssa"]
                pmc = consensus_by_hotkey.get(hotkey)
                consensus_mult = float(pmc.consensus_score) if pmc else 1.0
                if pmc is not None:
                    self.collusion_tracker.record(
                        hotkey=hotkey,
                        skill_type=task.skill_type.value,
                        round_id=round_id,
                        aligned_with_primaries=pmc.aligned_with_primaries,
                        aligned_with_auditors=pmc.aligned_with_auditors,
                    )
                result_entry = {
                    "hotkey": hotkey,
                    "skill_type": task.skill_type.value,
                    "task_type": task.task_type.value,
                    "epsilon": float(axes.epsilon),
                    "composite_q": float(q),
                    "tier": tier.value,
                    "is_bounty": bool(getattr(task, "is_bounty", False)),
                    "consensus_score": consensus_mult,
                    "role": role.value,
                }
                round_results.append(result_entry)
                per_uid_results.setdefault(int(uid), []).append(result_entry)
                emission = compute_task_emissions_score(
                    float(q), task.skill_type, tier, self.current_epoch,
                )
                emission *= self._early_submission_multiplier(latency_ms, t_min_s, deadline_s)
                if role == MinerRole.AUDITOR:
                    emission *= 0.6
                emission *= consensus_mult
                per_miner_payload.append(
                    {
                        "miner_uid": int(uid),
                        "miner_hotkey": hotkey,
                        "bundle_hash": prep.bundle_hash,
                        "skill_type": task.skill_type.value,
                        "composite_q": float(q),
                        "tier": tier.value,
                        "emission_score": float(emission),
                        "consensus_score": float(consensus_mult),
                        "role": role.value,
                        "verdict": sssa.verdict.decision.value,
                        "risk_score": int(sssa.verdict.risk_score),
                        "submission_latency_ms": int(latency_ms),
                        "sssa": sssa.model_dump(mode="json"),
                    }
                )
                bt.logging.info(
                    f"{task.skill_type.value} hk={hotkey[:10]} role={role.value} "
                    f"Q={q:.3f} cs={consensus_mult:.2f} tier={tier.value} ε={axes.epsilon:.2f}"
                )

            self._maybe_enqueue_reruns(task, prep, scored_members, consensus_report)

            self._publish_canonical_attestation(round_id, task, prep, scored_members)

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

        self._append_coverage_violations(round_results, miner_types_responded)
        self._scan_collusion_flags(round_results)
        self._publish_round_results(round_id, per_miner_payload)
        self._push_reputation_updates(round_results)
        self.last_completed_round_id = round_id

    def _scan_collusion_flags(self, round_results: list[dict]) -> None:
        hotkeys_seen: set[tuple[str, str]] = set()
        for r in round_results:
            hk = r.get("hotkey")
            st = r.get("skill_type")
            if not hk or not st:
                continue
            if (hk, st) in hotkeys_seen:
                continue
            hotkeys_seen.add((hk, st))
            verdict = self.collusion_tracker.evaluate(hk, st)
            if verdict.flagged:
                count = self.collusion_tracker.add_flag(
                    hk,
                    reason=f"primary_agreement={verdict.primary_agreement:.2f} "
                    f"auditor_agreement={verdict.auditor_agreement:.2f} "
                    f"samples={verdict.samples}",
                )
                bt.logging.warning(
                    f"collusion flag {count} for {hk[:10]} {st}: "
                    f"primary_agr={verdict.primary_agreement:.2f} "
                    f"auditor_agr={verdict.auditor_agreement:.2f}"
                )

    def _append_coverage_violations(
        self,
        round_results: list[dict],
        responded: dict[str, set[str]],
    ) -> None:
        for hotkey, declared in self._declared_types_by_hotkey.items():
            responded_types = responded.get(hotkey, set())
            for skill_type_value in declared - responded_types:
                round_results.append(
                    {
                        "hotkey": hotkey,
                        "skill_type": skill_type_value,
                        "task_type": "coverage",
                        "epsilon": 0.0,
                        "composite_q": 0.0,
                        "tier": Tier.BELOW_REFERENCE.value,
                        "violation": True,
                    }
                )

    async def _fetch_server_tasks(self) -> list[dict]:
        if self.server_client is None:
            return []
        collected: list[dict] = []
        recent = list(self._recent_bundle_hashes)
        for skill_type, slots in ROUND_COMPOSITION.items():
            needed = sum(1 for s in slots if s == TaskType.SERVER_CURATED)
            if needed <= 0:
                continue
            try:
                payload = await asyncio.to_thread(
                    self.server_client.post,
                    "/v1/tasks/by-type",
                    {
                        "skill_type": skill_type.value,
                        "count": needed,
                        "exclude_bundle_hashes": recent[-128:],
                    },
                )
            except ServerUnreachable as e:
                bt.logging.warning(f"by-type fetch unreachable for {skill_type.value}: {e}")
                continue
            except ServerIdentityMismatch as e:
                bt.logging.error(f"phylax-server identity mismatch: {e}; skipping round")
                return []
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"by-type fetch failed for {skill_type.value}: {e}")
                continue
            tasks = (payload or {}).get("tasks", []) if isinstance(payload, dict) else []
            for t in tasks:
                t.setdefault("skill_type", skill_type.value)
                t.setdefault("task_type", TaskType.SERVER_CURATED.value)
                collected.append(t)
        return collected

    async def _fetch_bundle_bytes(self, url: str) -> bytes | None:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.content
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(f"bundle fetch failed url={url}: {e}")
            return None

    async def _route_miners_for_skill_type(
        self, skill_type: SkillType, task_type: TaskType,
    ) -> list[tuple[str, int]]:
        hotkey_to_uid = {h: i for i, h in enumerate(self.metagraph.hotkeys)}
        include_recovery = task_type == TaskType.CANARY

        routed = await self._routing_call(
            skill_type, hotkey_to_uid, include_recovery=include_recovery,
        )
        if routed:
            self._record_declared_for(skill_type, routed)
            return routed

        if self.server_client is not None:
            generalists = await self._generalists_call(hotkey_to_uid)
            if generalists:
                self._record_declared_for(skill_type, generalists, declared_all=True)
                return generalists

        for adjacent in self._adjacent_types(skill_type):
            routed = await self._routing_call(
                adjacent, hotkey_to_uid, include_recovery=include_recovery,
            )
            if routed:
                self._record_declared_for(adjacent, routed)
                return routed

        cold: list[tuple[str, int]] = []
        for uid in self._get_active_miner_uids():
            if uid >= len(self.metagraph.hotkeys):
                continue
            cold.append((self.metagraph.hotkeys[uid], uid))
        return cold

    async def _routing_call(
        self,
        skill_type: SkillType,
        hotkey_to_uid: dict[str, int],
        *,
        include_recovery: bool,
    ) -> list[tuple[str, int]]:
        if self.server_client is None:
            return []
        params: dict = {"skill_type": skill_type.value}
        if include_recovery:
            params["include_recovery"] = "true"
        try:
            routing = await asyncio.to_thread(
                self.server_client.get,
                "/v1/specialization/routing",
                params=params,
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"routing fetch failed for {skill_type.value}: {e}")
            return []
        payload = routing.get("miners", []) if isinstance(routing, dict) else []
        out: list[tuple[str, int]] = []
        for entry in payload:
            hotkey = entry.get("hotkey", "")
            uid = hotkey_to_uid.get(hotkey)
            if uid is None:
                continue
            axon = self.metagraph.axons[uid]
            if axon.ip == "0.0.0.0":
                continue
            sandbox_image = entry.get("sandbox_image")
            if isinstance(sandbox_image, dict):
                self._sandbox_images_by_hotkey.setdefault(hotkey, {})[skill_type.value] = sandbox_image
            self._bounty_eligible_by_hotkey.setdefault(hotkey, {})[skill_type.value] = bool(
                entry.get("bounty_eligible", False)
            )
            out.append((hotkey, uid))
        return out

    async def _generalists_call(
        self, hotkey_to_uid: dict[str, int]
    ) -> list[tuple[str, int]]:
        if self.server_client is None:
            return []
        try:
            data = await asyncio.to_thread(
                self.server_client.get, "/v1/specialization/generalists"
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"generalists fetch failed: {e}")
            return []
        miners = data.get("miners", []) if isinstance(data, dict) else []
        out: list[tuple[str, int]] = []
        for entry in miners:
            hotkey = entry.get("hotkey", "")
            uid = hotkey_to_uid.get(hotkey)
            if uid is None:
                continue
            axon = self.metagraph.axons[uid]
            if axon.ip == "0.0.0.0":
                continue
            out.append((hotkey, uid))
        return out

    def _record_declared_for(
        self,
        skill_type: SkillType,
        miners: list[tuple[str, int]],
        *,
        declared_all: bool = False,
    ) -> None:
        for hotkey, _ in miners:
            current = self._declared_types_by_hotkey.setdefault(hotkey, set())
            if declared_all:
                current.update(st.value for st in SkillType)
            else:
                current.add(skill_type.value)

    @staticmethod
    def _adjacent_types(skill_type: SkillType) -> list[SkillType]:
        adjacents: dict[SkillType, list[SkillType]] = {
            SkillType.AGENT_COMPOSITION: [SkillType.MCP_SERVER],
            SkillType.MCP_SERVER: [SkillType.EXECUTABLE_PYTHON],
            SkillType.EXECUTABLE_SCRIPT: [SkillType.EXECUTABLE_PYTHON],
            SkillType.EXECUTABLE_PYTHON: [SkillType.DECLARATIVE],
            SkillType.DECLARATIVE: [SkillType.RAG_KNOWLEDGE],
            SkillType.RAG_KNOWLEDGE: [],
        }
        return adjacents.get(skill_type, [])

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
        return await self._dial_miner_with_role(
            uid, bundle, task, prep, MinerRole.PRIMARY, t_min_s, deadline_s,
        )

    async def _dial_miner_with_role(
        self,
        uid: int,
        bundle: SkillBundle,
        task: RoundTask,
        prep,
        role: MinerRole,
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
                role=role.value,
            ),
            inference_config=InferenceConfig(
                proxy_url=task.metadata.get("inference_proxy_url") or self.INFERENCE_PROXY_URL,
                allowed_models=task.metadata.get("allowed_models") or self.ALLOWED_MODELS,
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

    def _maybe_enqueue_reruns(
        self,
        task: RoundTask,
        prep,
        scored_members: list[dict],
        consensus_report,
    ) -> None:
        if not scored_members:
            return
        primaries = [m for m in scored_members if m["role"] == MinerRole.PRIMARY]
        if not primaries:
            return
        diverging_set = set(consensus_report.diverging_hotkeys) if consensus_report else set()

        targets: list[dict] = []
        if consensus_report and consensus_report.breakdown_flag:
            targets = [m for m in primaries if m["hotkey"] in diverging_set]
            if not targets:
                targets = primaries
        elif diverging_set:
            targets = [m for m in primaries if m["hotkey"] in diverging_set]
        else:
            targets = [_random.choice(primaries)]

        for m in targets:
            self._enqueue_rerun(
                m["hotkey"], task, prep, m["resp"],
                m["submitted_hashes"], m["decoded_records"],
            )

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

    @staticmethod
    def _early_submission_multiplier(latency_ms: int, t_min_s: int, deadline_s: int) -> float:
        window_ms = max(1, (deadline_s - t_min_s) * 1000)
        position = (latency_ms - t_min_s * 1000) / window_ms
        if position < 0.0:
            return 1.0
        if position <= 0.25:
            return 1.15
        if position <= 0.50:
            return 1.08
        return 1.0

    def _mark_task_active(self, hotkey: str, skill_type: SkillType, task_id: str, deadline_s: int) -> None:
        now = time.time()
        bucket = self._active_tasks_by_hotkey.setdefault(hotkey, {}).setdefault(skill_type.value, {})
        bucket[task_id] = now + deadline_s
        for tid, expiry in list(bucket.items()):
            if expiry <= now:
                bucket.pop(tid, None)

    def _mark_task_complete(self, hotkey: str, skill_type: SkillType, task_id: str) -> None:
        bucket = self._active_tasks_by_hotkey.get(hotkey, {}).get(skill_type.value)
        if bucket:
            bucket.pop(task_id, None)

    def _miner_has_open_task(self, hotkey: str, skill_type: SkillType) -> bool:
        now = time.time()
        bucket = self._active_tasks_by_hotkey.get(hotkey, {}).get(skill_type.value)
        if not bucket:
            return False
        for tid, expiry in list(bucket.items()):
            if expiry <= now:
                bucket.pop(tid, None)
        return bool(bucket)

    def _miner_saw_bundle_recently(self, hotkey: str, bundle_hash: str) -> bool:
        history = self._per_miner_recent_bundles.get(hotkey)
        if not history:
            return False
        return bundle_hash in history

    def _record_dispatch_history(self, hotkey: str, bundle_hash: str) -> None:
        history = self._per_miner_recent_bundles.setdefault(hotkey, deque(maxlen=60))
        history.append(bundle_hash)

    def _is_bounty_eligible(self, hotkey: str, skill_type: SkillType, per_type_rep: dict[str, dict[str, float]]) -> bool:
        rep = per_type_rep.get(hotkey, {}).get(skill_type.value, 0.0)
        if rep < 0.85:
            return False
        server_signal = self._bounty_eligible_by_hotkey.get(hotkey, {}).get(skill_type.value)
        if server_signal is False:
            return False
        return True

    def _filter_dispatchable_miners(
        self,
        candidates: list[tuple[str, int]],
        task: RoundTask,
        prep,
        per_type_rep: dict[str, dict[str, float]],
    ) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        is_bounty = bool(getattr(task, "is_bounty", False))
        for hotkey, uid in candidates:
            if self._miner_saw_bundle_recently(hotkey, prep.bundle_hash):
                continue
            if is_bounty:
                if not self._is_bounty_eligible(hotkey, task.skill_type, per_type_rep):
                    continue
            else:
                if self._miner_has_open_task(hotkey, task.skill_type):
                    continue
            out.append((hotkey, uid))
        return out

    @staticmethod
    def _extract_submitted_hashes(sssa: SSSA) -> dict[str, str | None]:
        ts = sssa.evidence.type_specific
        return {
            "network_trace_hash": sssa.evidence.base.network_trace_hash,
            "fs_trace_hash": sssa.evidence.base.fs_trace_hash,
            "process_trace_hash": sssa.evidence.base.process_trace_hash,
            "secrets_trace_hash": sssa.evidence.base.secrets_trace_hash,
            "imports_trace_hash": getattr(ts.executable_python, "imports_trace_hash", None) if ts.executable_python else None,
            "shell_commands_hash": getattr(ts.executable_script, "shell_commands_hash", None) if ts.executable_script else None,
            "tool_calls_hash": getattr(ts.mcp_server, "tool_calls_hash", None) if ts.mcp_server else None,
            "mcp_manifest_hash": getattr(ts.mcp_server, "mcp_manifest_hash", None) if ts.mcp_server else None,
            "agent_calls_hash": getattr(ts.agent_composition, "agent_calls_hash", None) if ts.agent_composition else None,
        }

    def _enqueue_rerun(
        self,
        hotkey: str,
        task: RoundTask,
        prep,
        resp: PhylaxSynapse,
        submitted_hashes: dict[str, str | None],
        decoded_records: dict[str, list[dict]],
    ) -> None:
        if not REQUIRED_TRACE_FILES.get(task.skill_type):
            return
        manifest = resp.sandbox_manifest or {}
        registered_image = self._lookup_registered_sandbox_image(hotkey, task.skill_type)
        image_uri = (registered_image or {}).get("image_uri") or manifest.get("image", "")
        image_hash = (registered_image or {}).get("image_hash") or manifest.get("digest", "")
        if not image_uri or not image_hash:
            return
        _, deadline_s = resolve_timing(task.skill_type, task.profile)
        job = RerunJob(
            hotkey=hotkey,
            skill_type=task.skill_type.value,
            task_id=task.task_id,
            bundle_bytes=prep.bundle_bytes,
            nonce=prep.nonce,
            canary_id=prep.canary_id,
            canary_val=prep.canary_val,
            submitted_hashes={k: v for k, v in submitted_hashes.items() if v is not None},
            miner_submitted_records=decoded_records,
            sandbox_image_uri=image_uri,
            sandbox_image_hash=image_hash,
            timeout_s=deadline_s,
        )
        try:
            self.rerun_queue.enqueue(job)
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"rerun enqueue failed: {e}")

    def _lookup_registered_sandbox_image(
        self, hotkey: str, skill_type: SkillType,
    ) -> dict[str, str] | None:
        cached = self._sandbox_images_by_hotkey.get(hotkey, {}).get(skill_type.value)
        if cached:
            return cached
        return None

    def _sandbox_digest_matches_registration(
        self, hotkey: str, skill_type: SkillType, manifest: dict | None,
    ) -> bool:
        if not manifest:
            return False
        submitted = str(manifest.get("digest", "")).strip()
        if not submitted:
            return False
        registered = self._lookup_registered_sandbox_image(hotkey, skill_type)
        if not registered:
            return True
        expected = str(registered.get("image_hash", "")).strip()
        if not expected:
            return True
        return submitted == expected

    def _submit_rerun_outcomes(self, outcomes: list) -> None:
        if self.server_client is None or not outcomes:
            return
        payload = {
            "verifications": [
                {
                    "hotkey": o.hotkey,
                    "skill_type": o.skill_type,
                    "task_id": o.task_id,
                    "passed": bool(o.passed),
                    "fs_trace_hash_matched": bool(o.fs_trace_hash_matched),
                    "semantic_agreement": float(o.semantic_agreement),
                    "image_hash": o.image_hash,
                    "notes": str(o.notes)[:256],
                }
                for o in outcomes
            ]
        }
        try:
            self.server_client.post("/v1/reputation/rerun-verification", payload)
        except Exception as e:  # noqa: BLE001
            bt.logging.debug(f"rerun-verification post failed: {e}")

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

    def _publish_canonical_attestation(
        self, round_id: str, task: RoundTask, prep, scored_members: list[dict],
    ) -> None:
        if self.server_client is None or task.task_type != TaskType.SERVER_CURATED:
            return
        primaries = [m for m in scored_members if m["role"] == MinerRole.PRIMARY]
        if not primaries:
            return
        best = max(primaries, key=lambda m: m["q"])
        try:
            self.server_client.push_attestation(
                bundle_hash=prep.bundle_hash,
                sssa=best["sssa"].model_dump(mode="json"),
                quality_score=max(0.0, min(1.0, float(best["q"]))),
                round_id=round_id,
            )
        except Exception as e:  # noqa: BLE001
            bt.logging.warning(
                f"attestation push failed bundle={prep.bundle_hash[:16]} "
                f"{task.skill_type.value}: {e}"
            )
            return
        bt.logging.info(
            f"attestation pushed {task.skill_type.value} "
            f"bundle={prep.bundle_hash[:16]} q={best['q']:.3f} hk={best['hotkey'][:10]}"
        )

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
            elif r.get("is_bounty"):
                updates.append(
                    {
                        "hotkey": r["hotkey"],
                        "skill_type": r["skill_type"],
                        "update_type": "bounty",
                        "bounty_passed": r["epsilon"] >= 0.5,
                        "epsilon": r["epsilon"],
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
        own_hotkey = self.wallet.hotkey.ss58_address
        out: list[int] = []
        for uid, axon in enumerate(self.metagraph.axons):
            if axon.ip == "0.0.0.0":
                continue
            if self.metagraph.hotkeys[uid] == own_hotkey:
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

    def _fetch_adopted_components(self) -> dict[str, str]:
        now = time.time()
        if now - self._adoptions_cached_at < _ADOPTIONS_CACHE_TTL:
            return self._adoptions_cache
        adoptions: dict[str, str] = {}
        if self.server_client is not None:
            try:
                data = self.server_client.get("/v1/components/adopted", signed=False)
                for entry in data.get("components", []):
                    component = entry.get("component")
                    hotkey = entry.get("author_hotkey")
                    if component and hotkey:
                        adoptions[component] = hotkey
            except Exception as e:  # noqa: BLE001
                bt.logging.debug(f"adopted components fetch failed: {e}")
        self._adoptions_cache = adoptions
        self._adoptions_cached_at = now
        return adoptions

    def _apply_emission_split(self, weights: torch.Tensor) -> torch.Tensor:
        adoptions = self._fetch_adopted_components()
        hotkey_to_uid = {hk: uid for uid, hk in enumerate(self.metagraph.hotkeys)}

        out = weights * (1.0 - EVOLVE_SHARE)
        if adoptions:
            per_contribution = EVOLVE_SHARE / len(adoptions)
            for hotkey in adoptions.values():
                uid = hotkey_to_uid.get(hotkey)
                if uid is not None:
                    out[uid] += per_contribution

        total = out.sum()
        if total > 0.0:
            out = out / total
        return out

    def set_weights(self) -> None:
        if self.scores.sum().item() <= 0.0:
            bt.logging.info("set_weights: all-zero scores; skipping")
            return
        weights = self.scores.clone()
        weights = weights / weights.sum()
        weights = self._apply_emission_split(weights)
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
        self.rerun_worker.start()
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

                    loop.run_until_complete(self.run_classify_round())
                    loop.run_until_complete(self.run_round())

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
            self.rerun_worker.stop()
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
