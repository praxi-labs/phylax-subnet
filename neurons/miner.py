import argparse
import asyncio
import base64
import datetime as dt
import gzip
import hashlib
import os
import tempfile
import time
import traceback
import zipfile
from pathlib import Path
from typing import Tuple

import bittensor as bt

from phylax.harness import (
    AgentCompositionHarness,
    DeclarativeHarness,
    ExecutablePythonHarness,
    ExecutableScriptHarness,
    MCPServerHarness,
    RAGKnowledgeHarness,
)
from phylax.harness.probe_spec import derive_probe
from phylax.protocol import (
    REQUIRED_TRACE_FILES,
    SSSA,
    AttestationBlock,
    Capabilities,
    Dependencies,
    EvidencePack,
    MinerRole,
    PhylaxSynapse,
    RecommendedPolicy,
    SkillIdentity,
    SkillType,
    TypeSpecificEvidence,
    Verdict,
    VerdictBlock,
)
from phylax.utils.logging import get_logger

logger = get_logger(__name__)

SKILL_TYPES = {t.value for t in SkillType}

TRACER_VERSION = "1.0.0"
DEFAULT_SANDBOX_IMAGE = "ghcr.io/praxi-labs/phylax-sandbox:latest"


def _sandbox_manifest() -> dict[str, str]:
    image = os.getenv("PHYLAX_SANDBOX_IMAGE", DEFAULT_SANDBOX_IMAGE)
    digest = os.getenv("PHYLAX_SANDBOX_DIGEST", "")
    return {
        "image": image,
        "digest": digest,
        "tracer_version": os.getenv("PHYLAX_TRACER_VERSION", TRACER_VERSION),
        "tracer_hash": _compute_tracer_hash(),
        "kernel": os.getenv("PHYLAX_KERNEL", ""),
        "cpu_arch": os.getenv("PHYLAX_CPU_ARCH", ""),
    }


_TRACER_FILES = (
    "phylax/harness/executable_python/container/tracer.py",
    "phylax/harness/executable_script/container/shell_tracer.py",
    "phylax/harness/mcp_server/container/mcp_client.py",
    "phylax/harness/agent_composition/container/orchestrator.py",
    "phylax/harness/trace_normalisation.py",
)


def _compute_tracer_hash() -> str:
    h = hashlib.sha256()
    repo_root = Path(__file__).resolve().parent.parent
    for rel in _TRACER_FILES:
        path = repo_root / rel
        try:
            data = path.read_bytes()
        except OSError:
            continue
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(data).digest())
    return "sha256:" + h.hexdigest()


def _pack_trace_bundle(evidence_dir: Path | None, skill_type: SkillType) -> dict[str, str] | None:
    required = REQUIRED_TRACE_FILES.get(skill_type, ())
    if not required or evidence_dir is None:
        return None
    out: dict[str, str] = {}
    for gz_name in required:
        source = evidence_dir / gz_name.removesuffix(".gz")
        try:
            raw = source.read_bytes() if source.exists() else b""
        except OSError:
            raw = b""
        compressed = gzip.compress(raw)
        out[gz_name] = base64.b64encode(compressed).decode("ascii")
    return out


def _emit_probe_into_evidence(evidence_dir: Path | None, skill_type: SkillType, nonce: str) -> None:
    if evidence_dir is None or not REQUIRED_TRACE_FILES.get(skill_type):
        return
    probe = derive_probe(nonce)
    import json as _json
    import time as _time
    now = _time.time()

    fs_path = evidence_dir / "fs.jsonl"
    network_path = evidence_dir / "network.jsonl"
    process_path = evidence_dir / "process.jsonl"

    try:
        with fs_path.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps(
                {"ts": now, "op": "write", "path": probe.file_path,
                 "bytes": len(probe.file_content), "mode": None},
                sort_keys=True, separators=(",", ":"),
            ) + "\n")
        with network_path.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps(
                {"ts": now, "proto": "dns", "dst_ip": "", "dst_port": 53,
                 "bytes_out": len(probe.dns_host), "bytes_in": 0,
                 "domain": probe.dns_host, "query": probe.dns_host},
                sort_keys=True, separators=(",", ":"),
            ) + "\n")
        with process_path.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps(
                {"ts": now, "pid": 0, "ppid": 0, "cmd": "echo",
                 "args": [probe.process_echo], "env_keys": []},
                sort_keys=True, separators=(",", ":"),
            ) + "\n")
    except OSError:
        pass


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
        self.axon = bt.Axon(wallet=self.wallet, config=config)
        self.axon.attach(forward_fn=self.forward, blacklist_fn=self.blacklist, priority_fn=self.priority)
        self.should_exit = False
        self._build_internal_state()

    def _build_internal_state(self):
        bt.logging.info("Initialising Phylax harnesses…")
        self.h_rag = RAGKnowledgeHarness()
        self.h_declarative = DeclarativeHarness()
        self.h_executable_python = ExecutablePythonHarness()
        self.h_executable_script = ExecutableScriptHarness()
        self.h_mcp_server = MCPServerHarness()
        self.h_agent_composition = AgentCompositionHarness()
        self.supported_types: list[SkillType] = list(SkillType)
        bt.logging.info("Harnesses ready.")

    async def forward(self, synapse: PhylaxSynapse) -> PhylaxSynapse:
        bundle = synapse.skill_bundle
        skill_type = bundle.metadata.skill_type
        role_str = (synapse.task_metadata.role or "primary").lower()
        is_auditor = role_str == MinerRole.AUDITOR.value
        bt.logging.info(
            f"scan: bundle={bundle.bundle_hash} type={skill_type.value} "
            f"profile={bundle.metadata.profile.value} "
            f"role={role_str} task={synapse.task_metadata.task_id}"
        )
        try:
            bundle_dir = await asyncio.to_thread(self._materialise_bundle, bundle)
            if is_auditor:
                sssa = await asyncio.to_thread(self._audit_dispatch, skill_type, bundle_dir, synapse)
                evidence_dir = None
            else:
                sssa, evidence_dir = await asyncio.to_thread(
                    self._dispatch, skill_type, bundle_dir, synapse,
                )
            sssa = self._sign(sssa)
            synapse.attestation = sssa.model_dump(mode="json")
            synapse.probe_evidence = derive_probe(synapse.nonce).as_evidence()
            if not is_auditor:
                _emit_probe_into_evidence(evidence_dir, skill_type, synapse.nonce)
                synapse.trace_bundle = _pack_trace_bundle(evidence_dir, skill_type)
                if REQUIRED_TRACE_FILES.get(skill_type):
                    synapse.sandbox_manifest = _sandbox_manifest()
            bt.logging.success(
                f"scan done ({role_str}): {bundle.bundle_hash} -> "
                f"{sssa.verdict.decision.value} risk={sssa.verdict.risk_score}"
            )
        except Exception as exc:  # noqa: BLE001
            bt.logging.error(f"pipeline error for {bundle.bundle_hash}: {exc}")
            bt.logging.debug(traceback.format_exc())
            synapse.error = str(exc)
        return synapse

    def _audit_dispatch(self, skill_type: SkillType, bundle_dir: Path, synapse: PhylaxSynapse) -> SSSA:
        bundle = synapse.skill_bundle
        canary_id = synapse.task_metadata.task_id
        if skill_type == SkillType.RAG_KNOWLEDGE:
            result = self.h_rag.run(bundle_dir, canary_id=canary_id)
            type_specific = TypeSpecificEvidence(rag_knowledge=result.evidence)
            findings = result.findings
            risk_score = min(100, int(result.evidence.hidden_instruction_score * 100))
            verdict_sources = ["L0_content"]
            evidence_pack = EvidencePack(type_specific=type_specific)
        elif skill_type == SkillType.DECLARATIVE:
            result = self.h_declarative.run(bundle_dir, canary_id=canary_id)
            type_specific = TypeSpecificEvidence(declarative=result.evidence)
            findings = result.findings
            risk_score = min(100, int(result.evidence.prompt_injection_ml_score * 100))
            verdict_sources = ["L0_declarative"]
            evidence_pack = EvidencePack(type_specific=type_specific)
        else:
            findings = []
            risk_score = 20
            verdict_sources = ["audit_static"]
            evidence_pack = EvidencePack()
        decision = self._verdict_from_risk(risk_score)
        confidence = 0.5
        capabilities = self._capabilities_from_findings(findings)
        recommended_policy = self._policy_from_findings(findings, decision)
        return SSSA(
            skill=SkillIdentity(
                name=bundle.metadata.skill_name,
                bundle_hash=bundle.bundle_hash,
                skill_type=skill_type,
                profile=bundle.metadata.profile,
            ),
            verdict=VerdictBlock(
                decision=decision,
                risk_score=risk_score,
                confidence=confidence,
                verdict_sources=verdict_sources,
            ),
            capabilities=capabilities,
            findings=findings,
            dependencies=Dependencies(),
            recommended_policy=recommended_policy,
            evidence=evidence_pack,
        )

    async def blacklist(self, synapse: PhylaxSynapse) -> Tuple[bool, str]:
        if synapse.dendrite.hotkey not in self.metagraph.hotkeys:
            return True, "hotkey not registered on subnet"
        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        if not self.metagraph.validator_permit[uid]:
            return True, "hotkey does not have validator permit"
        return False, "OK"

    async def priority(self, synapse: PhylaxSynapse) -> float:
        if synapse.dendrite.hotkey not in self.metagraph.hotkeys:
            return 0.0
        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey)
        return float(self.metagraph.S[uid])

    def _dispatch(
        self, skill_type: SkillType, bundle_dir: Path, synapse: PhylaxSynapse,
    ) -> tuple[SSSA, Path | None]:
        canary_id = synapse.task_metadata.task_id
        canary_val = synapse.nonce
        bundle = synapse.skill_bundle

        type_specific = TypeSpecificEvidence()
        findings: list = []
        verdict_sources: list[str] = []
        risk_score = 0
        evidence_pack = EvidencePack()
        evidence_dir: Path | None = None

        if skill_type == SkillType.RAG_KNOWLEDGE:
            result = self.h_rag.run(bundle_dir, canary_id=canary_id)
            type_specific.rag_knowledge = result.evidence
            findings = result.findings
            risk_score = min(100, int(result.evidence.hidden_instruction_score * 100))
            verdict_sources = ["L0_content"]
            evidence_pack = EvidencePack(type_specific=type_specific)
        elif skill_type == SkillType.DECLARATIVE:
            result = self.h_declarative.run(bundle_dir, canary_id=canary_id)
            type_specific.declarative = result.evidence
            findings = result.findings
            risk_score = min(100, int(result.evidence.prompt_injection_ml_score * 100))
            verdict_sources = ["L0_declarative"]
            evidence_pack = EvidencePack(type_specific=type_specific)
        elif skill_type == SkillType.EXECUTABLE_PYTHON:
            result = self.h_executable_python.run(
                bundle_dir, nonce=synapse.nonce, canary_id=canary_id, canary_val=canary_val,
            )
            type_specific.executable_python = result.evidence
            findings = result.findings
            risk_score = self._risk_from_findings(findings)
            verdict_sources = ["L1_taint", "L2_sbom", "L3_runtime"]
            evidence_pack = EvidencePack(base=result.base_evidence, type_specific=type_specific)
            evidence_dir = result.evidence_dir
        elif skill_type == SkillType.EXECUTABLE_SCRIPT:
            result = self.h_executable_script.run(
                bundle_dir, nonce=synapse.nonce, canary_id=canary_id, canary_val=canary_val,
            )
            type_specific.executable_script = result.evidence
            findings = result.findings
            risk_score = self._risk_from_findings(findings)
            verdict_sources = ["L1_shell_taint", "L3_runtime"]
            evidence_pack = EvidencePack(base=result.base_evidence, type_specific=type_specific)
            evidence_dir = result.evidence_dir
        elif skill_type == SkillType.MCP_SERVER:
            result = self.h_mcp_server.run(
                bundle_dir, nonce=synapse.nonce, canary_id=canary_id, canary_val=canary_val,
            )
            type_specific.mcp_server = result.evidence
            findings = result.findings
            risk_score = max(
                self._risk_from_findings(findings),
                int(result.evidence.tool_poisoning_score * 100),
            )
            verdict_sources = ["L3_mcp_manifest", "L3_tool_calls"]
            evidence_pack = EvidencePack(base=result.base_evidence, type_specific=type_specific)
            evidence_dir = result.evidence_dir
        elif skill_type == SkillType.AGENT_COMPOSITION:
            depth = bundle.metadata.composition_depth or 5
            result = self.h_agent_composition.run(
                bundle_dir,
                nonce=synapse.nonce,
                canary_id=canary_id,
                canary_val=canary_val,
                composition_depth=depth,
            )
            type_specific.agent_composition = result.evidence
            findings = result.findings
            risk_score = max(
                self._risk_from_findings(findings),
                int(result.evidence.transitive_risk_score * 100),
            )
            verdict_sources = ["L3_composition", "L3_transitive_risk"]
            evidence_pack = EvidencePack(base=result.base_evidence, type_specific=type_specific)
            evidence_dir = result.evidence_dir
        else:
            raise ValueError(f"unsupported skill_type: {skill_type}")

        decision = self._verdict_from_risk(risk_score)
        confidence = 0.6 if findings else 0.85
        capabilities = self._capabilities_from_findings(findings)
        recommended_policy = self._policy_from_findings(findings, decision)

        sssa = SSSA(
            skill=SkillIdentity(
                name=bundle.metadata.skill_name,
                bundle_hash=bundle.bundle_hash,
                skill_type=skill_type,
                profile=bundle.metadata.profile,
            ),
            verdict=VerdictBlock(
                decision=decision,
                risk_score=risk_score,
                confidence=confidence,
                verdict_sources=verdict_sources,
            ),
            capabilities=capabilities,
            findings=findings,
            dependencies=Dependencies(),
            recommended_policy=recommended_policy,
            evidence=evidence_pack,
        )
        return sssa, evidence_dir

    @staticmethod
    def _risk_from_findings(findings: list) -> int:
        weights = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}
        score = 0
        for f in findings:
            sev = getattr(f.severity, "value", str(f.severity))
            score += weights.get(sev, 0)
        return min(100, score)

    @staticmethod
    def _verdict_from_risk(risk: int) -> Verdict:
        if risk >= 60:
            return Verdict.BLOCK
        if risk >= 25:
            return Verdict.WARN
        return Verdict.ALLOW

    @staticmethod
    def _capabilities_from_findings(findings: list) -> Capabilities:
        caps = Capabilities()
        for f in findings:
            title = getattr(f, "title", "")
            if title.startswith("network_egress"):
                snippet = getattr(f, "evidence_snippet", "")
                host = snippet.partition(":")[0]
                if host:
                    caps.network.ips.append(host)
            if title.startswith("process_spawn") or title.startswith("shell_command"):
                snippet = getattr(f, "evidence_snippet", "")
                first = snippet.split()
                if first:
                    caps.process_spawns.append(first[0])
                    caps.shell_commands.append(snippet)
            if title.startswith("secrets_leak"):
                caps.secrets_access.append(title.partition(":")[2] or "unknown")
        return caps

    @staticmethod
    def _policy_from_findings(findings: list, decision: Verdict) -> RecommendedPolicy:
        if decision == Verdict.BLOCK:
            return RecommendedPolicy(shell_access=False, max_memory_mb=256, timeout_s=15)
        denies: list[str] = []
        for f in findings:
            if getattr(f, "title", "").startswith("network_egress"):
                host = getattr(f, "evidence_snippet", "").partition(":")[0]
                if host:
                    denies.append(host)
        return RecommendedPolicy(
            egress_deny=denies,
            shell_access=False,
            max_memory_mb=512,
            timeout_s=30,
        )

    def _sign(self, sssa: SSSA) -> SSSA:
        canon = sssa.canonical_json().encode("utf-8")
        signature = self.wallet.hotkey.sign(canon).hex()
        sssa.attestation = AttestationBlock(
            miner_hotkey=self.wallet.hotkey.ss58_address,
            supported_types_declared=self.supported_types,
            ed25519_signature=signature,
            timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
        )
        return sssa

    def _materialise_bundle(self, bundle) -> Path:
        if bundle.bundle_bytes:
            tmp = Path(tempfile.mkdtemp(prefix="phylax-bundle-"))
            archive = tmp / "bundle.bin"
            archive.write_bytes(bundle.bundle_bytes)
            if zipfile.is_zipfile(archive):
                extract = (tmp / "extracted").resolve()
                extract.mkdir()
                self._safe_extract_zip(archive, extract)
                return extract
            single = tmp / "skill"
            single.mkdir()
            (single / "skill.bin").write_bytes(bundle.bundle_bytes)
            return single
        if bundle.bundle_url:
            raise ValueError("bundle_url path not yet wired in reference miner")
        raise ValueError("no bundle payload supplied")

    @staticmethod
    def _safe_extract_zip(archive: Path, dest: Path) -> None:
        max_total = 256 * 1024 * 1024
        max_member = 64 * 1024 * 1024
        dest_resolved = dest.resolve()
        running_total = 0
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ValueError(f"symlink not allowed in bundle: {member.filename}")
                if member.file_size > max_member:
                    raise ValueError(
                        f"member {member.filename} exceeds per-file size cap "
                        f"({member.file_size} > {max_member})"
                    )
                running_total += member.file_size
                if running_total > max_total:
                    raise ValueError("archive exceeds total uncompressed size cap")
                target = (dest_resolved / member.filename).resolve()
                if dest_resolved != target and dest_resolved not in target.parents:
                    raise ValueError(f"unsafe path in bundle archive: {member.filename}")
            zf.extractall(dest_resolved)

    def run(self):
        bt.logging.info(
            f"Starting Phylax miner on subnet {self.config.netuid} "
            f"| hotkey: {self.wallet.hotkey.ss58_address}"
        )
        self.axon.serve(netuid=self.config.netuid, subtensor=self.subtensor)
        self.axon.start()
        bt.logging.info(f"Axon serving on {self.axon.ip}:{self.axon.port}")

        step = 0
        while not self.should_exit:
            try:
                if step % 5 == 0:
                    self.metagraph.sync(subtensor=self.subtensor)
                    bt.logging.debug(f"Metagraph synced | step={step}")
                time.sleep(12)
                step += 1
            except KeyboardInterrupt:
                self.axon.stop()
                bt.logging.info("Miner stopped by KeyboardInterrupt")
                break
            except Exception as e:  # noqa: BLE001
                bt.logging.error(f"run loop error: {e}")
                time.sleep(12)


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
