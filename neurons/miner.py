import argparse
import asyncio
import datetime as dt
import hashlib
import os
import tempfile
import time
import traceback
import zipfile
from pathlib import Path

import bittensor as bt

from phylax.attestation.signer import AttestationSigner
from phylax.harness import (
    AgentCompositionHarness,
    DeclarativeHarness,
    ExecutablePythonHarness,
    ExecutableScriptHarness,
    MCPServerHarness,
    RAGKnowledgeHarness,
)
from phylax.pipeline.sandbox import SandboxDetonator
from phylax.pipeline.sbom import SBOMAnalyzer
from phylax.pipeline.static import StaticAnalyzer
from phylax.policy.generator import PolicyGenerator
from phylax.protocol import (
    SSSA,
    SSSAV04,
    AttestationBlockV04,
    CapabilitiesV04,
    DependenciesV04,
    EvidencePackV04,
    PhylaxSynapse,
    PhylaxSynapseV04,
    RecommendedPolicyV04,
    SkillBundle,
    SkillIdentityV04,
    SkillType,
    TypeSpecificEvidence,
    Verdict,
    VerdictBlockV04,
)
from phylax.utils.logging import get_logger

logger = get_logger(__name__)

V04_SKILL_TYPES = {t.value for t in SkillType}


class PhylaxMiner:
    """
    Phylax miner neuron.

    Implements the 3-layer analysis pipeline:
      1. Static analysis  (always runs)
      2. SBOM / supply-chain  (always runs)
      3. Behavioral sandbox detonation  (runs for standard + deep profiles)

    Produces a Signed Skill Safety Attestation (SSSA) for each skill bundle.
    """

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
        self.axon.attach(forward_fn=self.forward)
        self.axon.attach(forward_fn=self.forward_v04)
        self.should_exit = False
        self._build_internal_state()

    def _build_internal_state(self):
        """Initialize analysis pipeline components."""
        bt.logging.info("Initialising Phylax analysis pipeline…")

        self.static_analyzer  = StaticAnalyzer()
        self.sbom_analyzer    = SBOMAnalyzer()
        sandbox_cfg = getattr(self.config, "sandbox", None)
        sandbox_image = (
            getattr(sandbox_cfg, "image", None) if sandbox_cfg is not None else None
        )
        self.sandbox = SandboxDetonator(
            image=sandbox_image or os.getenv("PHYLAX_SANDBOX_IMAGE", "phylax-sandbox:latest"),
            timeout_seconds=int(os.getenv("SANDBOX_TIMEOUT", "60")),
        )
        self.policy_generator = PolicyGenerator()
        self.signer           = AttestationSigner(wallet=self.wallet)

        self.h_rag = RAGKnowledgeHarness()
        self.h_declarative = DeclarativeHarness()
        self.h_executable_python = ExecutablePythonHarness()
        self.h_executable_script = ExecutableScriptHarness()
        self.h_mcp_server = MCPServerHarness()
        self.h_agent_composition = AgentCompositionHarness()
        self.v04_supported_types: list[SkillType] = list(SkillType)

        bt.logging.info("Pipeline ready.")


    async def forward(self, synapse: PhylaxSynapse) -> PhylaxSynapse:
        """
        Main request handler.

        Called by the Axon server each time a validator sends a PhylaxSynapse.
        Runs the full pipeline and returns the signed SSSA.

        PR2: routes on ``skill_type`` from the bundle metadata.
          * ``declarative`` → Layer 0 only (no sandbox), declarative
            evidence block carries the canary read from SKILL.md.
          * ``executable`` (or unset) → existing Layer 1/2/3 pipeline.
          * ``mixed`` → runs both, stricter verdict wins, declarative
            evidence rides along inside the same SSSA.
        """
        bundle = synapse.skill_bundle
        skill_type = (bundle.metadata or {}).get("skill_type", "executable")
        bt.logging.info(
            f"Received scan request: {bundle.bundle_hash} "
            f"profile={bundle.test_profile} skill_type={skill_type}"
        )
        start_time = time.time()

        try:
            # Declarative-only branch: skip Layer 1/2/3 entirely. Layer 3
            # would produce no_entry (no Python entrypoint) and pin
            # evidence to 0; running it is wasted compute.
            if skill_type == "declarative":
                synapse = await self._run_declarative_pipeline(
                    synapse, bundle, start_time,
                )
                return synapse

            # Bundle-hash verification already happens inside
            # _resolve_bundle — if the downloaded bytes don't match
            # bundle.bundle_hash it raises before extraction.
            bundle_path = await self._resolve_bundle(bundle)

            bt.logging.debug("Running Layer 1: Static analysis…")
            static_result = await asyncio.to_thread(
                self.static_analyzer.analyze, bundle_path
            )

            bt.logging.debug("Running Layer 2: SBOM + supply-chain…")
            sbom_result = await asyncio.to_thread(
                self.sbom_analyzer.analyze, bundle_path
            )

            sandbox_result = None
            if bundle.test_profile.value in ("standard", "deep"):
                if not synapse.nonce:
                    raise ValueError("validator did not supply a nonce; refusing to detonate")
                bt.logging.debug(
                    f"Running Layer 3: Sandbox detonation (seed={synapse.nonce})…"
                )
                sandbox_result = await asyncio.to_thread(
                    self.sandbox.detonate,
                    bundle_path,
                    seed=int(synapse.nonce),
                    extended=(bundle.test_profile.value == "deep"),
                    canary_id=synapse.canary_id,
                    canary_val=synapse.canary_val,
                )

            findings       = static_result.findings + sbom_result.findings
            capabilities   = self._merge_capabilities(static_result, sbom_result, sandbox_result)
            evidence_pack  = self._build_evidence_pack(static_result, sbom_result, sandbox_result)

            verdict = self._compute_verdict(findings, capabilities, sbom_result, bundle_path)

            policy = self.policy_generator.generate(capabilities, findings)

            duration_ms = int((time.time() - start_time) * 1000)
            sssa = self._assemble_sssa(
                bundle=bundle,
                sbom_result=sbom_result,
                verdict=verdict,
                capabilities=capabilities,
                findings=findings,
                policy=policy,
                evidence_pack=evidence_pack,
                duration_ms=duration_ms,
                nonce=int(synapse.nonce or 0),
            )

            signed_sssa = self.signer.sign(sssa)

            synapse.attestation = signed_sssa.model_dump(mode="json")
            bt.logging.success(
                f"Scan complete: {bundle.bundle_hash} → {verdict.decision} "
                f"risk={verdict.risk_score} duration={duration_ms}ms"
            )

        except Exception as exc:
            bt.logging.error(f"Pipeline error for {bundle.bundle_hash}: {exc}")
            bt.logging.debug(traceback.format_exc())
            synapse.error = str(exc)

        return synapse

    async def blacklist(self, synapse: PhylaxSynapse) -> tuple[bool, str]:
        """
        Reject requests from unregistered UIDs.
        Validators must be registered on the subnet to receive service.
        """
        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey) \
            if synapse.dendrite.hotkey in self.metagraph.hotkeys else None

        if uid is None:
            return True, "Hotkey not registered on subnet"

        if not self.metagraph.validator_permit[uid]:
            return True, "Hotkey does not have validator permit"

        return False, "OK"

    async def priority(self, synapse: PhylaxSynapse) -> float:
        """
        Higher stake → higher priority.
        Prevents low-stake validators from flooding the miner queue.
        """
        uid = self.metagraph.hotkeys.index(synapse.dendrite.hotkey) \
            if synapse.dendrite.hotkey in self.metagraph.hotkeys else None
        if uid is None:
            return 0.0
        return float(self.metagraph.S[uid])

    async def _run_declarative_pipeline(
        self,
        synapse: PhylaxSynapse,
        bundle,
        start_time: float,
    ) -> PhylaxSynapse:
        """PR2 declarative pipeline. No sandbox, no Docker — just Layer 0
        text analysis over the SKILL.md the validator shipped in metadata.

        We prefer ``bundle.metadata['skill_md']`` over re-extracting from
        the bundle on disk because the metadata copy is the canary-bearing
        version the server baked. The on-disk SKILL.md doesn't carry the
        canary (the server doesn't re-hash bundles after injection — see
        ``phylax_server/workers/declarative_baseline.py``).
        """
        from phylax.layer0_declarative import (
            analyze_skill_md,
            compute_verdict_from_findings,
            derive_declarative_policy,
            extract_canary,
            layer0_sync_hash,
            skill_md_fingerprint,
        )
        from phylax.protocol import DeclarativeEvidenceBlock

        try:
            skill_md = (bundle.metadata or {}).get("skill_md")
            if not skill_md:
                # Fallback: try to extract from the bundle on disk so a
                # legacy server that hasn't been updated still produces
                # *some* declarative SSSA rather than a hard error.
                bundle_path = await self._resolve_bundle(bundle)
                skill_md = await asyncio.to_thread(
                    _extract_skill_md_from_dir, bundle_path,
                )

            caps, findings = await asyncio.to_thread(
                analyze_skill_md, skill_md or "",
            )
            verdict_block = compute_verdict_from_findings(findings)
            policy = derive_declarative_policy(caps, findings)

            duration_ms = int((time.time() - start_time) * 1000)

            sssa = self._assemble_declarative_sssa(
                bundle=bundle,
                verdict_block=verdict_block,
                capabilities=caps,
                findings=findings,
                policy=policy,
                declarative_evidence=DeclarativeEvidenceBlock(
                    canary_id_found=extract_canary(skill_md or ""),
                    skill_md_fingerprint=skill_md_fingerprint(skill_md or ""),
                    findings_count=len(findings),
                    layer0_sync_hash=layer0_sync_hash(),
                    analysis_duration_ms=duration_ms,
                ),
                duration_ms=duration_ms,
                nonce=int(synapse.nonce or 0),
            )
            signed_sssa = self.signer.sign(sssa)
            synapse.attestation = signed_sssa.model_dump(mode="json")
            bt.logging.success(
                f"Declarative scan complete: {bundle.bundle_hash} → "
                f"{verdict_block['decision']} risk={verdict_block['risk_score']} "
                f"findings={len(findings)} duration={duration_ms}ms"
            )
        except Exception as exc:
            bt.logging.error(
                f"Declarative pipeline error for {bundle.bundle_hash}: {exc}"
            )
            bt.logging.debug(traceback.format_exc())
            synapse.error = str(exc)
        return synapse


    async def _resolve_bundle(self, bundle: SkillBundle) -> str:
        """
        Returns a local filesystem path to the skill bundle.
        Downloads from URL if bundle_bytes not provided.

        The extraction directory MUST live under PHYLAX_EVIDENCE_DIR (which
        is bind-mounted from the host) so the sandbox container — launched
        via the host docker socket — can actually see the bundle. A path
        under /tmp would only exist inside the miner container, and the
        host dockerd would silently create an empty dir there and mount
        that empty dir into /skill, producing no observations.
        """
        import tempfile
        import zipfile

        staging_root = os.path.expanduser(
            os.getenv("PHYLAX_EVIDENCE_DIR", tempfile.gettempdir())
        )
        os.makedirs(staging_root, exist_ok=True)
        tmp_dir = tempfile.mkdtemp(prefix="phylax_bundle_", dir=staging_root)
        bundle_zip = os.path.join(tmp_dir, "bundle.zip")

        if bundle.bundle_bytes:
            with open(bundle_zip, "wb") as f:
                f.write(bundle.bundle_bytes)
        elif bundle.bundle_url:
            import urllib.request
            await asyncio.to_thread(urllib.request.urlretrieve, bundle.bundle_url, bundle_zip)
        else:
            raise ValueError("SkillBundle must have either bundle_bytes or bundle_url")

        with open(bundle_zip, "rb") as f:
            actual_hash = "sha256:" + hashlib.sha256(f.read()).hexdigest()
        if actual_hash != bundle.bundle_hash:
            raise ValueError(
                f"Bundle hash mismatch: expected {bundle.bundle_hash}, got {actual_hash}"
            )

        extract_dir = os.path.join(tmp_dir, "extracted")
        with zipfile.ZipFile(bundle_zip, "r") as zf:
            zf.extractall(extract_dir)

        return extract_dir

    def _merge_capabilities(self, static, sbom, sandbox) -> dict:
        """Merge capability observations from all three layers."""
        from phylax.protocol import (
            CapabilityMap,
            FilesystemCapability,
            NetworkCapability,
            ProcessCapability,
            SecretsCapability,
        )
        fs_reads   = list(set(static.fs_reads + (sandbox.fs_reads if sandbox else [])))
        fs_writes  = list(set(static.fs_writes + (sandbox.fs_writes if sandbox else [])))
        domains    = list(set(static.network_domains + (sandbox.network_domains if sandbox else [])))
        commands   = list(set(static.shell_commands + (sandbox.shell_commands if sandbox else [])))
        env_vars   = list(set(static.env_vars + (sandbox.env_vars if sandbox else [])))

        return CapabilityMap(
            filesystem=FilesystemCapability(reads=fs_reads, writes=fs_writes),
            network=NetworkCapability(
                egress=bool(domains),
                observed_domains=domains,
            ),
            process=ProcessCapability(
                spawns=bool(commands),
                shell_exec=any("sh" in c or "bash" in c for c in commands),
                observed_commands=commands,
            ),
            secrets=SecretsCapability(
                env_access=bool(env_vars),
                observed_vars=env_vars,
            ),
        )

    def _build_evidence_pack(self, static, sbom, sandbox) -> dict:
        from phylax.protocol import EvidencePack
        return EvidencePack(
            network_trace_hash=sandbox.network_trace_hash if sandbox else None,
            fs_trace_hash=sandbox.fs_trace_hash if sandbox else None,
            process_trace_hash=sandbox.process_trace_hash if sandbox else None,
            secrets_trace_hash=sandbox.secrets_trace_hash if sandbox else None,
            sandbox_log_hash=sandbox.log_hash if sandbox else None,
        )

    def _compute_verdict(self, findings, capabilities, sbom_result, bundle_path):
        """Verdict = manifest-vs-observed discrepancy, combined with static
        findings and SBOM CVEs.

        Replaces the old hand-coded heuristic. The shared
        ``phylax.scoring.discrepancy`` engine compares what the sandbox
        observed against the bundle's declared SKILL.md (or
        IMPLICIT_ZERO_TRUST when no manifest exists). Miner and validator
        run the identical function so an honest miner matches the
        validator's verdict by construction.
        """
        from phylax.manifest import load_manifest
        from phylax.scoring.discrepancy import combine_verdict, compute_discrepancy

        manifest = load_manifest(bundle_path)
        discrepancy = compute_discrepancy(capabilities, manifest)
        return combine_verdict(discrepancy, findings, sbom_result.known_vulns)

    def _assemble_declarative_sssa(self, bundle, verdict_block, capabilities,
                                   findings, policy, declarative_evidence,
                                   duration_ms, nonce) -> SSSA:
        """Build an SSSA from declarative-pipeline outputs.

        Same SSSA shape as the executable path so the validator's
        scoring code doesn't fork on type — only the evidence block's
        ``declarative`` field is populated and the trace hashes stay
        None (a declarative skill never executes).
        """
        from phylax.protocol import SSSA as _SSSA
        from phylax.protocol import (
            CapabilityMap,
            DependencyInfo,
            EvidencePack,
            FilesystemCapability,
            Finding,
            FindingEvidence,
            NetworkCapability,
            ProcessCapability,
            RecommendedPolicy,
            RunMetadata,
            SecretsCapability,
            Severity,
            SkillIdentity,
            Verdict,
            VerdictBlock,
        )

        proto_findings = [
            Finding(
                severity=Severity(f.severity),
                title=f.kind,
                description=f.description,
                evidence=FindingEvidence(snippet=f.snippet),
            )
            for f in findings
        ]
        cap_map = CapabilityMap(
            network=NetworkCapability(
                egress=bool(capabilities.observed_hosts),
                observed_domains=list(capabilities.observed_hosts),
                observed_ips=[],
            ),
            filesystem=FilesystemCapability(reads=[], writes=[]),
            process=ProcessCapability(
                spawns=False,
                shell_exec=capabilities.references_shell,
                observed_commands=[],
            ),
            secrets=SecretsCapability(
                env_access=capabilities.references_secrets,
                observed_vars=[],
            ),
        )
        # ``derive_declarative_policy`` adds a ``_derivation`` audit key
        # that isn't part of RecommendedPolicy. Strip private keys so the
        # model validation doesn't reject the dict.
        policy_clean = {k: v for k, v in policy.items() if not k.startswith("_")}
        return _SSSA(
            skill=SkillIdentity(
                name=bundle.metadata.get("name", "unknown"),
                version=bundle.metadata.get("version", "unknown"),
                bundle_hash=bundle.bundle_hash,
                sbom_hash=None,
                declared_permissions=bundle.metadata.get("permissions", []),
            ),
            verdict=VerdictBlock(
                decision=Verdict(verdict_block["decision"]),
                risk_score=int(verdict_block["risk_score"]),
                confidence=1.0,
                summary=verdict_block.get("rationale", "")[:240],
            ),
            capabilities=cap_map,
            findings=proto_findings,
            dependencies=DependencyInfo(
                sbom_hash=None,
                high_risk_packages=[],
                known_vulns=[],
                install_hooks=[],
            ),
            recommended_policy=RecommendedPolicy(**policy_clean),
            evidence=EvidencePack(declarative=declarative_evidence),
            run_metadata=RunMetadata(
                tools={"layer0_declarative": declarative_evidence.layer0_sync_hash},
                determinism_seed=int(nonce),
                analysis_duration_ms=duration_ms,
            ),
        )

    def _assemble_sssa(self, bundle, sbom_result, verdict, capabilities,
                       findings, policy, evidence_pack, duration_ms, nonce) -> SSSA:
        from phylax.protocol import SSSA, DependencyInfo, RunMetadata, SkillIdentity

        return SSSA(
            skill=SkillIdentity(
                name=bundle.metadata.get("name", "unknown"),
                version=bundle.metadata.get("version", "unknown"),
                bundle_hash=bundle.bundle_hash,
                sbom_hash=sbom_result.sbom_hash,
                declared_permissions=bundle.metadata.get("permissions", []),
            ),
            verdict=verdict,
            capabilities=capabilities,
            findings=findings,
            dependencies=DependencyInfo(
                sbom_hash=sbom_result.sbom_hash,
                high_risk_packages=sbom_result.high_risk_packages,
                known_vulns=sbom_result.known_vulns,
                install_hooks=sbom_result.install_hooks,
            ),
            recommended_policy=policy,
            evidence=evidence_pack,
            run_metadata=RunMetadata(
                tools={
                    "bandit": "1.7.5",
                    "syft": "1.0.0",
                    "cyclonedx-bom": "4.3.0",
                },
                determinism_seed=int(nonce),
                analysis_duration_ms=duration_ms,
            ),
        )


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
            except Exception as e:
                bt.logging.error(f"Run loop error: {e}")
                time.sleep(12)


    async def forward_v04(self, synapse: PhylaxSynapseV04) -> PhylaxSynapseV04:
        bundle = synapse.skill_bundle
        skill_type = bundle.metadata.skill_type
        bt.logging.info(
            f"v0.4 scan: bundle={bundle.bundle_hash} type={skill_type.value} "
            f"profile={bundle.metadata.profile.value} "
            f"task={synapse.task_metadata.task_id}"
        )
        try:
            bundle_dir = await asyncio.to_thread(self._materialise_v04_bundle, bundle)
            sssa = await asyncio.to_thread(self._dispatch_v04, skill_type, bundle_dir, synapse)
            sssa = self._sign_v04(sssa)
            synapse.attestation = sssa.model_dump(mode="json")
            bt.logging.success(
                f"v0.4 scan complete: {bundle.bundle_hash} -> "
                f"{sssa.verdict.decision.value} risk={sssa.verdict.risk_score}"
            )
        except Exception as exc:  # noqa: BLE001
            bt.logging.error(f"v0.4 pipeline error for {bundle.bundle_hash}: {exc}")
            bt.logging.debug(traceback.format_exc())
            synapse.error = str(exc)
        return synapse

    def _dispatch_v04(self, skill_type, bundle_dir, synapse):
        canary_id = synapse.task_metadata.task_id
        canary_val = synapse.nonce
        bundle = synapse.skill_bundle

        type_specific = TypeSpecificEvidence()
        findings: list = []
        verdict_sources: list[str] = []
        risk_score = 0
        evidence_pack = EvidencePackV04()

        if skill_type == SkillType.RAG_KNOWLEDGE:
            result = self.h_rag.run(bundle_dir, canary_id=canary_id)
            type_specific.rag_knowledge = result.evidence
            findings = result.findings
            risk_score = min(100, int(result.evidence.hidden_instruction_score * 100))
            verdict_sources = ["L0_content"]
            evidence_pack = EvidencePackV04(type_specific=type_specific)
        elif skill_type == SkillType.DECLARATIVE:
            result = self.h_declarative.run(bundle_dir, canary_id=canary_id)
            type_specific.declarative = result.evidence
            findings = result.findings
            risk_score = min(100, int(result.evidence.prompt_injection_ml_score * 100))
            verdict_sources = ["L0_declarative"]
            evidence_pack = EvidencePackV04(type_specific=type_specific)
        elif skill_type == SkillType.EXECUTABLE_PYTHON:
            result = self.h_executable_python.run(
                bundle_dir, nonce=synapse.nonce, canary_id=canary_id, canary_val=canary_val,
            )
            type_specific.executable_python = result.evidence
            findings = result.findings
            risk_score = self._risk_from_v04_findings(findings)
            verdict_sources = ["L1_taint", "L2_sbom", "L3_runtime"]
            evidence_pack = EvidencePackV04(base=result.base_evidence, type_specific=type_specific)
        elif skill_type == SkillType.EXECUTABLE_SCRIPT:
            result = self.h_executable_script.run(
                bundle_dir, nonce=synapse.nonce, canary_id=canary_id, canary_val=canary_val,
            )
            type_specific.executable_script = result.evidence
            findings = result.findings
            risk_score = self._risk_from_v04_findings(findings)
            verdict_sources = ["L1_shell_taint", "L3_runtime"]
            evidence_pack = EvidencePackV04(base=result.base_evidence, type_specific=type_specific)
        elif skill_type == SkillType.MCP_SERVER:
            result = self.h_mcp_server.run(
                bundle_dir, nonce=synapse.nonce, canary_id=canary_id, canary_val=canary_val,
            )
            type_specific.mcp_server = result.evidence
            findings = result.findings
            risk_score = max(
                self._risk_from_v04_findings(findings),
                int(result.evidence.tool_poisoning_score * 100),
            )
            verdict_sources = ["L3_mcp_manifest", "L3_tool_calls"]
            evidence_pack = EvidencePackV04(base=result.base_evidence, type_specific=type_specific)
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
                self._risk_from_v04_findings(findings),
                int(result.evidence.transitive_risk_score * 100),
            )
            verdict_sources = ["L3_composition", "L3_transitive_risk"]
            evidence_pack = EvidencePackV04(base=result.base_evidence, type_specific=type_specific)
        else:
            raise ValueError(f"unsupported skill_type: {skill_type}")

        decision = self._verdict_from_risk(risk_score)
        confidence = 0.6 if findings else 0.85
        capabilities = self._capabilities_from_v04_findings(findings)
        recommended_policy = self._policy_from_v04(findings, decision)

        return SSSAV04(
            skill=SkillIdentityV04(
                name=bundle.metadata.skill_name,
                bundle_hash=bundle.bundle_hash,
                skill_type=skill_type,
                profile=bundle.metadata.profile,
            ),
            verdict=VerdictBlockV04(
                decision=decision,
                risk_score=risk_score,
                confidence=confidence,
                verdict_sources=verdict_sources,
            ),
            capabilities=capabilities,
            findings=findings,
            dependencies=DependenciesV04(),
            recommended_policy=recommended_policy,
            evidence=evidence_pack,
        )

    @staticmethod
    def _risk_from_v04_findings(findings: list) -> int:
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
    def _capabilities_from_v04_findings(findings: list) -> CapabilitiesV04:
        caps = CapabilitiesV04()
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
    def _policy_from_v04(findings: list, decision: Verdict) -> RecommendedPolicyV04:
        if decision == Verdict.BLOCK:
            return RecommendedPolicyV04(shell_access=False, max_memory_mb=256, timeout_s=15)
        denies: list[str] = []
        for f in findings:
            if getattr(f, "title", "").startswith("network_egress"):
                host = getattr(f, "evidence_snippet", "").partition(":")[0]
                if host:
                    denies.append(host)
        return RecommendedPolicyV04(
            egress_deny=denies,
            shell_access=False,
            max_memory_mb=512,
            timeout_s=30,
        )

    def _sign_v04(self, sssa: SSSAV04) -> SSSAV04:
        canon = sssa.canonical_json().encode("utf-8")
        signature = self.wallet.hotkey.sign(canon).hex()
        sssa.attestation = AttestationBlockV04(
            miner_hotkey=self.wallet.hotkey.ss58_address,
            supported_types_declared=self.v04_supported_types,
            ed25519_signature=signature,
            timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
        )
        return sssa

    def _materialise_v04_bundle(self, bundle) -> Path:
        if bundle.bundle_bytes:
            tmp = Path(tempfile.mkdtemp(prefix="phylax-v04-bundle-"))
            archive = tmp / "bundle.bin"
            archive.write_bytes(bundle.bundle_bytes)
            if zipfile.is_zipfile(archive):
                extract = tmp / "extracted"
                extract.mkdir()
                with zipfile.ZipFile(archive) as zf:
                    zf.extractall(extract)
                return extract
            single = tmp / "skill"
            single.mkdir()
            (single / "skill.bin").write_bytes(bundle.bundle_bytes)
            return single
        if bundle.bundle_url:
            raise ValueError("bundle_url path not yet wired in reference miner")
        raise ValueError("no bundle payload supplied")


_SKILL_MD_NAMES = ("skill.md", "skill.markdown", "readme.md")


def _extract_skill_md_from_dir(bundle_path: str) -> str | None:
    """Walk the extracted bundle for a SKILL.md (or .markdown / README.md
    fallback). The on-disk copy doesn't carry the server-injected canary
    — the canary lives in ``bundle.metadata['skill_md']``, the metadata
    copy — but this fallback exists for the case where a legacy server
    didn't bake the canary in the first place.
    """
    import os
    for root, _dirs, files in os.walk(bundle_path):
        for name in files:
            if name.lower() in _SKILL_MD_NAMES:
                try:
                    with open(os.path.join(root, name), encoding="utf-8",
                              errors="replace") as fh:
                        return fh.read()
                except OSError:
                    continue
    return None


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


def main():
    parser = argparse.ArgumentParser(description="Phylax miner neuron")
    parser.add_argument("--netuid", type=int, required=True,
                        help="Subnet netuid to mine on")
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

