import argparse
import asyncio
import hashlib
import os
import time
import traceback

import bittensor as bt

from phylax.attestation.signer import AttestationSigner
from phylax.pipeline.sandbox import SandboxDetonator
from phylax.pipeline.sbom import SBOMAnalyzer
from phylax.pipeline.static import StaticAnalyzer
from phylax.policy.generator import PolicyGenerator
from phylax.protocol import SSSA, PhylaxSynapse, SkillBundle
from phylax.utils.logging import get_logger

logger = get_logger(__name__)


class PhylaxMiner(bt.BaseNeuron if hasattr(bt, "BaseNeuron") else object):
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
        if hasattr(bt, "BaseNeuron"):
            super().__init__(config=config)
            # BaseNeuron in 9.x rebuilds self.wallet / self.subtensor from
            # config, which doesn't reliably honour --subtensor.network from
            # dotted CLI args, so override with the explicit objects main()
            # constructed (it parses argv directly).
            if wallet is not None:
                self.wallet = wallet
            if subtensor is not None:
                self.subtensor = subtensor
                self.metagraph = self.subtensor.metagraph(netuid=config.netuid)
            if not hasattr(self, "should_exit"):
                self.should_exit = False
        else:
            # bittensor 10.x removed BaseNeuron — wire up the standard
            # wallet/subtensor/metagraph/axon manually.
            self.config = config
            if callable(bt.logging):
                bt.logging(config=config)
            elif hasattr(bt.logging, "set_config"):
                bt.logging.set_config(config)
            self.wallet = wallet if wallet is not None else bt.Wallet(config=config)
            self.subtensor = subtensor if subtensor is not None else bt.Subtensor(config=config)
            self.metagraph = bt.Metagraph(
                netuid=config.netuid,
                network=self.subtensor.network,
                lite=True,
                sync=False,
            )
            try:
                self.metagraph.sync(subtensor=self.subtensor, lite=True)
            except Exception as e:  # noqa: BLE001
                # Fresh testnet subnets sometimes return a WASM trap from
                # NeuronInfoRuntimeApi while the chain warms up. Axon
                # serving doesn't need the metagraph; retry later.
                bt.logging.warning(
                    f"initial metagraph sync failed ({e!r}); continuing with "
                    "empty metagraph — will retry on next loop"
                )
            self.axon = bt.Axon(wallet=self.wallet, config=config)
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
            timeout_seconds=int(os.getenv("SANDBOX_TIMEOUT", "120")),
        )
        self.policy_generator = PolicyGenerator()
        self.signer           = AttestationSigner(wallet=self.wallet)

        bt.logging.info("Pipeline ready.")

    # -----------------------------------------------------------------------
    # Bittensor lifecycle hooks
    # -----------------------------------------------------------------------

    async def forward(self, synapse: PhylaxSynapse) -> PhylaxSynapse:
        """
        Main request handler.

        Called by the Axon server each time a validator sends a PhylaxSynapse.
        Runs the full pipeline and returns the signed SSSA.
        """
        bundle = synapse.skill_bundle
        bt.logging.info(f"Received scan request: {bundle.bundle_hash} profile={bundle.test_profile}")
        start_time = time.time()

        try:
            # ------------------------------------------------------------------
            # Resolve the skill bundle (download if URL provided)
            # ------------------------------------------------------------------
            bundle_path = await self._resolve_bundle(bundle)

            # ------------------------------------------------------------------
            # Layer 1: Static analysis
            # ------------------------------------------------------------------
            bt.logging.debug("Running Layer 1: Static analysis…")
            static_result = await asyncio.to_thread(
                self.static_analyzer.analyze, bundle_path
            )

            # ------------------------------------------------------------------
            # Layer 2: SBOM + supply-chain
            # ------------------------------------------------------------------
            bt.logging.debug("Running Layer 2: SBOM + supply-chain…")
            sbom_result = await asyncio.to_thread(
                self.sbom_analyzer.analyze, bundle_path
            )

            # Layer 3: sandbox detonation (standard + deep profiles only).
            # The seed is synapse.nonce — without it, evidence hashes would
            # not be miner-unique, so we refuse to detonate.
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
                )

            # ------------------------------------------------------------------
            # Aggregate findings + build capability map
            # ------------------------------------------------------------------
            findings       = static_result.findings + sbom_result.findings
            capabilities   = self._merge_capabilities(static_result, sbom_result, sandbox_result)
            evidence_pack  = self._build_evidence_pack(static_result, sbom_result, sandbox_result)

            # ------------------------------------------------------------------
            # Compute verdict
            # ------------------------------------------------------------------
            verdict = self._compute_verdict(findings, capabilities, sbom_result)

            # ------------------------------------------------------------------
            # Generate recommended policy
            # ------------------------------------------------------------------
            policy = self.policy_generator.generate(capabilities, findings)

            # ------------------------------------------------------------------
            # Assemble SSSA
            # ------------------------------------------------------------------
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

            # ------------------------------------------------------------------
            # Sign the attestation
            # ------------------------------------------------------------------
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

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    async def _resolve_bundle(self, bundle: SkillBundle) -> str:
        """
        Returns a local filesystem path to the skill bundle.
        Downloads from URL if bundle_bytes not provided.
        """
        import tempfile
        import zipfile

        tmp_dir = tempfile.mkdtemp(prefix="phylax_bundle_")
        bundle_zip = os.path.join(tmp_dir, "bundle.zip")

        if bundle.bundle_bytes:
            with open(bundle_zip, "wb") as f:
                f.write(bundle.bundle_bytes)
        elif bundle.bundle_url:
            import urllib.request
            await asyncio.to_thread(urllib.request.urlretrieve, bundle.bundle_url, bundle_zip)
        else:
            raise ValueError("SkillBundle must have either bundle_bytes or bundle_url")

        # Verify hash integrity
        with open(bundle_zip, "rb") as f:
            actual_hash = "sha256:" + hashlib.sha256(f.read()).hexdigest()
        if actual_hash != bundle.bundle_hash:
            raise ValueError(
                f"Bundle hash mismatch: expected {bundle.bundle_hash}, got {actual_hash}"
            )

        # Extract
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

    def _compute_verdict(self, findings, capabilities, sbom_result):
        """
        Compute the verdict based on findings severity and capabilities.

        Rules:
        - Any CRITICAL finding → BLOCK
        - Any HIGH finding OR known_vuln in deps → WARN
        - Shell exec observed → WARN (at minimum)
        - Exfiltration patterns → BLOCK
        - Otherwise → ALLOW
        """
        from phylax.protocol import Severity, Verdict, VerdictBlock

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high     = [f for f in findings if f.severity == Severity.HIGH]

        if critical or (capabilities.network.egress and capabilities.secrets.env_access
                        and capabilities.process.shell_exec):
            decision   = Verdict.BLOCK
            risk_score = min(100, 75 + len(critical) * 5)
        elif high or sbom_result.known_vulns or capabilities.process.shell_exec:
            decision   = Verdict.WARN
            risk_score = min(74, 40 + len(high) * 8)
        else:
            decision   = Verdict.ALLOW
            risk_score = max(0, len(findings) * 3)

        severity_names = {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "HIGH",
            Severity.MEDIUM: "MEDIUM",
            Severity.LOW: "LOW",
        }
        top_reasons = [
            f"[{severity_names[f.severity]}] {f.title}" for f in (critical + high)[:3]
        ]

        # Confidence rises with observation surface area; sandbox runs that
        # actually saw network/process/fs activity give us more to base the
        # verdict on than a static-only scan.
        observations = (
            int(capabilities.network.egress)
            + int(capabilities.process.spawns)
            + int(capabilities.secrets.env_access)
            + int(bool(capabilities.filesystem.reads or capabilities.filesystem.writes))
        )
        confidence = round(min(0.99, 0.70 + 0.07 * observations), 2)

        summary = (
            f"Verdict {decision.value}: risk_score={risk_score}. "
            f"{len(findings)} finding(s). "
            f"Networks contacted: {capabilities.network.observed_domains or 'none'}."
        )

        return VerdictBlock(
            decision=decision,
            risk_score=risk_score,
            confidence=confidence,
            summary=summary,
            top_reasons=top_reasons,
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

    # -----------------------------------------------------------------------
    # Standard Bittensor neuron run loop
    # -----------------------------------------------------------------------

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

                time.sleep(12)  # One block
                step += 1

            except KeyboardInterrupt:
                self.axon.stop()
                bt.logging.info("Miner stopped by KeyboardInterrupt")
                break
            except Exception as e:
                bt.logging.error(f"Run loop error: {e}")
                time.sleep(12)


def main():
    parser = argparse.ArgumentParser(description="Phylax miner neuron")
    parser.add_argument("--netuid", type=int, required=True,
                        help="Subnet netuid to mine on")
    bt.Wallet.add_args(parser)
    bt.Subtensor.add_args(parser)
    bt.logging.add_args(parser)
    bt.Axon.add_args(parser)
    config = bt.Config(parser)

    if hasattr(bt, "BaseNeuron"):
        # bittensor 9.x: bt.Config properly promotes dotted CLI args
        # (--wallet.name, --subtensor.network) into nested config nodes.
        # Wallet is fine to build from config, but bt.Subtensor(config=...)
        # honours config.subtensor.chain_endpoint, whose default is the
        # mainnet finney URL — that silently overrides --subtensor.network.
        # Pass network= explicitly so a known name like "test" resolves
        # to the correct testnet endpoint and chain_endpoint stays out.
        wallet = bt.Wallet(config=config)
        subtensor = bt.Subtensor(network=config.subtensor.network)
    else:
        # bittensor 10.x: bt.Config doesn't reliably promote dotted CLI
        # args, so parse argparse directly and build explicitly. The
        # network kwarg in 10.x accepts a known name ("test", "finney")
        # or a full WebSocket URL, so chain_endpoint folds into it.
        args, _ = parser.parse_known_args()
        wallet_name = getattr(args, "wallet.name", None) or "default"
        wallet_hotkey = getattr(args, "wallet.hotkey", None) or "default"
        network = getattr(args, "subtensor.network", None) or "finney"
        chain_endpoint = getattr(args, "subtensor.chain_endpoint", None) or None
        wallet = bt.Wallet(name=wallet_name, hotkey=wallet_hotkey)
        subtensor = bt.Subtensor(network=chain_endpoint or network)

    miner = PhylaxMiner(config=config, wallet=wallet, subtensor=subtensor)
    miner.run()


if __name__ == "__main__":
    main()
