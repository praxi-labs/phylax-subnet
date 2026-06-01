from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from phylax.protocol import (
    AgentCompositionEvidence,
    EvidenceBaseV04,
    FindingLayer,
    FindingSeverityV04,
    FindingType,
    FindingV04,
)

DEFAULT_HARNESS_IMAGE = "ghcr.io/praxi-labs/phylax-harness-agent-composition:latest"

_COMPOSITION_CANDIDATES = (
    "composition.json",
    "composition.yaml",
    "composition.yml",
    "manifest.json",
)


@dataclass
class AgentCompositionHarnessResult:
    evidence: AgentCompositionEvidence
    base_evidence: EvidenceBaseV04
    findings: list[FindingV04] = field(default_factory=list)
    evidence_dir: Path | None = None
    exit_code: int = 0
    log: str = ""


class AgentCompositionHarness:
    def __init__(
        self,
        image: str = DEFAULT_HARNESS_IMAGE,
        timeout_seconds: int = 300,
        memory_limit_mb: int = 1024,
        cpus: float = 2.0,
        max_depth: int = 5,
    ) -> None:
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.memory_limit_mb = memory_limit_mb
        self.cpus = cpus
        self.max_depth = max_depth

    def run(
        self,
        bundle_path: str | Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
        composition_depth: int | None = None,
        evidence_dir: str | Path | None = None,
    ) -> AgentCompositionHarnessResult:
        bundle = Path(bundle_path).resolve()
        if not bundle.exists():
            raise FileNotFoundError(f"bundle_path does not exist: {bundle}")

        evidence_root = (
            Path(evidence_dir).resolve()
            if evidence_dir
            else Path(tempfile.mkdtemp(prefix="phylax-evidence-"))
        )
        evidence_root.mkdir(parents=True, exist_ok=True)
        for f in (
            "network.jsonl",
            "fs.jsonl",
            "process.jsonl",
            "secrets.jsonl",
            "agent_calls.jsonl",
            "dependency_graph.json",
        ):
            (evidence_root / f).unlink(missing_ok=True)

        depth_cap = composition_depth or self.max_depth
        exit_code, log = self._detonate(
            bundle, evidence_root, nonce, canary_id, canary_val, depth_cap
        )

        for f in ("network.jsonl", "fs.jsonl", "process.jsonl", "secrets.jsonl", "agent_calls.jsonl"):
            (evidence_root / f).touch(exist_ok=True)
        if not (evidence_root / "dependency_graph.json").exists():
            (evidence_root / "dependency_graph.json").write_text("{}", encoding="utf-8")

        graph_path = evidence_root / "dependency_graph.json"
        try:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            graph = {}
        if not isinstance(graph, dict):
            graph = {}

        agent_calls = _jsonl_records(evidence_root / "agent_calls.jsonl")
        observed_depth = max((int(r.get("depth", 0)) for r in agent_calls), default=0)
        transitive_risk = self._compute_transitive_risk(graph, agent_calls)

        base = EvidenceBaseV04(
            network_trace_hash=_sha256_file(evidence_root / "network.jsonl"),
            fs_trace_hash=_sha256_file(evidence_root / "fs.jsonl"),
            process_trace_hash=_sha256_file(evidence_root / "process.jsonl"),
            secrets_trace_hash=_sha256_file(evidence_root / "secrets.jsonl"),
        )
        ev = AgentCompositionEvidence(
            agent_calls_hash=_sha256_file(evidence_root / "agent_calls.jsonl")
            or "sha256:" + ("0" * 64),
            dependency_graph_hash=_sha256_file(graph_path) or "sha256:" + ("0" * 64),
            transitive_risk_score=transitive_risk,
            composition_depth_observed=observed_depth,
        )
        findings = self._distill_findings(graph, agent_calls, transitive_risk)
        return AgentCompositionHarnessResult(
            evidence=ev,
            base_evidence=base,
            findings=findings,
            evidence_dir=evidence_root,
            exit_code=exit_code,
            log=log,
        )

    def _detonate(
        self,
        bundle: Path,
        evidence_root: Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
        depth_cap: int,
    ) -> tuple[int, str]:
        if not shutil.which("docker"):
            return self._detonate_in_process(
                bundle, evidence_root, nonce, canary_id, canary_val, depth_cap
            )
        cmd = [
            "docker", "run", "--rm",
            "--cap-drop=ALL",
            "--memory", f"{self.memory_limit_mb}m",
            "--cpus", str(self.cpus),
            "--tmpfs", "/tmp:rw,size=128m",  # noqa: S108
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{bundle}:/skill:ro",
            "-v", f"{evidence_root}:/evidence",
            "-e", f"CANARY_ID={canary_id}",
            "-e", f"CANARY_VAL={canary_val}",
            "-e", f"PHYLAX_NONCE={nonce}",
            "-e", f"AGENT_TIMEOUT={self.timeout_seconds}",
            "-e", f"COMPOSITION_DEPTH={depth_cap}",
            self.image,
            "/skill", str(nonce),
        ]
        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds + 30,
            )
            return proc.returncode, proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return 124, "harness timed out"
        except FileNotFoundError:
            return self._detonate_in_process(
                bundle, evidence_root, nonce, canary_id, canary_val, depth_cap
            )

    def _detonate_in_process(
        self,
        bundle: Path,
        evidence_root: Path,
        nonce: str,
        canary_id: str,
        canary_val: str,
        depth_cap: int,
    ) -> tuple[int, str]:
        env = {
            **os.environ,
            "CANARY_ID": canary_id,
            "CANARY_VAL": canary_val,
            "PHYLAX_NONCE": nonce,
            "AGENT_TIMEOUT": str(self.timeout_seconds),
            "COMPOSITION_DEPTH": str(depth_cap),
        }
        tracer = Path(__file__).parent / "container" / "orchestrator.py"
        cmd = ["python", str(tracer), str(bundle), str(nonce), str(evidence_root)]
        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=env,
            )
            return proc.returncode, proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return 124, "in-process orchestrator timed out"

    def _compute_transitive_risk(
        self,
        graph: dict,
        agent_calls: list[dict],
    ) -> float:
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        if not isinstance(nodes, list) or not nodes:
            return 0.0
        verdict_rank = {"ALLOW": 0.0, "WARN": 0.5, "BLOCK": 1.0, "UNKNOWN": 0.4}
        node_risk: dict[str, float] = {}
        for node in nodes:
            if not isinstance(node, dict):
                continue
            name = str(node.get("name") or "")
            verdict = str(node.get("verdict") or "UNKNOWN").upper()
            node_risk[name] = verdict_rank.get(verdict, 0.4)
        for call in agent_calls:
            callee = str(call.get("callee_skill") or "")
            v = str(call.get("callee_verdict") or "UNKNOWN").upper()
            node_risk[callee] = max(node_risk.get(callee, 0.0), verdict_rank.get(v, 0.4))
        edges = graph.get("edges") if isinstance(graph, dict) else None
        if isinstance(edges, list):
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                parent = str(edge.get("from") or "")
                child = str(edge.get("to") or "")
                if parent and child and child in node_risk:
                    node_risk[parent] = max(node_risk.get(parent, 0.0), node_risk[child] * 0.8)
        if not node_risk:
            return 0.0
        return min(1.0, max(node_risk.values()))

    def _distill_findings(
        self,
        graph: dict,
        agent_calls: list[dict],
        transitive_risk: float,
    ) -> list[FindingV04]:
        findings: list[FindingV04] = []
        if transitive_risk >= 0.5:
            findings.append(
                FindingV04(
                    finding_id=str(uuid.uuid4()),
                    severity=FindingSeverityV04.HIGH
                    if transitive_risk >= 0.8
                    else FindingSeverityV04.MEDIUM,
                    title="composition_transitive_risk",
                    description=(
                        f"Composition propagates risk={transitive_risk:.2f} from descendants. "
                        "A safe parent invokes unsafe children."
                    ),
                    owasp_ref="A06",
                    mitre_ref="T1611",
                    evidence_snippet="",
                    layer_source=FindingLayer.L3,
                    finding_type=FindingType.MANIFEST,
                )
            )
        if isinstance(graph, dict):
            cycle = _detect_cycle(graph)
            if cycle:
                findings.append(
                    FindingV04(
                        finding_id=str(uuid.uuid4()),
                        severity=FindingSeverityV04.HIGH,
                        title="composition_cycle",
                        description="Cycle detected in composition dependency graph: " + " -> ".join(cycle),
                        owasp_ref=None,
                        mitre_ref=None,
                        evidence_snippet=" -> ".join(cycle),
                        layer_source=FindingLayer.L3,
                        finding_type=FindingType.MANIFEST,
                    )
                )
        for call in agent_calls:
            if str(call.get("call_type") or "").lower() == "spawn":
                findings.append(
                    FindingV04(
                        finding_id=str(uuid.uuid4()),
                        severity=FindingSeverityV04.MEDIUM,
                        title="composition_unbounded_spawn",
                        description=(
                            f"{call.get('caller_skill')} spawned {call.get('callee_skill')} at "
                            f"depth={call.get('depth')}."
                        ),
                        owasp_ref=None,
                        mitre_ref="T1611",
                        evidence_snippet=json.dumps(call, sort_keys=True)[:200],
                        layer_source=FindingLayer.L3,
                        finding_type=FindingType.RUNTIME,
                    )
                )
        return findings


def _detect_cycle(graph: dict) -> list[str]:
    edges = graph.get("edges") if isinstance(graph, dict) else None
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    if not isinstance(edges, list) or not isinstance(nodes, list):
        return []
    adj: dict[str, list[str]] = {}
    for n in nodes:
        if isinstance(n, dict):
            adj.setdefault(str(n.get("name") or ""), [])
    for e in edges:
        if not isinstance(e, dict):
            continue
        adj.setdefault(str(e.get("from") or ""), []).append(str(e.get("to") or ""))

    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {k: WHITE for k in adj}
    stack: list[str] = []

    def dfs(node: str) -> list[str]:
        color[node] = GRAY
        stack.append(node)
        for nxt in adj.get(node, []):
            if color.get(nxt, WHITE) == GRAY:
                idx = stack.index(nxt) if nxt in stack else 0
                return stack[idx:] + [nxt]
            if color.get(nxt, WHITE) == WHITE:
                cyc = dfs(nxt)
                if cyc:
                    return cyc
        stack.pop()
        color[node] = BLACK
        return []

    for node in list(adj.keys()):
        if color.get(node, WHITE) == WHITE:
            cyc = dfs(node)
            if cyc:
                return cyc
    return []


def _sha256_file(path: Path) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def _jsonl_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
