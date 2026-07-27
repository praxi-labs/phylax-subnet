from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from phylax.utils.hashing import trace_hash

_PROBE_DOMAIN = "probe.phylax.ai"


@dataclass(frozen=True)
class ProbeSpec:
    nonce: str
    canary: str
    file_path: str
    file_content: str
    dns_host: str
    process_echo: str

    def as_inputs(self) -> dict[str, str]:
        return {
            "file_path": self.file_path,
            "file_content": self.file_content,
            "dns_host": self.dns_host,
            "process_echo": self.process_echo,
            "canary": self.canary,
        }

    def expected_probe_evidence(self) -> dict[str, str]:
        return {
            "file_write": self.file_path,
            "dns_lookup": self.dns_host,
            "process_echo": self.process_echo,
            "canary": self.canary,
        }


@dataclass(frozen=True)
class ProofResult:
    passed: bool
    reason: str


def new_nonce() -> str:
    return secrets.token_hex(32)


def derive_probe(nonce: str) -> ProbeSpec:
    seed = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    return ProbeSpec(
        nonce=nonce,
        canary=seed[24:56],
        file_path=f"/task/workspace/.probe_{seed[:16]}",
        file_content=seed[16:48],
        dns_host=f"{seed[:8]}.{_PROBE_DOMAIN}",
        process_echo=seed[8:24],
    )


def _fs_has_probe(events: list[dict], probe: ProbeSpec) -> bool:
    return any(str(e.get("path", "")) == probe.file_path for e in events)


def _network_has_probe(events: list[dict], probe: ProbeSpec) -> bool:
    for e in events:
        if str(e.get("domain", "") or "") == probe.dns_host:
            return True
        query = str(e.get("query", "") or "")
        proto = str(e.get("proto", "")).lower()
        port = int(e.get("dst_port", 0) or 0)
        if (proto == "dns" or port == 53) and probe.dns_host in query:
            return True
    return False


def _process_has_probe(events: list[dict], probe: ProbeSpec) -> bool:
    for e in events:
        cmd = str(e.get("cmd", ""))
        args = e.get("args") or []
        if cmd.startswith("echo") and any(probe.process_echo in str(a) for a in args):
            return True
        if "echo" in cmd and probe.process_echo in cmd:
            return True
    return False


def verify_probe_evidence(submitted: dict | None, probe: ProbeSpec) -> ProofResult:
    if not submitted or not isinstance(submitted, dict):
        return ProofResult(False, "probe_evidence missing")
    for key, want in probe.expected_probe_evidence().items():
        if str(submitted.get(key, "") or "") != want:
            return ProofResult(False, f"probe_evidence.{key} mismatch")
    return ProofResult(True, "")


def verify_validator_trace(events: list | None, probe: ProbeSpec) -> ProofResult:
    """Check the probe effects against the trace the validator's own runner
    recorded while the agent executed. Nothing here is agent-authored."""
    if not events:
        return ProofResult(False, "validator trace empty")
    saw_fs = saw_net = saw_proc = False
    for event in events:
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind", ""))
        if kind == "fs" and probe.file_path in str(event.get("path", "")):
            saw_fs = True
        elif kind == "net":
            blob = f"{event.get('host', '')} {event.get('url', '')} {event.get('peer', '')}"
            if probe.dns_host in blob:
                saw_net = True
        elif kind == "proc":
            blob = f"{event.get('cmd', '')} {event.get('args', '')}"
            if probe.process_echo in blob:
                saw_proc = True
    if not saw_fs:
        return ProofResult(False, "probe file write absent from validator trace")
    if not saw_net:
        return ProofResult(False, "probe dns lookup absent from validator trace")
    if not saw_proc:
        return ProofResult(False, "probe process echo absent from validator trace")
    return ProofResult(True, "")


def verify_proof_of_execution(
    probe: ProbeSpec,
    evidence: dict | None,
    *,
    detonation: bool,
) -> ProofResult:
    poe = (evidence or {}).get("proof_of_execution") or {}

    res = verify_probe_evidence(poe.get("probe_evidence"), probe)
    if not res.passed:
        return res

    if not detonation:
        return ProofResult(True, "")

    traces = poe.get("traces") or {}
    for plane in ("filesystem", "network", "process"):
        trace = traces.get(plane) or {}
        declared = str(trace.get("hash", "") or "")
        if trace_hash(trace.get("events") or []) != declared:
            return ProofResult(False, f"{plane} trace hash mismatch")

    fs = (traces.get("filesystem") or {}).get("events") or []
    network = (traces.get("network") or {}).get("events") or []
    process = (traces.get("process") or {}).get("events") or []

    if not _fs_has_probe(fs, probe):
        return ProofResult(False, "probe file write absent from filesystem trace")
    if not _network_has_probe(network, probe):
        return ProofResult(False, "probe dns lookup absent from network trace")
    if not _process_has_probe(process, probe):
        return ProofResult(False, "probe process echo absent from process trace")
    return ProofResult(True, "")
