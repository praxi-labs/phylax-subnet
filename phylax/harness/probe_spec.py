from __future__ import annotations

import hashlib
from dataclasses import dataclass

_PROBE_DOMAIN = "probe.phylax.ai"


@dataclass(frozen=True)
class ProbeSpec:
    nonce: str
    file_path: str
    file_content: str
    dns_host: str
    process_echo: str

    def as_evidence(self) -> dict[str, str]:
        return {
            "file_path": self.file_path,
            "file_content": self.file_content,
            "dns_host": self.dns_host,
            "process_echo": self.process_echo,
        }


def derive_probe(nonce: str) -> ProbeSpec:
    seed = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
    return ProbeSpec(
        nonce=nonce,
        file_path=f"/skill/.probe_{seed[:16]}",
        file_content=seed[16:48],
        dns_host=f"{seed[:8]}.{_PROBE_DOMAIN}",
        process_echo=seed[8:24],
    )


def probe_present_in_fs(records: list[dict], probe: ProbeSpec) -> bool:
    for r in records:
        if str(r.get("path", "")) == probe.file_path:
            return True
    return False


def probe_present_in_network(records: list[dict], probe: ProbeSpec) -> bool:
    for r in records:
        domain = str(r.get("domain", "") or "")
        if domain == probe.dns_host:
            return True
        proto = str(r.get("proto", "")).lower()
        port = int(r.get("dst_port", 0) or 0)
        if proto == "dns" and probe.dns_host in str(r.get("query", "") or ""):
            return True
        if port == 53 and probe.dns_host in str(r.get("query", "") or ""):
            return True
    return False


def probe_present_in_process(records: list[dict], probe: ProbeSpec) -> bool:
    for r in records:
        cmd = str(r.get("cmd", ""))
        args = r.get("args") or []
        if cmd.startswith("echo") and any(probe.process_echo in str(a) for a in args):
            return True
        if "echo" in cmd and probe.process_echo in cmd:
            return True
    return False


def verify_probe_evidence(
    submitted: dict | None,
    probe: ProbeSpec,
) -> tuple[bool, str]:
    if not submitted or not isinstance(submitted, dict):
        return False, "probe_evidence missing"
    expected = probe.as_evidence()
    for key, want in expected.items():
        got = str(submitted.get(key, "") or "")
        if got != want:
            return False, f"probe_evidence.{key} mismatch (expected {want}, got {got})"
    return True, ""


def verify_probe_in_traces(
    fs_records: list[dict] | None,
    network_records: list[dict] | None,
    process_records: list[dict] | None,
    probe: ProbeSpec,
) -> tuple[bool, str]:
    if not (fs_records and probe_present_in_fs(fs_records, probe)):
        return False, "probe file write absent from fs.jsonl"
    if not (network_records and probe_present_in_network(network_records, probe)):
        return False, "probe DNS lookup absent from network.jsonl"
    if not (process_records and probe_present_in_process(process_records, probe)):
        return False, "probe process spawn absent from process.jsonl"
    return True, ""
