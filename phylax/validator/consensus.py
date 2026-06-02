from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from statistics import median

from phylax.protocol import SSSA, MinerRole

VERDICT_RANK: dict[str, int] = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}

CONSENSUS_THRESHOLD = 0.6
FINDING_LINE_BUCKET = 5

WEIGHTS: dict[str, float] = {
    "verdict_agreement": 0.15,
    "risk_score_agreement": 0.10,
    "findings_recall": 0.30,
    "findings_precision": 0.15,
    "capabilities_agreement": 0.15,
    "dependencies_agreement": 0.10,
    "policy_derivation": 0.05,
}

_LINE_NUM = re.compile(r":(\d+)")


@dataclass(frozen=True)
class FindingKey:
    layer_source: str
    ref: str
    affected_file: str
    line_bucket: int


@dataclass
class GroupMember:
    hotkey: str
    role: MinerRole
    sssa: SSSA


@dataclass
class PerMinerConsensus:
    hotkey: str
    role: MinerRole
    consensus_score: float
    verdict_agreement: float
    risk_score_agreement: float
    findings_recall: float
    findings_precision: float
    capabilities_agreement: float
    dependencies_agreement: float
    policy_derivation: float
    aligned_with_primaries: float
    aligned_with_auditors: float


@dataclass
class ConsensusReport:
    consensus_verdict: str | None
    consensus_risk: float | None
    consensus_findings: set[FindingKey] = field(default_factory=set)
    consensus_capabilities: set[tuple[str, str]] = field(default_factory=set)
    consensus_cves: set[str] = field(default_factory=set)
    per_miner: list[PerMinerConsensus] = field(default_factory=list)
    group_size: int = 0
    breakdown_flag: bool = False
    diverging_hotkeys: list[str] = field(default_factory=list)


def _extract_finding_keys(sssa: SSSA) -> set[FindingKey]:
    keys: set[FindingKey] = set()
    for f in sssa.findings or []:
        ref = (f.owasp_ref or "") or (f.mitre_ref or "") or ""
        affected_file = ""
        line_bucket = 0
        snippet = f.evidence_snippet or ""
        m = _LINE_NUM.search(snippet)
        if m:
            try:
                line = int(m.group(1))
                line_bucket = line // FINDING_LINE_BUCKET
            except ValueError:
                pass
        if ":" in snippet:
            head = snippet.split(":", 1)[0]
            if head and "/" in head or "." in head:
                affected_file = head
        keys.add(
            FindingKey(
                layer_source=f.layer_source.value if f.layer_source else "",
                ref=ref,
                affected_file=affected_file,
                line_bucket=line_bucket,
            )
        )
    return keys


def _capability_signatures(sssa: SSSA) -> set[tuple[str, str]]:
    caps = sssa.capabilities
    out: set[tuple[str, str]] = set()
    for d in caps.network.domains or []:
        out.add(("net_domain", str(d)))
    for ip in caps.network.ips or []:
        out.add(("net_ip", str(ip)))
    for port in caps.network.ports or []:
        out.add(("net_port", str(port)))
    for p in caps.filesystem.reads or []:
        out.add(("fs_read", str(p)))
    for p in caps.filesystem.writes or []:
        out.add(("fs_write", str(p)))
    for cmd in caps.process_spawns or []:
        out.add(("proc", str(cmd)))
    for s in caps.secrets_access or []:
        out.add(("secret", str(s)))
    for t in caps.tool_calls or []:
        out.add(("tool", str(t)))
    for c in caps.child_skills or []:
        out.add(("child", str(c)))
    return out


def _cves(sssa: SSSA) -> set[str]:
    return set(sssa.dependencies.known_cves or [])


def _consensus_findings(members: list[GroupMember]) -> set[FindingKey]:
    keys_per_miner = [_extract_finding_keys(m.sssa) for m in members]
    if not members:
        return set()
    threshold = max(1, int(CONSENSUS_THRESHOLD * len(members)))
    counter: Counter[FindingKey] = Counter()
    for keys in keys_per_miner:
        for k in keys:
            counter[k] += 1
    return {k for k, c in counter.items() if c >= threshold}


def _consensus_set(values_per_miner: list[set]) -> set:
    if not values_per_miner:
        return set()
    threshold = max(1, int(CONSENSUS_THRESHOLD * len(values_per_miner)))
    counter: Counter = Counter()
    for s in values_per_miner:
        for v in s:
            counter[v] += 1
    return {v for v, c in counter.items() if c >= threshold}


def _verdict_consensus(members: list[GroupMember]) -> str | None:
    if not members:
        return None
    counter = Counter(m.sssa.verdict.decision.value for m in members)
    top, _ = counter.most_common(1)[0]
    return top


def _verdict_agreement(miner_verdict: str, consensus: str | None) -> float:
    if consensus is None:
        return 1.0
    if miner_verdict == consensus:
        return 1.0
    a = VERDICT_RANK.get(miner_verdict, 0)
    b = VERDICT_RANK.get(consensus, 0)
    distance = abs(a - b)
    if distance == 1:
        return 0.6
    return 0.0


def _risk_agreement(miner_risk: float, consensus_risk: float | None) -> float:
    if consensus_risk is None:
        return 1.0
    delta = abs(miner_risk - consensus_risk)
    if delta <= 15:
        return 1.0
    if delta <= 30:
        return 0.5
    return 0.0


def _set_agreement_score(miner: set, consensus: set, full: set) -> float:
    if not consensus:
        if not miner:
            return 1.0
        outliers = miner - full
        return max(0.0, 1.0 - 0.05 * len(outliers))
    recall = len(miner & consensus) / len(consensus)
    precision = len(miner & consensus) / max(1, len(miner)) if miner else 0.0
    if not miner:
        return recall * 0.7
    return 0.5 * recall + 0.5 * precision


def _findings_recall_precision(miner_keys: set[FindingKey], consensus_keys: set[FindingKey]) -> tuple[float, float]:
    if not consensus_keys:
        recall = 1.0
    else:
        recall = len(miner_keys & consensus_keys) / len(consensus_keys)
    if not miner_keys:
        precision = 1.0 if not consensus_keys else 0.0
    else:
        precision = len(miner_keys & consensus_keys) / len(miner_keys) if consensus_keys else 0.5
    return recall, precision


def _policy_derivation_score(sssa: SSSA, consensus_caps: set[tuple[str, str]]) -> float:
    policy = sssa.recommended_policy
    derived: set[tuple[str, str]] = set()
    for d in policy.egress_allow or []:
        derived.add(("net_domain", str(d)))
    for d in policy.egress_deny or []:
        derived.add(("net_domain", str(d)))
    for p in policy.fs_read or []:
        derived.add(("fs_read", str(p)))
    for p in policy.fs_write or []:
        derived.add(("fs_write", str(p)))
    for t in policy.tool_allowlist or []:
        derived.add(("tool", str(t)))
    for c in policy.child_skill_allowlist or []:
        derived.add(("child", str(c)))
    if not consensus_caps:
        return 0.5
    if not derived:
        return 0.0
    overlap = len(derived & consensus_caps)
    return min(1.0, overlap / max(1, len(consensus_caps)))


def _agreement_between(a: GroupMember, others: list[GroupMember]) -> float:
    if not others:
        return 1.0
    a_keys = _extract_finding_keys(a.sssa)
    a_caps = _capability_signatures(a.sssa)
    scores: list[float] = []
    for o in others:
        o_keys = _extract_finding_keys(o.sssa)
        o_caps = _capability_signatures(o.sssa)
        finding_jacc = (
            len(a_keys & o_keys) / max(1, len(a_keys | o_keys))
            if (a_keys or o_keys) else 1.0
        )
        cap_jacc = (
            len(a_caps & o_caps) / max(1, len(a_caps | o_caps))
            if (a_caps or o_caps) else 1.0
        )
        verdict_match = 1.0 if a.sssa.verdict.decision == o.sssa.verdict.decision else 0.0
        scores.append(0.5 * finding_jacc + 0.3 * cap_jacc + 0.2 * verdict_match)
    return sum(scores) / len(scores)


def compute_consensus(members: list[GroupMember]) -> ConsensusReport:
    if not members:
        return ConsensusReport(consensus_verdict=None, consensus_risk=None)

    consensus_verdict = _verdict_consensus(members)
    risks = [float(m.sssa.verdict.risk_score) for m in members]
    consensus_risk = float(median(risks)) if risks else None

    consensus_findings = _consensus_findings(members)
    caps_per = [_capability_signatures(m.sssa) for m in members]
    full_caps_union = set().union(*caps_per) if caps_per else set()
    consensus_caps = _consensus_set(caps_per)
    cves_per = [_cves(m.sssa) for m in members]
    full_cves_union = set().union(*cves_per) if cves_per else set()
    consensus_cves = _consensus_set(cves_per)

    primaries = [m for m in members if m.role == MinerRole.PRIMARY]
    auditors = [m for m in members if m.role == MinerRole.AUDITOR]

    per_miner: list[PerMinerConsensus] = []
    diverging: list[str] = []

    for m in members:
        v_agree = _verdict_agreement(m.sssa.verdict.decision.value, consensus_verdict)
        r_agree = _risk_agreement(float(m.sssa.verdict.risk_score), consensus_risk)
        m_keys = _extract_finding_keys(m.sssa)
        recall, precision = _findings_recall_precision(m_keys, consensus_findings)
        m_caps = _capability_signatures(m.sssa)
        cap_score = _set_agreement_score(m_caps, consensus_caps, full_caps_union)
        m_cves = _cves(m.sssa)
        dep_score = _set_agreement_score(m_cves, consensus_cves, full_cves_union)
        policy_score = _policy_derivation_score(m.sssa, consensus_caps)

        aligned_p = _agreement_between(m, [x for x in primaries if x.hotkey != m.hotkey])
        aligned_a = _agreement_between(m, [x for x in auditors if x.hotkey != m.hotkey])

        weighted = (
            WEIGHTS["verdict_agreement"] * v_agree
            + WEIGHTS["risk_score_agreement"] * r_agree
            + WEIGHTS["findings_recall"] * recall
            + WEIGHTS["findings_precision"] * precision
            + WEIGHTS["capabilities_agreement"] * cap_score
            + WEIGHTS["dependencies_agreement"] * dep_score
            + WEIGHTS["policy_derivation"] * policy_score
        )
        consensus_score = max(0.0, min(1.0, weighted))

        if v_agree < 0.6 or recall < 0.5:
            diverging.append(m.hotkey)

        per_miner.append(
            PerMinerConsensus(
                hotkey=m.hotkey,
                role=m.role,
                consensus_score=consensus_score,
                verdict_agreement=v_agree,
                risk_score_agreement=r_agree,
                findings_recall=recall,
                findings_precision=precision,
                capabilities_agreement=cap_score,
                dependencies_agreement=dep_score,
                policy_derivation=policy_score,
                aligned_with_primaries=aligned_p,
                aligned_with_auditors=aligned_a,
            )
        )

    breakdown = len(diverging) >= max(1, len(members) // 2)

    return ConsensusReport(
        consensus_verdict=consensus_verdict,
        consensus_risk=consensus_risk,
        consensus_findings=consensus_findings,
        consensus_capabilities=consensus_caps,
        consensus_cves=consensus_cves,
        per_miner=per_miner,
        group_size=len(members),
        breakdown_flag=breakdown,
        diverging_hotkeys=diverging,
    )
