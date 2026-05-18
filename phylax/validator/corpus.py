from __future__ import annotations

import json
import random
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

FAMILIES = (
    "known_bad",
    "known_good",
    "near_miss",
    "adversarial",
    "canaries",
    "regression",
    "synthetic",
)


@dataclass
class CorpusTask:
    name: str
    family: str
    path: str
    bundle_hash: str
    bundle_url: str | None
    bundle_bytes_b64: str | None
    metadata: dict
    test_profile: str
    expected_verdict: str
    expected_risk_score: int | None
    expected_capabilities: dict
    expected_policy: dict
    expected_findings: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict, *, family: str, path: str) -> CorpusTask:
        bundle_hash = data["bundle_hash"]
        if not (bundle_hash.startswith("sha256:") and len(bundle_hash) == 71):
            raise ValueError(f"{path}: bundle_hash must be 'sha256:<64 hex>'")
        if data.get("expected_verdict") not in ("ALLOW", "WARN", "BLOCK"):
            raise ValueError(f"{path}: expected_verdict missing or invalid")
        return cls(
            name=data.get("name", Path(path).stem),
            family=family,
            path=path,
            bundle_hash=bundle_hash,
            bundle_url=data.get("bundle_url"),
            bundle_bytes_b64=data.get("bundle_bytes_b64"),
            metadata=data.get("metadata", {}) or {},
            test_profile=data.get("test_profile", "standard"),
            expected_verdict=data["expected_verdict"],
            expected_risk_score=data.get("expected_risk_score"),
            expected_capabilities=data.get("expected_capabilities", {}) or {},
            expected_policy=data.get("expected_policy", {}) or {},
            expected_findings=list(data.get("expected_findings", []) or []),
            tags=list(data.get("tags", []) or []),
        )

    def as_scoring_dict(self) -> dict:
        return {
            "name": self.name,
            "_family": self.family,
            "_path": self.path,
            "bundle_hash": self.bundle_hash,
            "bundle_url": self.bundle_url,
            "metadata": self.metadata,
            "test_profile": self.test_profile,
            "expected_verdict": self.expected_verdict,
            "expected_risk_score": self.expected_risk_score,
            "expected_capabilities": self.expected_capabilities,
            "expected_policy": self.expected_policy,
            "expected_findings": self.expected_findings,
            "tags": self.tags,
        }


class CorpusLoader:
    def __init__(self, corpora_dir: str | Path):
        self.root = Path(corpora_dir)
        self.tasks: list[CorpusTask] = []
        self.errors: list[str] = []

    def load(self) -> CorpusLoader:
        self.tasks = []
        self.errors = []
        for family in FAMILIES:
            family_dir = self.root / family
            if not family_dir.exists():
                continue
            for task_file in sorted(family_dir.glob("*.json")):
                try:
                    data = json.loads(task_file.read_text(encoding="utf-8"))
                    task = CorpusTask.from_dict(data, family=family, path=str(task_file))
                    self.tasks.append(task)
                except Exception as e:  # noqa: BLE001
                    self.errors.append(f"{task_file}: {e}")
        return self

    def by_family(self) -> dict[str, list[CorpusTask]]:
        out: dict[str, list[CorpusTask]] = {}
        for t in self.tasks:
            out.setdefault(t.family, []).append(t)
        return out

    def sample_stratified(self, n: int, rng: random.Random | None = None) -> list[CorpusTask]:
        """Stratified sample across families, with deterministic RNG support."""
        if not self.tasks:
            return []
        rng = rng or random.Random()
        per_family = max(1, n // max(1, len(self.by_family())))
        picks: list[CorpusTask] = []
        for fam_tasks in self.by_family().values():
            picks.extend(rng.sample(fam_tasks, min(per_family, len(fam_tasks))))
        rng.shuffle(picks)
        return picks[:n]

    def iter_family(self, family: str) -> Iterable[CorpusTask]:
        yield from (t for t in self.tasks if t.family == family)
