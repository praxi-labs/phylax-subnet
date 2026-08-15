from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phylax.analysis import proof, repositories, scoring  # noqa: E402
from phylax.harness.corpus import load_corpus  # noqa: E402

TRACKS = ("skills", "mcp_servers", "packages", "repositories")
MALICIOUS = "known-bad"


def load_agent(path: Path):
    spec = importlib.util.spec_from_file_location("local_agent", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, "agent_main", None)
    if fn is None:
        raise SystemExit(f"{path} has no agent_main")
    return fn


def unpack(artifact_b64: str, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(artifact_b64))) as zf:
        for member in zf.infolist():
            name = member.filename.replace("\\", "/")
            if member.is_dir() or name.startswith("/") or ".." in name.split("/"):
                continue
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def probe_context(spec: proof.ProbeSpec) -> dict:
    return {
        "nonce": spec.nonce,
        "canary": spec.canary,
        "file_path": spec.file_path,
        "file_content": spec.canary,
        "dns_host": spec.dns_host,
        "process_echo": spec.canary,
    }


def decision_of(body: dict) -> str:
    verdict = body.get("verdict")
    if isinstance(verdict, dict):
        return str(verdict.get("decision") or verdict.get("DECISION") or "").upper()
    return str(verdict or "").upper()


def run_task(agent, track: str, task: dict, workdir: Path) -> tuple[str, dict]:
    artifact_dir = workdir / "artifact"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    unpack(task["artifact_b64"], artifact_dir)
    spec = proof.derive_probe(proof.new_nonce())
    context = {
        "track": track,
        "artifact_dir": str(artifact_dir),
        "probe": probe_context(spec),
        "ref": task["ref"],
    }
    try:
        body = agent(context)
    except Exception as exc:  # noqa: BLE001
        return "ERROR", {"_error": f"{type(exc).__name__}: {exc}"}
    if not isinstance(body, dict):
        return "ERROR", {"_error": "agent_main did not return a dict"}
    return decision_of(body), body


def score_behavioural(results: list[dict]) -> tuple[float, dict]:
    tp = tn = fp = fn = 0
    for r in results:
        bad = r["label"] == MALICIOUS
        flagged = r["verdict"] in ("BLOCK", "WARN")
        if bad and flagged:
            tp += 1
        elif bad:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return scoring.clamped_mcc(tp, tn, fp, fn), {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def score_repositories(results: list[dict]) -> tuple[float, dict]:
    total = 0.0
    for r in results:
        spec = proof.derive_probe(proof.new_nonce())
        body = r["body"] if isinstance(r["body"], dict) else {}
        evidence = body.get("evidence") if isinstance(body.get("evidence"), dict) else body
        evaluation = repositories.evaluate(
            evidence,
            r["verdict"],
            label="malicious" if r["label"] == MALICIOUS else "safe",
            probe=spec,
            ground_truth=r["ground_truth"],
        )
        r["task_score"] = evaluation.result.score
        total += evaluation.result.score
    mean = total / len(results) if results else 0.0
    return mean, {"tasks": len(results)}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Score an agent against a local corpus using the metric the network applies."
    )
    ap.add_argument("--agent", required=True, help="path to your agent file exposing agent_main")
    ap.add_argument("--track", required=True, choices=TRACKS, help="track to evaluate")
    ap.add_argument("--json", action="store_true", help="emit machine readable results")
    args = ap.parse_args()

    tasks = load_corpus(args.track)
    if not tasks:
        print("no tasks loaded. Set PHYLAX_CORPUS_DIR to a built corpus directory.")
        print("see docs/local_testing.md")
        return 1

    agent = load_agent(Path(args.agent).expanduser().resolve())
    results: list[dict] = []

    with tempfile.TemporaryDirectory() as tmp:
        for i, task in enumerate(tasks):
            workdir = Path(tmp) / str(i)
            verdict, body = run_task(agent, args.track, task, workdir)
            results.append(
                {
                    "ref": task["ref"],
                    "label": task["label"],
                    "verdict": verdict,
                    "body": body,
                    "ground_truth": task.get("ground_truth"),
                    "expected_findings": task.get("expected_findings") or [],
                }
            )

    if args.track == "repositories":
        score, detail = score_repositories(results)
    else:
        score, detail = score_behavioural(results)

    threshold = scoring.TRACK_THRESHOLDS.get(args.track, 0.0)

    if args.json:
        print(json.dumps(
            {
                "track": args.track,
                "score": score,
                "threshold": threshold,
                "qualifies": score >= threshold,
                "detail": detail,
                "tasks": [
                    {k: v for k, v in r.items() if k != "body"} for r in results
                ],
            },
            indent=2,
            default=str,
        ))
        return 0

    print(f"\ntrack {args.track}   {len(results)} tasks\n")
    for r in results:
        name = r["ref"].rsplit("/", 1)[-1]
        want = "flag" if r["label"] == MALICIOUS else "allow"
        if args.track == "repositories":
            mark = "ok" if r.get("task_score", 0.0) >= threshold else "MISS"
            print(f"  {mark:4}  {name:28} F2={r.get('task_score', 0.0):.3f}  expected={want}")
        else:
            flagged = r["verdict"] in ("BLOCK", "WARN")
            correct = flagged == (r["label"] == MALICIOUS)
            mark = "ok" if correct else "MISS"
            print(f"  {mark:4}  {name:28} verdict={r['verdict']:7} expected={want}")
        err = r["body"].get("_error") if isinstance(r["body"], dict) else None
        if err:
            print(f"        {err}")

    if args.track == "repositories":
        print(f"\nF2 mean          {score:.4f}")
    else:
        print(f"\nTP {detail['tp']}  TN {detail['tn']}  FP {detail['fp']}  FN {detail['fn']}")
        print(f"clamped MCC      {score:.4f}")
    print(f"threshold        {threshold:.2f}")
    print(f"result           {'QUALIFIES' if score >= threshold else 'BELOW THRESHOLD'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
