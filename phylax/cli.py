from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from phylax.attestation import (
    export_json_schema,
    verify_attestation,
)
from phylax.client.runtime import fetch_and_verify
from phylax.protocol import SSSA, Verdict


def _bundle_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_check(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    if not bundle.exists():
        print(f"phylax: bundle not found: {bundle}", file=sys.stderr)
        return 2

    sssa, result = fetch_and_verify(
        bundle.read_bytes(),
        base_url=args.api,
        require_countersignature=args.require_countersignature,
        max_age_seconds=args.max_age_seconds,
    )
    if sssa is None or not result.ok:
        print(
            f"phylax: verification failed: {result.reason or 'unknown'}",
            file=sys.stderr,
        )
        return 3

    if args.require and sssa.verdict.decision.value != args.require:
        print(
            f"phylax: required verdict {args.require}, "
            f"got {sssa.verdict.decision.value} (risk {sssa.verdict.risk_score})",
            file=sys.stderr,
        )
        return 4

    if sssa.verdict.risk_score > args.max_risk:
        print(
            f"phylax: risk {sssa.verdict.risk_score} > max-risk {args.max_risk}",
            file=sys.stderr,
        )
        return 5

    print(
        f"phylax: OK — verdict={sssa.verdict.decision.value} "
        f"risk={sssa.verdict.risk_score} miner={sssa.attestation.miner_hotkey if sssa.attestation else '?'}"
    )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.attestation).read_text(encoding="utf-8"))
    try:
        sssa = SSSA(**payload)
    except Exception as e:  # noqa: BLE001
        print(f"phylax: invalid SSSA: {e}", file=sys.stderr)
        return 2

    local_hash = _bundle_hash(Path(args.bundle)) if args.bundle else None
    result = verify_attestation(
        sssa,
        local_bundle_hash=local_hash,
        require_countersignature=args.require_countersignature,
        max_age_seconds=args.max_age_seconds,
    )
    if not result.ok:
        print(f"phylax: verify failed — {result.reason}", file=sys.stderr)
        return 3
    print("phylax: signature valid")
    return 0


def cmd_export_schema(args: argparse.Namespace) -> int:
    Path(args.output).write_text(
        json.dumps(export_json_schema(), indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"phylax: wrote schema to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phylax", description="Phylax CLI gate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Fetch + verify + gate on a local bundle")
    p_check.add_argument("bundle", help="Path to skill bundle (.zip)")
    p_check.add_argument("--api", default="http://localhost:8080", help="Phylax API URL")
    p_check.add_argument("--max-risk", type=int, default=49, help="Maximum allowed risk_score")
    p_check.add_argument("--require", choices=["ALLOW", "WARN", "BLOCK"], default=None)
    p_check.add_argument("--require-countersignature", action="store_true")
    p_check.add_argument("--max-age-seconds", type=int, default=86_400)
    p_check.set_defaults(func=cmd_check)

    p_verify = sub.add_parser("verify", help="Verify a local attestation JSON file")
    p_verify.add_argument("attestation", help="Path to SSSA JSON")
    p_verify.add_argument("--bundle", help="Local bundle file to cross-check bundle_hash")
    p_verify.add_argument("--require-countersignature", action="store_true")
    p_verify.add_argument("--max-age-seconds", type=int, default=None)
    p_verify.set_defaults(func=cmd_verify)

    p_schema = sub.add_parser("export-schema", help="Write the SSSA JSON schema")
    p_schema.add_argument("output", help="Output path")
    p_schema.set_defaults(func=cmd_export_schema)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
