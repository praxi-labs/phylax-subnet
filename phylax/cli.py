from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import zipfile
from pathlib import Path

from phylax.attestation import (
    export_json_schema,
    verify_attestation,
)
from phylax.client.runtime import fetch_and_verify
from phylax.manifest import (
    IMPLICIT_ZERO_TRUST,
    generate_manifest_from_observations,
    load_manifest,
    render_skill_md,
)
from phylax.protocol import SSSA


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


def _extract_bundle(bundle_path: Path, dest: Path) -> Path:
    """Return a directory containing the unpacked skill code. If the input
    is a zip, extract to dest; if it's already a directory, just return
    it. Used by both `manifest init` and `manifest check`."""
    if bundle_path.is_dir():
        return bundle_path
    if bundle_path.suffix == ".zip" or zipfile.is_zipfile(bundle_path):
        extract_dir = dest / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(bundle_path) as zf:
            zf.extractall(extract_dir)
        return extract_dir
    raise ValueError(f"unsupported bundle format: {bundle_path}")


def cmd_manifest_init(args: argparse.Namespace) -> int:
    """Run the bundle in the sandbox once, observe its behavior, and emit
    a draft SKILL.md the developer can commit. The Trojan Horse for
    capability-manifest adoption — devs don't have to write a security
    manifest by hand, they just run this and commit the output."""
    from phylax.pipeline.sandbox import SandboxDetonator

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"phylax: bundle not found: {bundle_path}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="phylax_manifest_") as td:
        try:
            extract_dir = _extract_bundle(bundle_path, Path(td))
        except (ValueError, zipfile.BadZipFile) as e:
            print(f"phylax: {e}", file=sys.stderr)
            return 2

        det = SandboxDetonator(
            image=args.sandbox_image,
            timeout_seconds=args.timeout,
        )
        try:
            result = det.detonate(str(extract_dir), seed=args.seed)
        except Exception as e:  # noqa: BLE001
            print(f"phylax: sandbox detonation failed: {e}", file=sys.stderr)
            return 3

    manifest = generate_manifest_from_observations(
        name=args.name or bundle_path.stem,
        version=args.version,
        description=args.description,
        observed_domains=result.network_domains,
        observed_ips=result.network_ips,
        observed_fs_reads=result.fs_reads,
        observed_fs_writes=result.fs_writes,
        observed_shell_exec=bool(result.shell_commands),
        observed_commands=result.shell_commands,
        observed_env_access=bool(result.env_vars),
        observed_env_vars=result.env_vars,
    )

    body = (
        f"# {manifest.name}\n\n"
        f"Auto-generated by `phylax manifest init` from a single sandbox run.\n"
        f"Review the capability declarations above and trim anything the skill\n"
        f"shouldn't legitimately need. Phylax compares this manifest against\n"
        f"observed behavior on every scan — under-declaration is a security\n"
        f"violation, over-declaration is a soft signal of over-permissive design.\n"
    )
    output_text = render_skill_md(manifest, body)

    if args.output == "-":
        sys.stdout.write(output_text)
    else:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"phylax: wrote SKILL.md to {args.output}", file=sys.stderr)
    return 0


def _generate_manifest_static(extract_dir: Path) -> object:
    """Generate a SkillManifest from static analysis only — no sandbox.
    ~1s per bundle; suitable for bulk corpus processing where a full
    sandbox run (~10s each) would mean weeks of wall-clock time."""
    from phylax.manifest import generate_manifest_from_observations
    from phylax.pipeline.static import StaticAnalyzer

    sa = StaticAnalyzer(run_bandit=False, run_semgrep=False)
    res = sa.analyze(str(extract_dir))
    return generate_manifest_from_observations(
        observed_domains=res.network_domains,
        observed_ips=[],
        observed_fs_reads=res.fs_reads,
        observed_fs_writes=res.fs_writes,
        observed_shell_exec=bool(res.shell_commands),
        observed_commands=res.shell_commands,
        observed_env_access=bool(res.env_vars),
        observed_env_vars=res.env_vars,
    )


def _generate_manifest_sandbox(extract_dir: Path, seed: int, image: str, timeout: int) -> object:
    """Generate a SkillManifest from a single sandbox detonation. Accurate
    but slow (~5-30s per bundle depending on skill behavior + image
    pull). Use for small batches; static mode for full-corpus passes."""
    from phylax.manifest import generate_manifest_from_observations
    from phylax.pipeline.sandbox import SandboxDetonator

    det = SandboxDetonator(image=image, timeout_seconds=timeout)
    res = det.detonate(str(extract_dir), seed=seed)
    return generate_manifest_from_observations(
        observed_domains=res.network_domains,
        observed_ips=res.network_ips,
        observed_fs_reads=res.fs_reads,
        observed_fs_writes=res.fs_writes,
        observed_shell_exec=bool(res.shell_commands),
        observed_commands=res.shell_commands,
        observed_env_access=bool(res.env_vars),
        observed_env_vars=res.env_vars,
    )


def _bulk_init_one(
    zip_path: Path,
    output_path: Path,
    mode: str,
    name: str,
    sandbox_image: str,
    sandbox_timeout: int,
) -> tuple[str, str | None]:
    """Process one bundle. Returns (status, error_message).

    status ∈ {"written", "skipped_existing", "skipped_empty", "failed"}.
    """
    if output_path.exists():
        return ("skipped_existing", None)
    try:
        with tempfile.TemporaryDirectory(prefix="phylax_bulk_") as td:
            extract_dir = _extract_bundle(zip_path, Path(td))
            if mode == "sandbox":
                manifest = _generate_manifest_sandbox(
                    extract_dir, seed=1, image=sandbox_image, timeout=sandbox_timeout,
                )
            else:
                manifest = _generate_manifest_static(extract_dir)
        manifest.name = name
        body = (
            f"# {name}\n\n"
            f"Auto-generated by `phylax manifest bulk-init` ({mode} mode).\n"
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render_skill_md(manifest, body), encoding="utf-8")
        return ("written", None)
    except (zipfile.BadZipFile, ValueError, OSError) as e:
        return ("failed", str(e))
    except Exception as e:  # noqa: BLE001
        return ("failed", repr(e))


def cmd_manifest_bulk_init(args: argparse.Namespace) -> int:
    """Walk a corpus tree of bundles/<first-2>/<hash>.zip and generate
    one SKILL.md per bundle into skill_md/<first-2>/<hash>.md.

    Idempotent: bundles whose output file already exists are skipped, so
    re-running picks up where the last invocation left off. A single
    bundle failure (malformed zip, sandbox timeout, etc.) logs and
    continues to the next one rather than crashing the whole run.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    corpus_dir = Path(args.corpus_dir)
    bundles_dir = corpus_dir / "bundles"
    if not bundles_dir.is_dir():
        print(f"phylax: not a corpus dir (no bundles/ subdir): {corpus_dir}", file=sys.stderr)
        return 2
    output_root = Path(args.output_dir or (corpus_dir / "skill_md"))

    work: list[tuple[Path, Path, str]] = []
    for zip_path in sorted(bundles_dir.glob("*/*.zip")):
        bundle_hash = zip_path.stem
        prefix = bundle_hash[:2]
        output_path = output_root / prefix / f"{bundle_hash}.md"
        name = f"sha256:{bundle_hash[:16]}"
        work.append((zip_path, output_path, name))
        if args.limit and len(work) >= args.limit:
            break

    print(f"phylax bulk-init: {len(work)} bundles, mode={args.mode}, workers={args.parallel}", file=sys.stderr)

    counts = {"written": 0, "skipped_existing": 0, "failed": 0}
    failures: list[tuple[str, str]] = []

    def _process(item):
        zip_path, output_path, name = item
        status, err = _bulk_init_one(
            zip_path, output_path, args.mode, name,
            args.sandbox_image, args.timeout,
        )
        return zip_path.stem, status, err

    if args.parallel <= 1:
        for i, item in enumerate(work, 1):
            stem, status, err = _process(item)
            counts[status] = counts.get(status, 0) + 1
            if status == "failed":
                failures.append((stem, err or "unknown"))
            if i % 100 == 0:
                print(
                    f"  progress: {i}/{len(work)}  "
                    f"written={counts['written']} skipped={counts['skipped_existing']} failed={counts['failed']}",
                    file=sys.stderr,
                )
    else:
        with ThreadPoolExecutor(max_workers=args.parallel) as ex:
            futures = {ex.submit(_process, item): item for item in work}
            for i, fut in enumerate(as_completed(futures), 1):
                stem, status, err = fut.result()
                counts[status] = counts.get(status, 0) + 1
                if status == "failed":
                    failures.append((stem, err or "unknown"))
                if i % 100 == 0:
                    print(
                        f"  progress: {i}/{len(work)}  "
                        f"written={counts['written']} skipped={counts['skipped_existing']} failed={counts['failed']}",
                        file=sys.stderr,
                    )

    print(
        f"phylax bulk-init done: written={counts['written']} "
        f"skipped_existing={counts['skipped_existing']} failed={counts['failed']}",
        file=sys.stderr,
    )
    if failures and args.failures_log:
        Path(args.failures_log).write_text(
            "\n".join(f"{h}\t{e}" for h, e in failures) + "\n",
            encoding="utf-8",
        )
        print(f"phylax bulk-init: wrote {len(failures)} failure entries to {args.failures_log}", file=sys.stderr)
    return 0 if counts["failed"] == 0 else 1


def cmd_manifest_check(args: argparse.Namespace) -> int:
    """Load and validate a SKILL.md (or report the Implicit Zero-Trust
    fallback if missing). Useful in CI before publishing a bundle —
    catches malformed YAML early."""
    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"phylax: bundle not found: {bundle_path}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="phylax_check_") as td:
        try:
            extract_dir = _extract_bundle(bundle_path, Path(td))
        except (ValueError, zipfile.BadZipFile) as e:
            print(f"phylax: {e}", file=sys.stderr)
            return 2

        manifest = load_manifest(extract_dir)

    is_default = manifest == IMPLICIT_ZERO_TRUST
    if is_default:
        print(
            "phylax: no SKILL.md found — Implicit Zero-Trust baseline will apply.\n"
            "        Any observed behavior at scan time will count as discrepancy.\n"
            "        Run `phylax manifest init` to generate a draft.",
            file=sys.stderr,
        )
        return 1 if args.strict else 0

    print(json.dumps(manifest.model_dump(), indent=2))
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

    p_manifest = sub.add_parser("manifest", help="SKILL.md capability manifest tools")
    p_manifest_sub = p_manifest.add_subparsers(dest="manifest_cmd", required=True)

    p_mi = p_manifest_sub.add_parser(
        "init",
        help="Run the bundle in the sandbox and emit a draft SKILL.md",
    )
    p_mi.add_argument("bundle", help="Path to skill bundle (.zip or extracted dir)")
    p_mi.add_argument("-o", "--output", default="SKILL.md",
                      help="Output path. Use '-' for stdout. Default: SKILL.md")
    p_mi.add_argument("--name", default="", help="Skill name (defaults to bundle filename)")
    p_mi.add_argument("--version", default="0.1.0")
    p_mi.add_argument("--description", default="")
    p_mi.add_argument("--seed", type=int, default=1, help="Determinism seed for sandbox")
    p_mi.add_argument("--timeout", type=int, default=60, help="Sandbox timeout (seconds)")
    p_mi.add_argument("--sandbox-image", default="ghcr.io/praxi-labs/phylax-sandbox:latest")
    p_mi.set_defaults(func=cmd_manifest_init)

    p_mc = p_manifest_sub.add_parser(
        "check",
        help="Validate a SKILL.md (or report missing-manifest fallback)",
    )
    p_mc.add_argument("bundle", help="Path to skill bundle (.zip or extracted dir)")
    p_mc.add_argument("--strict", action="store_true",
                      help="Exit non-zero if no SKILL.md is present")
    p_mc.set_defaults(func=cmd_manifest_check)

    p_mb = p_manifest_sub.add_parser(
        "bulk-init",
        help="Generate one SKILL.md per bundle across a corpus directory.",
    )
    p_mb.add_argument("corpus_dir", help="Path to corpus root (contains bundles/<2>/<hash>.zip)")
    p_mb.add_argument("--output-dir", default="",
                      help="Where to write SKILL.md files. Default: <corpus>/skill_md")
    p_mb.add_argument("--mode", choices=["static", "sandbox"], default="static",
                      help="Static = AST-only, fast (~1s/skill). Sandbox = real detonation, slow.")
    p_mb.add_argument("--limit", type=int, default=0,
                      help="Process only the first N bundles (0 = all).")
    p_mb.add_argument("--parallel", type=int, default=1,
                      help="Worker thread count. Use 1 for sandbox mode (docker contention).")
    p_mb.add_argument("--failures-log", default="",
                      help="If set, write '<bundle_hash>\\t<error>' lines for each failure here.")
    p_mb.add_argument("--timeout", type=int, default=60, help="Sandbox timeout (seconds, sandbox mode only)")
    p_mb.add_argument("--sandbox-image", default="ghcr.io/praxi-labs/phylax-sandbox:latest")
    p_mb.set_defaults(func=cmd_manifest_bulk_init)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
