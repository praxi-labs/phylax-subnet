from __future__ import annotations

import argparse
from pathlib import Path

from phylax.corpus.connectors import DatadogPackagesConnector, LocalDirConnector
from phylax.corpus.pipeline import dump, load_index, version_manifest


def _connectors(args) -> list:
    conns: list = []
    for spec in args.local or []:
        if "=" not in spec:
            raise SystemExit(f"--local expects TRACK=DIR, got {spec!r}")
        track, path = spec.split("=", 1)
        conns.append(LocalDirConnector(path, track))
    if args.datadog:
        conns.append(DatadogPackagesConnector(args.datadog))
    return conns


def _cmd_dump(args) -> None:
    conns = _connectors(args)
    if not conns:
        raise SystemExit("no connectors: pass --local TRACK=DIR and/or --datadog DIR")
    res = dump(conns, Path(args.root), args.version)
    print(
        f"{res.version}: {len(res.new)} new, {len(res.revised)} revised, "
        f"{len(res.unchanged)} unchanged"
    )
    print(f"held-out this version (new + revised): {len(res.held_out)}")


def _cmd_status(args) -> None:
    index = load_index(Path(args.root))
    counts: dict = {}
    for entry in index["entries"].values():
        key = (entry["track"], entry["label"])
        counts[key] = counts.get(key, 0) + 1
    print(f"latest version: {index.get('latest_version')}")
    print(f"total entries: {len(index['entries'])}")
    for (track, label), count in sorted(counts.items()):
        print(f"  {track}/{label}: {count}")


def _cmd_show(args) -> None:
    manifest = version_manifest(Path(args.root), args.version)
    if manifest is None:
        raise SystemExit(f"no manifest for {args.version}")
    print(f"version {manifest['version']}")
    print(f"  new:     {len(manifest['new'])}")
    print(f"  revised: {len(manifest['revised'])}")
    print(f"  unchanged: {manifest['unchanged_count']}")
    print(f"  held-out: {len(manifest['held_out'])}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="phylax-corpus")
    ap.add_argument("--root", default="corpora")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("dump", help="pull connectors, diff against the index, write a version")
    d.add_argument("--version", required=True)
    d.add_argument("--local", action="append", metavar="TRACK=DIR")
    d.add_argument("--datadog", metavar="DIR")
    d.set_defaults(func=_cmd_dump)

    s = sub.add_parser("status", help="summarise the cumulative index")
    s.set_defaults(func=_cmd_status)

    sh = sub.add_parser("show", help="show a version's delta")
    sh.add_argument("--version", required=True)
    sh.set_defaults(func=_cmd_show)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
