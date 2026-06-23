from __future__ import annotations

import argparse
from pathlib import Path

import bittensor as bt


def _load_hotkeys(file_path: str | None, inline: list[str] | None) -> list[str]:
    keys: list[str] = []
    if file_path:
        for line in Path(file_path).expanduser().read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                keys.append(s)
    keys.extend(inline or [])
    ordered: list[str] = []
    for k in keys:
        k = k.strip()
        if k and k not in ordered:
            ordered.append(k)
    return ordered


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish the Phylax recognized-contributor set as an on-chain commitment. "
        "Validators read this with PHYLAX_CONTRIBUTOR_AUTHORITY set to the publishing hotkey."
    )
    parser.add_argument("--netuid", type=int, required=True)
    parser.add_argument("--file", help="file with one contributor hotkey per line")
    parser.add_argument("--add", action="append", help="a contributor hotkey (repeatable)")
    bt.Wallet.add_args(parser)
    bt.Subtensor.add_args(parser)
    config = bt.Config(parser)
    wallet = bt.Wallet(config=config)
    subtensor = bt.Subtensor(config=config)

    contributors = _load_hotkeys(getattr(config, "file", None), getattr(config, "add", None))
    payload = ",".join(sorted(contributors))
    print(f"netuid={config.netuid} authority={wallet.hotkey.ss58_address}")
    print(f"publishing {len(contributors)} contributors ({len(payload)} bytes)")
    for hk in sorted(contributors):
        print(f"  {hk}")
    if len(payload) > 1024:
        print("ERROR: payload exceeds the on-chain commitment size limit (1024 bytes)")
        return 1

    try:
        subtensor.commit(wallet, config.netuid, payload)
    except Exception as exc:  # noqa: BLE001
        print(f"commit failed: {exc}")
        return 1
    print("committed; validators will pick it up on their next round")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
