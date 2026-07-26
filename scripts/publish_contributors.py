from __future__ import annotations

import argparse
import os
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
    parser.add_argument("--network", default=os.getenv("SUBTENSOR_NETWORK", "finney"))
    parser.add_argument(
        "--wallet.name", dest="wallet_name", default=os.getenv("WALLET_NAME", "owner")
    )
    parser.add_argument(
        "--wallet.hotkey", dest="wallet_hotkey", default=os.getenv("WALLET_HOTKEY", "default")
    )
    parser.add_argument("--file", help="file with one contributor hotkey per line")
    parser.add_argument("--add", action="append", help="a contributor hotkey (repeatable)")
    args = parser.parse_args()

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.wallet_hotkey)
    subtensor = bt.Subtensor(args.network)

    contributors = _load_hotkeys(args.file, args.add)
    payload = ",".join(sorted(contributors)).encode("utf-8")
    print(f"netuid={args.netuid} authority={wallet.hotkey.ss58_address}")
    print(f"publishing {len(contributors)} contributors ({len(payload)} bytes)")
    for hk in sorted(contributors):
        print(f"  {hk}")
    if len(payload) > 1024:
        print("ERROR: payload exceeds the on-chain commitment size limit (1024 bytes)")
        return 1

    info = {"fields": [[{f"Raw{len(payload)}": payload}]]}
    call = bt.calls.Commitments.set_commitment(args.netuid, info)
    try:
        result = subtensor.submit_call(call, wallet)
    except Exception as exc:  # noqa: BLE001
        print(f"commit failed: {exc}")
        return 1
    if not getattr(result, "success", True):
        print(f"commit failed: {getattr(result, 'error', result)}")
        return 1
    print("committed; validators will pick it up on their next round")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
