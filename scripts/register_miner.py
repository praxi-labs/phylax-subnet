#!/usr/bin/env python3
"""
register_miner.py — declare this miner's specialization with the coordinator.

Reads config from the standard miner .env file. Signs the request with the
hotkey loaded from BITTENSOR_DIR. Idempotent: re-run whenever you change
supported types, the sandbox image, or its digest.

Usage:
    python3 register_miner.py [.env path]

If no .env path is given, defaults to ./.env relative to the script.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def require(env: dict[str, str], key: str) -> str:
    val = env.get(key, "").strip()
    if not val:
        sys.exit(f"ERROR: {key} is not set in .env")
    return val


def require_any(env: dict[str, str], *keys: str) -> str:
    """Return the first non-empty value for any of the given keys."""
    for k in keys:
        v = env.get(k, "").strip()
        if v:
            return v
    sys.exit(f"ERROR: none of {keys} is set in .env (set one)")


def load_keypair(bittensor_dir: str, wallet_name: str, hotkey_name: str):
    try:
        from substrateinterface import Keypair  # type: ignore
    except ImportError:
        sys.exit("ERROR: substrate-interface not installed. pip install substrate-interface")

    hotkey_path = Path(bittensor_dir).expanduser() / "wallets" / wallet_name / "hotkeys" / hotkey_name
    if not hotkey_path.exists():
        sys.exit(f"ERROR: hotkey file not found at {hotkey_path}")

    raw = json.loads(hotkey_path.read_text())
    seed_hex = raw.get("secretSeed") or raw.get("privateKey") or ""
    if not seed_hex:
        sys.exit(f"ERROR: no secretSeed/privateKey in {hotkey_path}")
    return Keypair.create_from_seed(seed_hex)


def sign(method: str, path: str, timestamp: str, body: bytes, keypair) -> str:
    h = hashlib.sha256()
    h.update(method.upper().encode("ascii"))
    h.update(b"\n")
    h.update(path.encode("utf-8"))
    h.update(b"\n")
    h.update(timestamp.encode("ascii"))
    h.update(b"\n")
    h.update(body)
    sig = keypair.sign(h.digest())
    return "ed25519:" + sig.hex()


def main() -> int:
    env_path = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        env_path = Path.cwd() / ".env"
    if not env_path.exists():
        sys.exit(f"ERROR: .env not found (looked at {env_path})")

    env = load_env(env_path)

    coordinator = require_any(env, "PHYLAX_COORDINATOR_URL", "PHYLAX_SERVER_URL").rstrip("/")
    wallet_name = require(env, "WALLET_NAME")
    hotkey_name = env.get("WALLET_HOTKEY", "default").strip() or "default"
    bittensor_dir = env.get("BITTENSOR_DIR", "~/.bittensor")

    supported = [t.strip() for t in require(env, "PHYLAX_SUPPORTED_TYPES").split(",") if t.strip()]
    # declarative is the default skill type for every miner. Inject it if
    # the operator did not list it explicitly so the server's same rule sees
    # a consistent payload.
    if "declarative" not in supported:
        supported.append("declarative")
    sandbox_image = require(env, "PHYLAX_SANDBOX_IMAGE")
    sandbox_digest = require(env, "PHYLAX_SANDBOX_DIGEST")
    if not sandbox_digest.startswith("sha256:"):
        sys.exit("ERROR: PHYLAX_SANDBOX_DIGEST must start with 'sha256:'")

    runtime_types = {"executable_python", "executable_script", "mcp_server", "agent_composition"}
    sandbox_images = {
        t: {"image_uri": sandbox_image, "image_hash": sandbox_digest}
        for t in supported if t in runtime_types
    }
    if any(t in runtime_types for t in supported) and not sandbox_images:
        sys.exit("ERROR: at least one runtime type declared but no sandbox image resolved")

    keypair = load_keypair(bittensor_dir, wallet_name, hotkey_name)
    hotkey_ss58 = keypair.ss58_address

    payload = {
        "hotkey": hotkey_ss58,
        "registration_version": "2.0",
        "specialization": {
            "supported_types": supported,
            "sandbox_images": sandbox_images,
            "min_profile": env.get("PHYLAX_MIN_PROFILE", "standard"),
            "max_concurrent_tasks": int(env.get("PHYLAX_MAX_CONCURRENT_TASKS", "2")),
            "implementation_tier_claim": env.get("PHYLAX_TIER_CLAIM", "reference"),
        },
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")

    path = "/v1/specialization/register"
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signature = sign("POST", path, timestamp, body, keypair)

    url = coordinator + path
    # Refuse anything that isn't plain HTTP(S). Closes ruff S310 by making the
    # scheme an explicit gate rather than relying on user input.
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        sys.exit(
            f"ERROR: PHYLAX_COORDINATOR_URL / PHYLAX_SERVER_URL must use http or https, "
            f"got scheme={parsed.scheme!r}"
        )

    req = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Phylax-Hotkey", hotkey_ss58)
    req.add_header("X-Phylax-Timestamp", timestamp)
    req.add_header("X-Phylax-Signature", signature)

    print(f"==> POST {url}")
    print(f"    hotkey: {hotkey_ss58}")
    print(f"    types:  {supported}")
    print(f"    image:  {sandbox_image}")
    print(f"    digest: {sandbox_digest[:24]}...")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = resp.read().decode("utf-8")
            print(f"==> {resp.status} {resp.reason}")
            print(data)
            return 0
    except urllib.error.HTTPError as exc:
        print(f"==> {exc.code} {exc.reason}", file=sys.stderr)
        try:
            print(exc.read().decode("utf-8"), file=sys.stderr)
        except OSError as read_exc:
            print(f"    (could not read response body: {read_exc})", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"==> URL error: {exc.reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
