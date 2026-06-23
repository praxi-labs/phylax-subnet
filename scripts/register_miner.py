#!/usr/bin/env python3
"""Register a miner into a Phylax track and submit its agent (code + image + key)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TRACKS = ("skills", "mcp_servers", "packages", "repositories")


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
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

    hotkey_path = (
        Path(bittensor_dir).expanduser() / "wallets" / wallet_name / "hotkeys" / hotkey_name
    )
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
    return "ed25519:" + keypair.sign(h.digest()).hex()


def post(server: str, path: str, payload: dict, keypair, hotkey: str) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signature = sign("POST", path, timestamp, body, keypair)
    url = server + path
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        sys.exit(f"ERROR: server URL must be http or https, got {parsed.scheme!r}")

    req = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Phylax-Hotkey", hotkey)
    req.add_header("X-Phylax-Timestamp", timestamp)
    req.add_header("X-Phylax-Signature", signature)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            print(f"==> {resp.status} {resp.reason} {path}")
            print(resp.read().decode("utf-8"))
            return {"ok": True}
    except urllib.error.HTTPError as exc:
        print(f"==> {exc.code} {exc.reason} {path}", file=sys.stderr)
        try:
            print(exc.read().decode("utf-8"), file=sys.stderr)
        except OSError:
            pass
        return {"ok": False}
    except urllib.error.URLError as exc:
        print(f"==> URL error: {exc.reason}", file=sys.stderr)
        return {"ok": False}


def main() -> int:
    env_path = (
        Path(sys.argv[1]).expanduser()
        if len(sys.argv) > 1
        else Path(__file__).resolve().parent.parent / ".env"
    )
    if not env_path.exists():
        env_path = Path.cwd() / ".env"
    if not env_path.exists():
        sys.exit(f"ERROR: .env not found (looked at {env_path})")
    env = load_env(env_path)

    server = require_any(env, "PHYLAX_SERVER_URL", "PHYLAX_COORDINATOR_URL").rstrip("/")
    wallet_name = require(env, "WALLET_NAME")
    hotkey_name = env.get("WALLET_HOTKEY", "default").strip() or "default"
    bittensor_dir = env.get("BITTENSOR_DIR", "~/.bittensor")

    track = env.get("PHYLAX_TRACK", "skills").strip() or "skills"
    if track not in TRACKS:
        sys.exit(f"ERROR: PHYLAX_TRACK must be one of {TRACKS}, got {track!r}")

    api_key = require(env, "PHYLAX_EXECUTION_API_KEY")
    if not (api_key.startswith("cpk_") or api_key.startswith("sk-or-")):
        sys.exit("ERROR: PHYLAX_EXECUTION_API_KEY must start with 'cpk_' or 'sk-or-'")
    sandbox_image = require(env, "PHYLAX_SANDBOX_IMAGE")
    sandbox_digest = require(env, "PHYLAX_SANDBOX_DIGEST")
    if not sandbox_digest.startswith("sha256:"):
        sys.exit("ERROR: PHYLAX_SANDBOX_DIGEST must start with 'sha256:'")

    default_agent = (
        Path(__file__).resolve().parent.parent
        / "phylax" / "harness" / "skills_reference_agent.py"
    )
    agent_path = Path(env.get("PHYLAX_AGENT_PATH", "") or default_agent).expanduser()
    if not agent_path.exists():
        sys.exit(f"ERROR: agent file not found at {agent_path}")
    code = agent_path.read_text(encoding="utf-8")

    manifest = ""
    manifest_path = env.get("PHYLAX_DEPENDENCY_MANIFEST", "").strip()
    if manifest_path and Path(manifest_path).expanduser().exists():
        manifest = Path(manifest_path).expanduser().read_text(encoding="utf-8")

    keypair = load_keypair(bittensor_dir, wallet_name, hotkey_name)
    hotkey = keypair.ss58_address

    print(f"==> server: {server}")
    print(f"==> hotkey: {hotkey}")
    print(f"==> track:  {track}")
    print(f"==> agent:  {agent_path.name} ({len(code)} bytes)")
    print(f"==> image:  {sandbox_image}@{sandbox_digest[:20]}…")

    reg = post(
        server,
        "/v1/specialization/register",
        {
            "hotkey": hotkey,
            "registration_version": "2.0",
            "track": track,
            "label": env.get("PHYLAX_MINER_LABEL", ""),
        },
        keypair,
        hotkey,
    )
    if not reg["ok"]:
        return 1

    sub = post(
        server,
        "/v1/specialization/agent",
        {
            "hotkey": hotkey,
            "name": env.get("PHYLAX_MINER_LABEL", ""),
            "code": code,
            "entrypoint": env.get("PHYLAX_AGENT_ENTRYPOINT", "agent_main"),
            "execution_api_key": api_key,
            "inference_model": env.get("PHYLAX_INFERENCE_MODEL", ""),
            "sandbox": {"image_uri": sandbox_image, "image_hash": sandbox_digest},
            "dependency_manifest": manifest,
        },
        keypair,
        hotkey,
    )
    return 0 if sub["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
