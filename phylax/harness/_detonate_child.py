from __future__ import annotations

import json
import os
import runpy
import sys
import sysconfig
import traceback

_EVENTS: list[dict] = []
_ARMED = [False]
_MAX_EVENTS = 4000
_ARTIFACT_ROOT = [""]
_STDLIB_PREFIXES: tuple[str, ...] = ()
_SITE_PREFIXES: tuple[str, ...] = ()


def _init_lib_prefixes() -> None:
    global _STDLIB_PREFIXES, _SITE_PREFIXES
    paths = sysconfig.get_paths()
    std = set()
    site = set()
    for key in ("stdlib", "platstdlib"):
        p = paths.get(key)
        if p:
            std.add(os.path.normcase(os.path.abspath(p)))
    for key in ("purelib", "platlib"):
        p = paths.get(key)
        if p:
            site.add(os.path.normcase(os.path.abspath(p)))
    std.add(os.path.normcase(os.path.dirname(os.path.abspath(__file__))))
    _STDLIB_PREFIXES = tuple(sorted(std))
    _SITE_PREFIXES = tuple(sorted(site))


def _origin() -> str:
    frame = sys._getframe(1)
    while frame is not None:
        name = frame.f_code.co_filename
        if name and not name.startswith("<"):
            norm = os.path.normcase(os.path.abspath(name))
            if norm.startswith(_SITE_PREFIXES):
                return "library"
            if not norm.startswith(_STDLIB_PREFIXES):
                root = _ARTIFACT_ROOT[0]
                return "artifact" if root and norm.startswith(root) else "external"
        frame = frame.f_back
    return "library"

_SECRET_MARKERS = (
    ".aws/credentials", ".aws\\credentials", ".ssh/id_", ".ssh\\id_",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".docker/config",
    ".kube/config", "kubeconfig", ".gnupg", "keychain", "wallet.dat",
    "logins.json", "key4.db", "cookies.sqlite", "/etc/shadow",
    ".password-store", "service_account", "credentials.json",
)
_PRIVATE_KEY_MARKERS = (".ssh/id_", ".ssh\\id_", "id_rsa", "id_ed25519", "id_ecdsa")
_WALLET_MARKERS = ("wallet.dat", "metamask", "keystore.json", "mnemonic")


def _record(kind: str, detail: dict) -> None:
    if not _ARMED[0] or len(_EVENTS) >= _MAX_EVENTS:
        return
    _EVENTS.append({"kind": kind, "origin": _origin(), **detail})


class DetonationDenied(Exception):
    pass


def _deny(what: str) -> None:
    raise DetonationDenied(f"phylax detonation: {what} denied")


def _classify_path(path: str) -> list[str]:
    low = path.replace("\\", "/").lower()
    caps: list[str] = []
    if any(m in low for m in _PRIVATE_KEY_MARKERS):
        caps.append("READ_PRIVATE_KEY")
    if any(m in low for m in _WALLET_MARKERS):
        caps.append("ACCESS_WALLET")
    if any(m.replace("\\", "/") in low for m in _SECRET_MARKERS):
        caps.append("READ_SECRETS")
    return caps


def _hook(event: str, args) -> None:
    if not _ARMED[0]:
        return
    try:
        if event == "open":
            path, mode = str(args[0]), str(args[1] or "")
            if path.endswith("_phylax_events.json"):
                return
            caps = _classify_path(path)
            if any(c in mode for c in ("w", "a", "+", "x")):
                caps.append("WRITE_FILE")
            else:
                caps.append("READ_FILE")
            _record("file", {"path": path, "mode": mode, "caps": caps})
        elif event == "socket.connect":
            _record("network", {"detail": str(args[1])[:200], "caps": ["OPEN_SOCKET"]})
            _deny("socket.connect")
        elif event == "socket.getaddrinfo":
            _record("dns", {"host": str(args[0])[:200], "caps": ["RESOLVE_DNS"]})
            _deny("socket.getaddrinfo")
        elif event == "urllib.Request":
            url = str(args[0])[:300]
            has_body = len(args) > 1 and args[1] is not None
            _record("http", {
                "url": url,
                "caps": ["POST_WEB" if has_body else "FETCH_WEB"],
            })
        elif event == "subprocess.Popen":
            _record("process", {
                "cmd": str(args[0])[:300],
                "caps": ["CREATE_PROCESS", "EXEC_SHELL"],
            })
        elif event == "os.system":
            _record("process", {"cmd": str(args[0])[:300], "caps": ["EXEC_SHELL"]})
        elif event in ("exec", "compile"):
            _record("dynamic", {"caps": ["EXECUTE_SOURCE_CODE"]})
        elif event == "os.listdir" or event == "os.scandir":
            _record("file", {"path": str(args[0])[:200], "caps": ["LIST_DIRECTORY"]})
        elif event in ("os.remove", "os.unlink"):
            _record("file", {"path": str(args[0])[:200], "caps": ["DELETE_FILE"]})
    except DetonationDenied:
        raise
    except Exception:
        return


def _run_script(path: str) -> None:
    runpy.run_path(path, run_name="__main__")


def _run_import(artifact_dir: str, module: str) -> None:
    src = os.path.join(artifact_dir, "src")
    sys.path.insert(0, src if os.path.isdir(src) else artifact_dir)
    __import__(module)


def _run_setup_install(artifact_dir: str) -> None:
    setup_py = os.path.join(artifact_dir, "setup.py")
    sys.argv = ["setup.py", "install", "--dry-run"]
    os.chdir(artifact_dir)
    runpy.run_path(setup_py, run_name="__main__")


def main() -> int:
    spec = json.loads(sys.argv[1])
    out_path = spec["out"]
    mode = spec["mode"]
    error = ""
    _init_lib_prefixes()
    root = spec.get("artifact_root") or ""
    if root:
        _ARTIFACT_ROOT[0] = os.path.normcase(os.path.abspath(root))
    sys.addaudithook(_hook)
    _ARMED[0] = True
    try:
        if mode == "script":
            _run_script(spec["path"])
        elif mode == "import":
            _run_import(spec["artifact_dir"], spec["module"])
        elif mode == "setup_install":
            _run_setup_install(spec["artifact_dir"])
    except SystemExit:
        pass
    except BaseException:
        error = traceback.format_exc(limit=3)[-800:]
    _ARMED[0] = False
    attributed = [e for e in _EVENTS if e.get("origin") == "artifact"]
    caps = sorted({c for e in attributed for c in e.get("caps", [])})
    all_caps = sorted({c for e in _EVENTS for c in e.get("caps", [])})
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "capabilities": caps,
                "capabilities_unattributed": all_caps,
                "events": attributed[:400],
                "error": error,
            },
            fh,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
