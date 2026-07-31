from __future__ import annotations

import contextlib
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_PROVIDERS = {
    "chutes": "https://llm.chutes.ai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
}

_MAX_BODY = 1_000_000
_MAX_RESPONSE = 4_000_000

# Per-task inference accounting. Keyed by the task nonce the agent must echo in
# the X-Phylax-Nonce header, this is both the meter (tokens/requests) and the
# liveness signal the validator reads to confirm an agent really did work.
_METRICS: dict[str, dict[str, int]] = {}
_LOCK = threading.Lock()

# Credentials never enter the sandbox. The validator registers a session before
# it runs an agent; the agent presents only its nonce and the proxy attaches the
# key. Budget is enforced here so a looping agent cannot drain a miner balance.
_SESSIONS: dict[str, dict[str, str]] = {}
_MAX_TOKENS_PER_TASK = int(os.getenv("PHYLAX_MAX_TOKENS_PER_TASK", "400000"))
_MAX_REQUESTS_PER_TASK = int(os.getenv("PHYLAX_MAX_REQUESTS_PER_TASK", "200"))


def _usage(nonce: str) -> dict[str, int]:
    with _LOCK:
        row = _METRICS.get(nonce) or {}
        return dict(row)


def _over_budget(nonce: str) -> str:
    row = _usage(nonce)
    if row.get("requests", 0) >= _MAX_REQUESTS_PER_TASK:
        return f"request budget exhausted ({_MAX_REQUESTS_PER_TASK} calls)"
    spent = row.get("input_tokens", 0) + row.get("output_tokens", 0)
    if spent >= _MAX_TOKENS_PER_TASK:
        return f"token budget exhausted ({_MAX_TOKENS_PER_TASK} tokens)"
    return ""


def _provider_url(provider: str, api_key: str) -> str | None:
    if provider in _PROVIDERS:
        return _PROVIDERS[provider]
    if api_key.startswith("cpk_"):
        return _PROVIDERS["chutes"]
    if api_key.startswith("sk-or-"):
        return _PROVIDERS["openrouter"]
    return None


def _record(nonce: str, data: bytes) -> None:
    if not nonce:
        return
    usage = {}
    with contextlib.suppress(Exception):
        usage = json.loads(data).get("usage") or {}
    with _LOCK:
        row = _METRICS.setdefault(
            nonce, {"requests": 0, "input_tokens": 0, "output_tokens": 0}
        )
        row["requests"] += 1
        row["input_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
        row["output_tokens"] += int(usage.get("completion_tokens", 0) or 0)


def _admin_ok(headers) -> bool:
    token = os.getenv("PHYLAX_PROXY_ADMIN_TOKEN", "")
    if not token:
        return False
    return headers.get("X-Phylax-Admin", "") == token


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if parsed.path == "/metrics":
            # Liveness/metering read for the validator. Admin-authenticated so an
            # agent on the internal network cannot read or forge usage.
            if not _admin_ok(self.headers):
                self.send_error(401, "admin token required")
                return
            nonce = (parse_qs(parsed.query).get("nonce") or [""])[0]
            with _LOCK:
                if nonce:
                    self._json(200, {"nonce": nonce, "usage": _METRICS.get(nonce, {})})
                else:
                    self._json(200, {"usage": dict(_METRICS)})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/metrics/reset":
            if not _admin_ok(self.headers):
                self.send_error(401, "admin token required")
                return
            nonce = (parse_qs(parsed.query).get("nonce") or [""])[0]
            with _LOCK:
                if nonce:
                    _METRICS.pop(nonce, None)
                    _SESSIONS.pop(nonce, None)
                else:
                    _METRICS.clear()
                    _SESSIONS.clear()
            self._json(200, {"reset": nonce or "all"})
            return

        if parsed.path == "/session":
            if not _admin_ok(self.headers):
                self.send_error(401, "admin token required")
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > 8192:
                self.send_error(400, "invalid session body")
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except ValueError:
                self.send_error(400, "invalid session body")
                return
            nonce = str(payload.get("nonce") or "").strip()
            api_key = str(payload.get("api_key") or "").strip()
            if not nonce or not api_key:
                self.send_error(400, "nonce and api_key required")
                return
            with _LOCK:
                _SESSIONS[nonce] = {
                    "api_key": api_key,
                    "provider": str(payload.get("provider") or "").strip(),
                }
                _METRICS.pop(nonce, None)
            self._json(200, {"registered": nonce})
            return

        if not parsed.path.startswith("/v1/chat/completions"):
            self.send_error(404, "only /v1/chat/completions is proxied")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > _MAX_BODY:
            self.send_error(413, "invalid body size")
            return
        body = self.rfile.read(length)
        nonce = self.headers.get("X-Phylax-Nonce", "").strip()
        with _LOCK:
            session = dict(_SESSIONS.get(nonce) or {})
        api_key = session.get("api_key") or (
            self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        )
        provider = session.get("provider") or self.headers.get("X-Phylax-Provider", "").strip()
        url = _provider_url(provider, api_key)
        if not url or not api_key:
            self.send_error(400, "missing provider or api key")
            return
        exhausted = _over_budget(nonce)
        if exhausted:
            self._json(429, {"error": exhausted, "nonce": nonce})
            return

        upstream = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
        upstream.add_header("Content-Type", "application/json")
        upstream.add_header("Authorization", f"Bearer {api_key}")
        try:
            with urllib.request.urlopen(upstream, timeout=120) as resp:  # noqa: S310
                data = resp.read(_MAX_RESPONSE)
        except urllib.error.HTTPError as exc:
            payload = exc.read(_MAX_RESPONSE)
            self.send_response(exc.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, f"upstream error: {exc}")
            return

        _record(nonce, data)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args) -> None:
        return


def main() -> None:
    host = os.getenv("PHYLAX_PROXY_HOST", "0.0.0.0")  # noqa: S104
    port = int(os.getenv("PHYLAX_PROXY_PORT", "8900"))
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
