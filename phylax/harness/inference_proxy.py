from __future__ import annotations

import contextlib
import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_PROVIDERS = {
    "chutes": "https://llm.chutes.ai/v1/chat/completions",
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
}

_MAX_BODY = 1_000_000


def _provider_url(provider: str, api_key: str) -> str | None:
    if provider in _PROVIDERS:
        return _PROVIDERS[provider]
    if api_key.startswith("cpk_"):
        return _PROVIDERS["chutes"]
    if api_key.startswith("sk-or-"):
        return _PROVIDERS["openrouter"]
    return None


def _meter(data: bytes) -> None:
    with contextlib.suppress(Exception):
        usage = json.loads(data).get("usage") or {}
        print(json.dumps({"event": "inference", "usage": usage}), flush=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.path.startswith("/v1/chat/completions"):
            self.send_error(404, "only /v1/chat/completions is proxied")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > _MAX_BODY:
            self.send_error(413, "invalid body size")
            return
        body = self.rfile.read(length)
        api_key = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        provider = self.headers.get("X-Phylax-Provider", "").strip()
        url = _provider_url(provider, api_key)
        if not url or not api_key:
            self.send_error(400, "missing provider or api key")
            return

        upstream = urllib.request.Request(url, data=body, method="POST")  # noqa: S310
        upstream.add_header("Content-Type", "application/json")
        upstream.add_header("Authorization", f"Bearer {api_key}")
        try:
            with urllib.request.urlopen(upstream, timeout=120) as resp:  # noqa: S310
                data = resp.read()
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, f"upstream error: {exc}")
            return

        _meter(data)
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
