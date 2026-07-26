from __future__ import annotations

import datetime as dt
import hashlib
import json


def _signing_bytes(method: str, path: str, timestamp: str, body: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(method.upper().encode("ascii"))
    h.update(b"\n")
    h.update(path.encode("utf-8"))
    h.update(b"\n")
    h.update(timestamp.encode("ascii"))
    h.update(b"\n")
    h.update(body or b"")
    return h.digest()


class ServerUnreachable(Exception):
    pass


class ServerRejected(Exception):
    def __init__(self, status_code: int, detail: str, path: str):
        super().__init__(f"{path}: HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail
        self.path = path


class ServerIdentityMismatch(Exception):
    pass


class PhylaxServerClient:
    def __init__(self, base_url: str, wallet, *, timeout: float = 10.0,
                 expected_server_hotkey: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.wallet = wallet
        self.timeout = timeout
        self._server_hotkey: str | None = expected_server_hotkey

    @property
    def hotkey_address(self) -> str:
        return self.wallet.hotkey.ss58_address

    @property
    def server_hotkey(self) -> str | None:
        return self._server_hotkey

    def _signed_headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        timestamp = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        message = _signing_bytes(method, path, timestamp, body)
        signature = self.wallet.hotkey.sign(message).hex()
        return {
            "X-Phylax-Hotkey": self.hotkey_address,
            "X-Phylax-Timestamp": timestamp,
            "X-Phylax-Signature": "ed25519:" + signature,
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, *, json_body: dict | None = None,
                 params: dict | None = None, signed: bool = True) -> dict:
        import httpx

        body = (
            json.dumps(json_body or {}, separators=(",", ":")).encode("utf-8")
            if json_body is not None
            else b""
        )
        url = f"{self.base_url}{path}"
        headers: dict[str, str] = {"Content-Type": "application/json"} if json_body is not None else {}
        if signed:
            headers.update(self._signed_headers(method, path, body))
        try:
            r = httpx.request(
                method, url, headers=headers, content=body,
                params=params, timeout=self.timeout,
            )
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.TransportError) as exc:
            raise ServerUnreachable(f"{method} {path}: {exc}") from exc
        if r.status_code >= 400:
            try:
                detail = str((r.json() or {}).get("detail") or "")
            except ValueError:
                detail = r.text[:200]
            raise ServerRejected(r.status_code, detail or r.reason_phrase, path)
        return r.json() if r.content else {}

    def fetch_server_identity(self) -> str:
        data = self._request("GET", "/v1/server-identity", signed=False)
        sh = data.get("server_hotkey")
        if not sh:
            raise ServerIdentityMismatch("server-identity response missing server_hotkey")
        if self._server_hotkey and self._server_hotkey != sh:
            raise ServerIdentityMismatch(
                f"server rotated key: pinned {self._server_hotkey[:16]}… got {sh[:16]}…"
            )
        self._server_hotkey = sh
        return sh

    def health(self) -> dict:
        return self._request("GET", "/v1/health", signed=False)

    def register_track(self, hotkey: str, track: str, label: str = "") -> dict:
        if self._server_hotkey is None:
            self.fetch_server_identity()
        return self._request(
            "POST",
            "/v1/specialization/register",
            json_body={
                "hotkey": hotkey,
                "registration_version": "2.0",
                "track": track,
                "label": label,
            },
        )

    def next_round(self, track: str, hotkey: str) -> dict | None:
        """Ask the server whether a round should run for this track now.

        The server is the scheduler: rounds are not block-timed. Returns the
        round spec ({round_id, track, corpus_version, ...}) when a round is due,
        or None when there is nothing to run.
        """
        if self._server_hotkey is None:
            self.fetch_server_identity()
        data = self._request(
            "GET",
            "/v1/rounds/next",
            params={"track": track, "hotkey": hotkey},
        )
        if not data or not data.get("round_id"):
            return None
        return data

    def get_runnable_agent(self, hotkey: str) -> dict | None:
        """Fetch one participant's runnable agent from the backend.

        The backend is the source of truth for agent code: miners submit to it,
        and validators pull each frozen participant's agent here at round start.
        Returns the code, entrypoint, inference key, and model, or None if the
        participant has no active agent (404).
        """
        if self._server_hotkey is None:
            self.fetch_server_identity()
        try:
            data = self._request("GET", f"/v1/specialization/agent/{hotkey}/runnable")
        except Exception as exc:  # noqa: BLE001 — 404/other: treat as no agent
            if isinstance(exc, ServerUnreachable):
                raise
            return None
        return data or None

    def submit_round_results(
        self,
        *,
        round_id: str,
        track: str,
        validator_hotkey: str,
        start_block: int,
        seed: str,
        results: list[dict],
        attestations: list[dict] | None = None,
    ) -> dict:
        """Persist this validator's signed per-agent results for the round.

        The server records each validator's opinion; it does not decide the
        winner. Champion-per-track is read from on-chain consensus.
        """
        if self._server_hotkey is None:
            self.fetch_server_identity()
        return self._request(
            "POST",
            "/v1/rounds/results",
            json_body={
                "round_id": round_id,
                "track": track,
                "validator_hotkey": validator_hotkey,
                "start_block": start_block,
                "seed": seed,
                "results": results,
                "attestations": attestations or [],
            },
        )

    def submit_agent(
        self,
        *,
        hotkey: str,
        code: str,
        execution_api_key: str,
        sandbox_image: str = "",
        sandbox_digest: str = "",
        entrypoint: str = "agent_main",
        name: str = "",
        inference_model: str = "",
        dependency_manifest: str = "",
    ) -> dict:
        body = {
            "hotkey": hotkey,
            "name": name,
            "code": code,
            "entrypoint": entrypoint,
            "execution_api_key": execution_api_key,
            "inference_model": inference_model,
            "dependency_manifest": dependency_manifest,
        }
        # Code-only submissions omit the sandbox; the validator owns the runtime.
        if sandbox_image and sandbox_digest:
            body["sandbox"] = {"image_uri": sandbox_image, "image_hash": sandbox_digest}
        return self._request("POST", "/v1/specialization/agent", json_body=body)


__all__ = ["PhylaxServerClient", "ServerIdentityMismatch", "ServerUnreachable"]
