from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass


@dataclass
class WeightAttestation:
    """Mirrors phylax_server.schemas.WeightAttestation on the wire."""

    attestation_id: str
    round_id: str
    validator_hotkey: str
    weights: dict[int, float]
    weight_vector_hash: str
    issued_at: str
    expires_at: str
    server_signature: str
    server_hotkey: str

    def is_expired(self) -> bool:
        try:
            exp = dt.datetime.fromisoformat(self.expires_at.rstrip("Z"))
        except ValueError:
            return True
        return dt.datetime.utcnow() >= exp


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
    """Raised when phylax-server cannot be contacted."""


class ServerIdentityMismatch(Exception):
    """Raised when a server-issued attestation is signed by an unexpected key."""


class PhylaxServerClient:
    """Validator-side client for phylax-server.

    Pass a Bittensor wallet (``wallet.hotkey`` is used to sign). The
    wallet object must expose a ``sign(message: bytes) -> bytes`` method
    on its hotkey, which is the standard substrate-interface keypair API.

    The client pins the server's signing public key on first use via
    ``GET /v1/server-identity`` and refuses to accept any weight
    attestation signed by a different key. This protects against a rogue
    or man-in-the-middled server impersonating the real one.
    """

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
        """The server's signing public key, pinned on first use."""
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
        r.raise_for_status()
        return r.json() if r.content else {}

    def get(self, path: str, *, params: dict | None = None, signed: bool = True) -> dict:
        return self._request("GET", path, params=params, signed=signed)

    def post(self, path: str, json_body: dict | None = None, *, signed: bool = True) -> dict:
        return self._request("POST", path, json_body=json_body, signed=signed)


    def fetch_server_identity(self) -> str:
        """Pull the server's public signing key and pin it. Idempotent."""
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

    def register(self, label: str = "") -> dict:
        if self._server_hotkey is None:
            self.fetch_server_identity()
        return self._request("POST", "/v1/validators/register", json_body={"label": label})

    def whoami(self) -> dict:
        return self._request("GET", "/v1/validators/me")

    def dispatch_track_task(self, track: str) -> dict | None:
        resp = self._request("POST", "/v1/tasks/track/next", json_body={"track": track})
        return resp or None

    def get_runnable_agent(self, hotkey: str) -> dict:
        return self._request("GET", f"/v1/specialization/agent/{hotkey}/runnable")

    def fetch_track_weights(self) -> dict:
        return self._request("GET", "/v1/tasks/track/weights")

    def submit_track_attestation(
        self,
        task_id: str,
        *,
        verdict: str,
        evidence: dict,
        risk_score: int = 0,
        miner_signature: str | None = None,
    ) -> dict:
        return self._request(
            "POST",
            f"/v1/tasks/track/{task_id}/attestation",
            json_body={
                "verdict": verdict,
                "risk_score": risk_score,
                "evidence": evidence,
                "miner_signature": miner_signature,
            },
        )

    def report_rerun(self, task_id: str, *, reproduced: bool) -> dict:
        return self._request(
            "POST",
            f"/v1/tasks/track/{task_id}/rerun",
            json_body={"reproduced": reproduced},
        )

    def fetch_rerun_sample(self, track: str, limit: int = 3) -> dict:
        return self._request(
            "POST",
            "/v1/tasks/track/rerun-sample",
            json_body={"track": track, "limit": limit},
        )

    def register_track(self, hotkey: str, track: str, specialization: dict) -> dict:
        return self._request(
            "POST",
            "/v1/specialization/register",
            json_body={
                "hotkey": hotkey,
                "track": track,
                "specialization": specialization,
            },
        )

    def submit_agent(
        self,
        *,
        hotkey: str,
        code: str,
        execution_api_key: str,
        sandbox_image: str,
        sandbox_digest: str,
        entrypoint: str = "agent_main",
        name: str = "",
        inference_model: str = "",
        dependency_manifest: str = "",
    ) -> dict:
        return self._request(
            "POST",
            "/v1/specialization/agent",
            json_body={
                "hotkey": hotkey,
                "name": name,
                "code": code,
                "entrypoint": entrypoint,
                "execution_api_key": execution_api_key,
                "inference_model": inference_model,
                "sandbox": {"image_uri": sandbox_image, "image_hash": sandbox_digest},
                "dependency_manifest": dependency_manifest,
            },
        )

    def fetch_task_batch(
        self,
        n_curated: int = 8,
        *,
        include_canaries: bool = True,
        families: list[str] | None = None,
    ) -> dict:
        return self._request(
            "POST",
            "/v1/tasks/batch",
            json_body={
                "n_curated": n_curated,
                "include_canaries": include_canaries,
                "families": families,
            },
        )

    def open_round(
        self,
        *,
        round_id: str,
        task_count: int,
        bundle_hashes: list[str],
    ) -> dict:
        return self._request(
            "POST",
            "/v1/rounds/open",
            json_body={
                "round_id": round_id,
                "task_count": int(task_count),
                "bundle_hashes": bundle_hashes,
            },
        )

    def submit_round_results(
        self,
        round_id: str,
        miner_scores: list[dict],
        *,
        consensus_sssa: dict | None = None,
    ) -> dict:
        return self._request(
            "POST",
            f"/v1/rounds/{round_id}/results",
            json_body={
                "round_id": round_id,
                "miner_scores": miner_scores,
                "consensus_sssa": consensus_sssa,
            },
        )

    def post_round_record(
        self,
        round_id: str,
        *,
        participated: list[str],
        all_queried: list[str],
        per_miner_scores: dict[str, dict],
        axon_ips: dict[str, str] | None = None,
        completed_assignments: dict[str, list[str]] | None = None,
    ) -> dict:
        return self._request(
            "POST",
            "/v1/rounds/record",
            json_body={
                "round_id": round_id,
                "participated": list(participated),
                "all_queried": list(all_queried),
                "per_miner_scores": per_miner_scores,
                "axon_ips": axon_ips or {},
                "completed_assignments": completed_assignments or {},
            },
        )

    def post_label_review(
        self,
        bundle_hash: str,
        *,
        server_label: str,
        validator_verdict: str,
        agreeing_miners: int = 0,
    ) -> dict:
        return self._request(
            "POST",
            "/v1/label_review",
            json_body={
                "task_id": bundle_hash,
                "server_label": server_label,
                "validator_verdict": validator_verdict,
                "agreeing_miners": int(agreeing_miners),
            },
        )

    def report_weights(self, round_id: str, weights: dict[int, float]) -> dict:
        return self._request(
            "POST",
            "/v1/weights/report",
            json_body={
                "round_id": round_id,
                "weights": {str(int(k)): float(v) for k, v in weights.items()},
            },
        )

    def push_attestation(
        self, bundle_hash: str, sssa: dict, *, quality_score: float, round_id: str
    ) -> dict:
        return self._request(
            "POST",
            "/v1/attestations",
            json_body={
                "bundle_hash": bundle_hash,
                "sssa": sssa,
                "quality_score": quality_score,
                "round_id": round_id,
            },
        )

    def intel_lookup(
        self,
        hosts: list[str] | None = None,
        ips: list[str] | None = None,
    ) -> dict:
        """Resolve threat-intel for a batch of observed hosts/IPs.

        Server proxies to urlhaus (hosts) and Spamhaus DROP/EDROP (IPs)
        and returns ``{queried_at, results: [{host, ip, hits: [...]}]}``.
        A non-empty ``hits`` list means the validator treats that host/IP
        as malicious regardless of what the skill's SKILL.md declared
        — a known C2 doesn't get a free pass just because the developer
        listed it as allowed.

        Gated by validator-only auth; miners can't reach this endpoint.
        """
        return self._request(
            "POST",
            "/v1/intel/lookup",
            json_body={
                "hosts": hosts or [],
                "ips": ips or [],
            },
        )

    def fetch_miner_reputation(self) -> dict:
        """GET the current miner-reputation snapshot from the server.

        Returns ``{computed_at, miners: [{miner_hotkey, accuracy,
        reputation, flagged_clusters, ...}], collusion_clusters: [...]}``.

        The ``reputation`` float in [0.5, 1.0] is the multiplier the
        validator applies to each miner's final emission weight: 1.0 =
        no penalty (new miners or those with ≥90% canary accuracy);
        0.5 = floor for miners who systematically lie on canaries.
        Smooth de-weighting rather than slashing keeps the incentive
        to keep behaving on the existing hotkey rather than churn to
        a new one.

        Cached server-side for 5 minutes; cheap to poll per round.
        """
        return self._request("GET", "/v1/reputation/miners")

    def cve_lookup(self, packages: list[dict] | None = None) -> dict:
        """Resolve CVEs for a batch of SBOM packages.

        Each ``packages`` entry is ``{name, version, ecosystem}`` (eco
        defaults to PyPI). Server queries osv.dev and returns per-package
        records with severity + reference URL. Hits become
        ``known_vulns`` entries that ``combine_verdict`` escalates to
        BLOCK/WARN.

        Like intel_lookup, gated by validator allowlist. Reference miners
        that don't run their own osv.dev integration miss every CVE in
        their dependency trees and take a systematic detection penalty
        when the validator catches them.
        """
        return self._request(
            "POST",
            "/v1/intel/cve_lookup",
            json_body={"packages": packages or []},
        )


    def request_and_verify_weight_attestation(
        self, round_id: str, weights: dict[int, float]
    ) -> WeightAttestation | None:
        """Call /v1/weights/report and return a verified attestation, or None.

        Enforces three checks in order:
          1. Server accepted the report (``accepted=True``).
          2. The attestation's ``server_hotkey`` matches the pinned identity.
          3. The ed25519 signature verifies under that key.

        Returns ``None`` if any check fails; logs no details here so the
        caller can decide whether to retry / fail-closed / fail-open.
        """
        resp = self.report_weights(round_id, weights)
        if not resp.get("accepted"):
            return None
        att_raw = resp.get("attestation") or {}
        try:
            att = WeightAttestation(
                attestation_id=att_raw["attestation_id"],
                round_id=att_raw["round_id"],
                validator_hotkey=att_raw["validator_hotkey"],
                weights={int(k): float(v) for k, v in att_raw["weights"].items()},
                weight_vector_hash=att_raw["weight_vector_hash"],
                issued_at=str(att_raw["issued_at"]),
                expires_at=str(att_raw["expires_at"]),
                server_signature=att_raw["server_signature"],
                server_hotkey=att_raw["server_hotkey"],
            )
        except (KeyError, TypeError):
            return None

        if self._server_hotkey and att.server_hotkey != self._server_hotkey:
            raise ServerIdentityMismatch(
                f"weight attestation signed by {att.server_hotkey[:16]}…; "
                f"pinned identity is {self._server_hotkey[:16]}…"
            )

        if not _verify_weight_attestation(att):
            return None
        return att


def _verify_weight_attestation(att: WeightAttestation) -> bool:
    """Verify the server's signature locally before trusting the attestation."""
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    if att.is_expired():
        return False
    try:
        vk = VerifyKey(bytes.fromhex(att.server_hotkey))
    except (ValueError, Exception):  # noqa: BLE001
        return False
    sig_hex = att.server_signature.removeprefix("ed25519:")
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    normalised = {str(int(k)): round(float(v), 8) for k, v in att.weights.items()}
    payload = {"round_id": att.round_id, "weights": normalised}
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        vk.verify(msg, sig)
        return True
    except BadSignatureError:
        return False


__all__ = [
    "PhylaxServerClient",
    "ServerIdentityMismatch",
    "ServerUnreachable",
    "WeightAttestation",
]

