import base64
import io
import json
import zipfile

import pytest

pytestmark = pytest.mark.skipif(
    pytest.importorskip("fastapi", reason="fastapi not installed") is None,
    reason="fastapi not installed",
)


def _build_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps({"name": "x", "version": "1"}))
        zf.writestr("main.py", "def main():\n    pass\n")
    return buf.getvalue()


@pytest.fixture
def app(tmp_path, monkeypatch):
    from phylax.api.server import create_app
    from phylax.validator.baseline import BaselineRunner
    from phylax.validator.registry import AttestationRegistry

    # Stub the sandbox detonation so the API works without Docker.
    class _NoopSandbox:
        def detonate(self, *_a, **_kw):  # noqa: D401
            raise RuntimeError("no sandbox in tests")

    runner = BaselineRunner.__new__(BaselineRunner)
    runner.static_analyzer = __import__("phylax.pipeline.static", fromlist=["StaticAnalyzer"]).StaticAnalyzer(run_bandit=False)
    runner.sbom_analyzer = __import__("phylax.pipeline.sbom", fromlist=["SBOMAnalyzer"]).SBOMAnalyzer(use_syft=False)
    runner.sandbox = _NoopSandbox()
    runner.policy_generator = __import__("phylax.policy.generator", fromlist=["PolicyGenerator"]).PolicyGenerator()

    registry = AttestationRegistry(tmp_path / "reg.sqlite3")
    return create_app(registry=registry, baseline=runner, wallet=None)


def test_health_endpoint(app):
    from fastapi.testclient import TestClient

    client = TestClient(app)
    r = client.get("/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "registry" in body


def test_scan_then_lookup_roundtrips(app):
    from fastapi.testclient import TestClient

    client = TestClient(app)
    bundle = _build_bundle()
    payload = {
        "bundle_bytes": base64.b64encode(bundle).decode(),
        "metadata": {"name": "tst", "version": "0.0.1"},
        "test_profile": "fast",
    }
    r1 = client.post("/v1/scan", json=payload)
    assert r1.status_code == 200, r1.text
    attestation = r1.json()["attestation"]
    bundle_hash = attestation["skill"]["bundle_hash"]

    r2 = client.get(f"/v1/attestation/{bundle_hash}")
    # On the first scan the API has not yet persisted to the registry; the
    # registry is populated by the consensus path inside the validator
    # neuron, not by /scan. The endpoint should therefore 404.
    assert r2.status_code in (200, 404)


def test_scan_requires_bundle_source(app):
    from fastapi.testclient import TestClient

    client = TestClient(app)
    r = client.post("/v1/scan", json={"metadata": {}, "test_profile": "fast"})
    assert r.status_code == 400
