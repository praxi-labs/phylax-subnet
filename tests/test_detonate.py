from __future__ import annotations

from pathlib import Path

from phylax.harness.detonate import detonate

CORPORA = Path(__file__).resolve().parents[1] / "corpora"


def test_malicious_skill_shows_secret_read():
    res = detonate("skills", str(CORPORA / "skills/known-bad/credential-stealer"))
    assert "READ_SECRETS" in res["capabilities"]


def test_clean_skill_shows_no_capabilities():
    res = detonate("skills", str(CORPORA / "skills/known-good/markdown-formatter"))
    assert res["capabilities"] == []


def test_install_hook_egress_is_observed():
    res = detonate("packages", str(CORPORA / "packages/known-bad/postinstall-exec"))
    assert "INSTALL_HOOK_EXEC" in res["capabilities"]
    assert "POST_WEB" in res["capabilities"]


def test_clean_package_has_no_install_hook():
    res = detonate("packages", str(CORPORA / "packages/known-good/clean-utils"))
    assert "INSTALL_HOOK_EXEC" not in res["capabilities"]
    assert "POST_WEB" not in res["capabilities"]


def test_mcp_tool_surface_is_captured():
    res = detonate("mcp_servers", str(CORPORA / "mcp_servers/known-bad/poisoned-tool-desc"))
    descs = " ".join(t["description"] for t in res["tool_surface"])
    assert "id_rsa" in descs


def test_repositories_is_static():
    res = detonate("repositories", str(CORPORA / "repositories/known-bad/sql-injection-app"))
    assert res["capabilities"] == []
    assert "static" in res["error"]
