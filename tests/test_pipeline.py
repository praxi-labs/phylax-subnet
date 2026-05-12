"""Tests for the static + SBOM analysis pipeline layers."""

from pathlib import Path

import pytest

from phylax.pipeline.static import StaticAnalyzer
from phylax.pipeline.sbom import SBOMAnalyzer
from phylax.protocol import Severity


def _make_bundle(tmp_path: Path, files: dict[str, str]) -> Path:
    for relpath, content in files.items():
        p = tmp_path / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------
# Static analyzer
# --------------------------------------------------------------------------

def test_static_flags_eval(tmp_path):
    _make_bundle(tmp_path, {
        "main.py": "x = eval(input())\n",
    })
    result = StaticAnalyzer(run_bandit=False).analyze(str(tmp_path))
    assert any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in result.findings)
    assert any("eval" in f.title.lower() for f in result.findings)


def test_static_captures_url(tmp_path):
    _make_bundle(tmp_path, {
        "client.py": 'URL = "https://api.example.com/v1"\n',
    })
    result = StaticAnalyzer(run_bandit=False).analyze(str(tmp_path))
    assert "api.example.com" in result.network_domains


def test_static_captures_env_var(tmp_path):
    _make_bundle(tmp_path, {
        "cfg.py": "import os; key = os.environ.get('STRIPE_API_KEY')\n",
    })
    result = StaticAnalyzer(run_bandit=False).analyze(str(tmp_path))
    assert "STRIPE_API_KEY" in result.env_vars


def test_static_clean_code_no_findings(tmp_path):
    _make_bundle(tmp_path, {
        "ok.py": "def add(a, b): return a + b\n",
    })
    result = StaticAnalyzer(run_bandit=False).analyze(str(tmp_path))
    assert all(f.severity == Severity.LOW for f in result.findings) or not result.findings


# --------------------------------------------------------------------------
# SBOM analyzer
# --------------------------------------------------------------------------

def test_sbom_parses_requirements_txt(tmp_path):
    _make_bundle(tmp_path, {
        "requirements.txt": "requests==2.31.0\nnumpy>=1.24\n",
    })
    result = SBOMAnalyzer(use_syft=False).analyze(str(tmp_path))
    names = {p["name"] for p in result.packages}
    assert "requests" in names
    assert "numpy" in names


def test_sbom_typosquat_detection(tmp_path):
    _make_bundle(tmp_path, {
        "requirements.txt": "reqeusts==2.31.0\n",  # typo of 'requests'
    })
    result = SBOMAnalyzer(use_syft=False).analyze(str(tmp_path))
    assert "reqeusts" in result.high_risk_packages


def test_sbom_install_hook_detected(tmp_path):
    _make_bundle(tmp_path, {
        "setup.py": "from setuptools import setup\nsetup(name='x', cmdclass={'install': lambda *_: None})\n",
    })
    result = SBOMAnalyzer(use_syft=False).analyze(str(tmp_path))
    assert any("install" in h for h in result.install_hooks)
