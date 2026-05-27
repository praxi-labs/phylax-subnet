import json
import zipfile

from phylax.cli import main as cli_main


def test_export_schema_writes_file(tmp_path):
    out = tmp_path / "schema.json"
    rc = cli_main(["export-schema", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "$defs" in data or "properties" in data


def _make_corpus(root, bundles: dict[str, str]) -> None:
    """Build a fake corpus tree: ``bundles/<first-2>/<hash>.zip`` per entry.
    ``bundles`` maps a synthetic 64-hex hash to a tiny main.py body."""
    bundles_dir = root / "bundles"
    for h, body in bundles.items():
        prefix = h[:2]
        d = bundles_dir / prefix
        d.mkdir(parents=True, exist_ok=True)
        zp = d / f"{h}.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("main.py", body)


def test_bulk_init_writes_skill_md_per_bundle_in_static_mode(tmp_path):
    """Static mode runs AST-only — no docker required — so the bulk
    pass produces one SKILL.md per bundle into skill_md/<2>/<hash>.md."""
    hashes = {
        "a" * 64: "import os; os.environ.get('FOO')\n",
        "b" * 64: "import urllib.request; urllib.request.urlopen('https://api.example.com/v1')\n",
    }
    _make_corpus(tmp_path, hashes)

    rc = cli_main([
        "manifest", "bulk-init", str(tmp_path),
        "--mode", "static",
        "--parallel", "1",
    ])
    assert rc == 0

    for h in hashes:
        out = tmp_path / "skill_md" / h[:2] / f"{h}.md"
        assert out.exists(), f"missing manifest for {h}"
        text = out.read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert "name:" in text


def test_bulk_init_is_idempotent(tmp_path):
    """Second run on the same corpus must skip everything that already
    has a SKILL.md."""
    hashes = {"c" * 64: "x = 1\n"}
    _make_corpus(tmp_path, hashes)

    rc1 = cli_main(["manifest", "bulk-init", str(tmp_path), "--mode", "static"])
    assert rc1 == 0
    out = tmp_path / "skill_md" / "cc" / ("c" * 64 + ".md")
    first_mtime = out.stat().st_mtime

    rc2 = cli_main(["manifest", "bulk-init", str(tmp_path), "--mode", "static"])
    assert rc2 == 0
    # File untouched on second pass — proves the skip path fired.
    assert out.stat().st_mtime == first_mtime


def test_bulk_init_respects_limit(tmp_path):
    hashes = {
        f"{i:064x}": f"# bundle {i}\n"
        for i in range(5)
    }
    _make_corpus(tmp_path, hashes)

    rc = cli_main([
        "manifest", "bulk-init", str(tmp_path),
        "--mode", "static", "--limit", "2",
    ])
    assert rc == 0
    written = list((tmp_path / "skill_md").rglob("*.md"))
    assert len(written) == 2


def test_bulk_init_continues_past_corrupt_bundle(tmp_path):
    """A malformed zip must not crash the whole run — log + move on."""
    good = "d" * 64
    bad = "e" * 64
    _make_corpus(tmp_path, {good: "x = 1\n"})
    # Plant a corrupt zip alongside the good one.
    bad_path = tmp_path / "bundles" / bad[:2] / f"{bad}.zip"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_bytes(b"this is not a zip")

    failures_log = tmp_path / "failures.txt"
    rc = cli_main([
        "manifest", "bulk-init", str(tmp_path),
        "--mode", "static",
        "--failures-log", str(failures_log),
    ])
    # Non-zero exit because at least one failed; the good one still got written.
    assert rc == 1
    assert (tmp_path / "skill_md" / good[:2] / f"{good}.md").exists()
    assert failures_log.exists()
    assert bad in failures_log.read_text(encoding="utf-8")
