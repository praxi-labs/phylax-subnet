import json

from phylax.cli import main as cli_main


def test_export_schema_writes_file(tmp_path):
    out = tmp_path / "schema.json"
    rc = cli_main(["export-schema", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "$defs" in data or "properties" in data
