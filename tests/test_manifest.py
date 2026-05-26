
from phylax.manifest import (
    IMPLICIT_ZERO_TRUST,
    SkillManifest,
    generate_manifest_from_observations,
    load_manifest,
    parse_skill_md,
    render_skill_md,
)

_VALID_FRONTMATTER = """\
---
name: weather-api
version: 1.2.3
network:
  egress: true
  allowed_domains:
    - api.weather.com
secrets:
  env_access: true
  allowed_vars:
    - WEATHER_API_KEY
---
# Weather Skill
Body text here.
"""


def test_parse_skill_md_extracts_frontmatter():
    m, body = parse_skill_md(_VALID_FRONTMATTER)
    assert m.name == "weather-api"
    assert m.version == "1.2.3"
    assert m.network.egress is True
    assert m.network.allowed_domains == ["api.weather.com"]
    assert m.secrets.env_access is True
    assert "WEATHER_API_KEY" in m.secrets.allowed_vars
    assert "Weather Skill" in body


def test_parse_skill_md_unfilled_axes_default_to_zero_trust():
    """A partial manifest only declares some axes; the omitted ones inherit
    the Implicit Zero-Trust defaults rather than being treated as 'any
    behavior allowed'."""
    partial = (
        "---\n"
        "name: small\n"
        "network:\n"
        "  egress: true\n"
        "  allowed_domains: [api.example.com]\n"
        "---\n"
    )
    m, _ = parse_skill_md(partial)
    assert m.network.egress is True
    assert m.process.shell_exec is False
    assert m.secrets.env_access is False
    assert m.filesystem.read_write == []


def test_parse_skill_md_no_frontmatter_falls_back_to_implicit_zero_trust():
    text = "# Just a readme, no frontmatter\n\nNothing structured here.\n"
    m, body = parse_skill_md(text)
    assert m == IMPLICIT_ZERO_TRUST
    assert body == text


def test_parse_skill_md_malformed_yaml_falls_back_to_implicit_zero_trust():
    text = (
        "---\n"
        "name: bad\n"
        "  bad indent: :::\n"
        "---\n"
        "body"
    )
    m, _ = parse_skill_md(text)
    assert m == IMPLICIT_ZERO_TRUST


def test_load_manifest_missing_file_returns_implicit_zero_trust(tmp_path):
    assert load_manifest(tmp_path) == IMPLICIT_ZERO_TRUST


def test_load_manifest_reads_skill_md_from_bundle_dir(tmp_path):
    (tmp_path / "SKILL.md").write_text(_VALID_FRONTMATTER, encoding="utf-8")
    m = load_manifest(tmp_path)
    assert m.name == "weather-api"
    assert m.network.allowed_domains == ["api.weather.com"]


def test_generate_manifest_from_observations_dedupes_and_sorts():
    """Observed lists from the sandbox can have duplicates (the same env var
    is read multiple times) and arrive in firing order. The generated
    manifest must be stable across runs of the same skill — dedupe and
    sort so a developer running `phylax manifest init` twice on the
    same code gets the same SKILL.md output."""
    m = generate_manifest_from_observations(
        observed_domains=["b.com", "a.com", "a.com"],
        observed_env_vars=["FOO", "BAR", "FOO"],
        observed_env_access=True,
    )
    assert m.network.allowed_domains == ["a.com", "b.com"]
    assert m.secrets.allowed_vars == ["BAR", "FOO"]
    assert m.network.egress is True


def test_generate_manifest_egress_false_when_no_network_observed():
    m = generate_manifest_from_observations(observed_domains=[], observed_ips=[])
    assert m.network.egress is False
    assert m.network.allowed_domains == []


def test_render_then_parse_round_trips():
    """render → parse must be lossless for the structured fields. Body
    text is treated separately and isn't required to round-trip exactly."""
    original = SkillManifest(
        name="round-trip",
        version="0.1.0",
        description="round-trip test",
    )
    original.network.egress = True
    original.network.allowed_domains = ["x.com"]
    original.secrets.env_access = True
    original.secrets.allowed_vars = ["KEY"]

    text = render_skill_md(original, "# Body\n")
    parsed, body = parse_skill_md(text)

    assert parsed.name == original.name
    assert parsed.network.allowed_domains == original.network.allowed_domains
    assert parsed.secrets.allowed_vars == original.secrets.allowed_vars
    assert "Body" in body


def test_implicit_zero_trust_is_strictest_possible():
    """Sanity: a skill with no manifest must default to the strictest
    possible declaration, so any observed behavior counts as discrepancy."""
    z = IMPLICIT_ZERO_TRUST
    assert z.network.egress is False
    assert z.network.allowed_domains == []
    assert z.process.shell_exec is False
    assert z.process.allowed_commands == []
    assert z.secrets.env_access is False
    assert z.secrets.allowed_vars == []
    assert z.filesystem.read_only == []
    assert z.filesystem.read_write == []
