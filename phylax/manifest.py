"""SKILL.md capability manifest — the declared contract a skill makes about
what it'll do at runtime. Phylax's discrepancy engine compares this
declaration against the sandbox's observed behavior, with under-declaration
(skill did more than it said) treated as a security violation and
over-declaration (skill said more than it did) as a soft signal of
over-permissive design.

Schema (SKILL.md is markdown with YAML frontmatter; body is free-form
developer docs):

    ---
    name: weather-api
    version: 1.0.0
    network:
      egress: true
      allowed_domains: [api.weather.com]
    filesystem:
      read_only: []
      read_write: []
    process:
      shell_exec: false
      allowed_commands: []
    secrets:
      env_access: true
      allowed_vars: [WEATHER_API_KEY]
    runtime:
      max_memory_mb: 256
      timeout_seconds: 30
    ---

    # Weather API Skill
    Fetches current weather from the Weather.com API.

Skills without a SKILL.md are evaluated against IMPLICIT_ZERO_TRUST: no
network, no env access, no shell, empty filesystem allowlists. Any
observed behavior counts as discrepancy. This forces ecosystem-wide
capability documentation as a side effect — the only way a developer
gets a clean attestation is by writing a SKILL.md that honestly
declares what the skill needs.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class NetworkManifest(BaseModel):
    egress: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)


class FilesystemManifest(BaseModel):
    read_only: list[str] = Field(default_factory=list)
    read_write: list[str] = Field(default_factory=list)


class ProcessManifest(BaseModel):
    shell_exec: bool = False
    allowed_commands: list[str] = Field(default_factory=list)


class SecretsManifest(BaseModel):
    env_access: bool = False
    allowed_vars: list[str] = Field(default_factory=list)


class RuntimeManifest(BaseModel):
    max_memory_mb: int = 256
    timeout_seconds: int = 30


class SkillManifest(BaseModel):
    """The declared capability contract for a skill bundle."""

    model_config = ConfigDict(extra="ignore")

    name: str = "unknown"
    version: str = "unknown"
    description: str = ""
    network: NetworkManifest = Field(default_factory=NetworkManifest)
    filesystem: FilesystemManifest = Field(default_factory=FilesystemManifest)
    process: ProcessManifest = Field(default_factory=ProcessManifest)
    secrets: SecretsManifest = Field(default_factory=SecretsManifest)
    runtime: RuntimeManifest = Field(default_factory=RuntimeManifest)


IMPLICIT_ZERO_TRUST = SkillManifest()


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


def parse_skill_md(text: str) -> tuple[SkillManifest, str]:
    """Parse a SKILL.md string. Returns (manifest, body_text).

    Falls back to IMPLICIT_ZERO_TRUST when frontmatter is missing or
    malformed — keeps the discrepancy engine running on garbage input
    instead of crashing.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return IMPLICIT_ZERO_TRUST, text
    body = text[m.end():]
    try:
        data = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        return IMPLICIT_ZERO_TRUST, body
    if not isinstance(data, dict):
        return IMPLICIT_ZERO_TRUST, body
    try:
        return SkillManifest(**data), body
    except Exception:
        return IMPLICIT_ZERO_TRUST, body


def load_manifest(bundle_path: str | Path) -> SkillManifest:
    """Find and load SKILL.md from a bundle directory. Returns
    IMPLICIT_ZERO_TRUST when no manifest exists or it's malformed."""
    p = Path(bundle_path) / "SKILL.md"
    if not p.exists():
        return IMPLICIT_ZERO_TRUST
    try:
        manifest, _ = parse_skill_md(p.read_text(encoding="utf-8"))
        return manifest
    except OSError:
        return IMPLICIT_ZERO_TRUST


def generate_manifest_from_observations(
    *,
    name: str = "unknown",
    version: str = "unknown",
    description: str = "",
    observed_domains: list[str] | None = None,
    observed_ips: list[str] | None = None,
    observed_fs_reads: list[str] | None = None,
    observed_fs_writes: list[str] | None = None,
    observed_shell_exec: bool = False,
    observed_commands: list[str] | None = None,
    observed_env_access: bool = False,
    observed_env_vars: list[str] | None = None,
) -> SkillManifest:
    """Build a draft SkillManifest from sandbox observations.

    The intent: a developer runs `phylax manifest init` once on their
    bundle, the harness observes what the skill does, and the resulting
    manifest declares exactly what was seen. The developer commits the
    SKILL.md; from then on, any future change in the skill's runtime
    behavior shows up as a discrepancy that has to be either fixed in
    the code or acknowledged by updating the manifest.
    """
    return SkillManifest(
        name=name,
        version=version,
        description=description,
        network=NetworkManifest(
            egress=bool(observed_domains or observed_ips),
            allowed_domains=sorted(set(observed_domains or [])),
            allowed_ips=sorted(set(observed_ips or [])),
        ),
        filesystem=FilesystemManifest(
            read_only=sorted(set(observed_fs_reads or [])),
            read_write=sorted(set(observed_fs_writes or [])),
        ),
        process=ProcessManifest(
            shell_exec=observed_shell_exec,
            allowed_commands=sorted(set(observed_commands or [])),
        ),
        secrets=SecretsManifest(
            env_access=observed_env_access,
            allowed_vars=sorted(set(observed_env_vars or [])),
        ),
    )


def render_skill_md(manifest: SkillManifest, body: str = "") -> str:
    """Serialize a SkillManifest into SKILL.md text with YAML frontmatter."""
    yaml_block = yaml.safe_dump(
        manifest.model_dump(),
        sort_keys=False,
        default_flow_style=False,
    )
    body_block = body if body.endswith("\n") or not body else body + "\n"
    return f"---\n{yaml_block}---\n{body_block}"
