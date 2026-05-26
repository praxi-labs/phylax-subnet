# SKILL.md Capability Manifest — Spec v1

The contract a skill bundle makes about what it'll do at runtime. Phylax compares this declaration against the sandbox's observed behavior on every scan; the gap between promise and reality is the primary scoring signal.

## File format

`SKILL.md` is a markdown file at the bundle root, with a YAML frontmatter block followed by free-form developer documentation. Tools that don't speak YAML can still render the body as a regular README.

```markdown
---
name: weather-api
version: 1.2.3
description: Fetches current weather from Weather.com
network:
  egress: true
  allowed_domains:
    - api.weather.com
  allowed_ips: []
filesystem:
  read_only: []
  read_write:
    - ./cache
process:
  shell_exec: false
  allowed_commands: []
secrets:
  env_access: true
  allowed_vars:
    - WEATHER_API_KEY
runtime:
  max_memory_mb: 256
  timeout_seconds: 30
---

# Weather Skill

Free-form description, usage examples, etc.
```

## Schema

| Field | Type | Default | Purpose |
|---|---|---|---|
| `name` | string | `"unknown"` | Human-readable skill name |
| `version` | string | `"unknown"` | Semver, also used for invalidation tracking |
| `description` | string | `""` | One-line summary; surfaces in the registry |
| `network.egress` | bool | `false` | Does the skill make outbound network calls at all? |
| `network.allowed_domains` | string[] | `[]` | Domains the skill is allowed to contact |
| `network.allowed_ips` | string[] | `[]` | IPs the skill is allowed to contact (use sparingly) |
| `filesystem.read_only` | string[] | `[]` | Paths the skill reads (relative to bundle root, or absolute) |
| `filesystem.read_write` | string[] | `[]` | Paths the skill may also write |
| `process.shell_exec` | bool | `false` | Does the skill exec a shell? |
| `process.allowed_commands` | string[] | `[]` | Subprocess invocations the skill makes |
| `secrets.env_access` | bool | `false` | Does the skill read environment variables? |
| `secrets.allowed_vars` | string[] | `[]` | Specific env vars the skill needs |
| `runtime.max_memory_mb` | int | `256` | Memory ceiling the runtime should enforce |
| `runtime.timeout_seconds` | int | `30` | Wall-clock ceiling |

Fields not in this list are silently ignored — forward-compatible for future schema versions.

## Implicit Zero-Trust default

Bundles without a `SKILL.md` are evaluated against the Implicit Zero-Trust baseline:

```yaml
network: { egress: false, allowed_domains: [], allowed_ips: [] }
filesystem: { read_only: [], read_write: [] }
process: { shell_exec: false, allowed_commands: [] }
secrets: { env_access: false, allowed_vars: [] }
runtime: { max_memory_mb: 256, timeout_seconds: 30 }
```

Any observed behavior from such a skill is automatically counted as a discrepancy. This is the structural pressure that drives ecosystem-wide manifest adoption: the only way a developer gets a clean attestation is by declaring honestly what their skill needs.

## Generating a draft

Don't hand-write the manifest. Use the CLI:

```bash
phylax manifest init ./my-skill.zip --output SKILL.md
```

This runs the bundle in the sandbox once, observes every network call / file access / env var read / process spawn the harness sees, and emits a draft `SKILL.md` declaring exactly what was observed. Commit the result; future scans grade against it.

Re-run after any change that legitimately adds new capabilities:

```bash
phylax manifest init ./my-skill.zip --output SKILL.md
git diff SKILL.md   # review the new declarations before committing
```

## Validating before publish

```bash
phylax manifest check ./my-skill.zip          # prints the parsed manifest as JSON
phylax manifest check ./my-skill.zip --strict # exits non-zero if SKILL.md is missing
```

Drop `--strict` into CI to refuse publishing a bundle that has no manifest.

## Discrepancy scoring

Phylax compares observed behavior against the declared manifest with **asymmetric penalties**:

- **Under-declaration** (skill did more than the manifest promised) is a real security violation. Example: manifest says `network.egress: false` but the skill connects to `evil.example`. The discrepancy axis collapses to zero and the verdict escalates toward `BLOCK`.
- **Over-declaration** (skill said it might do X but didn't) is a soft warning. Example: manifest lists `STRIPE_API_KEY` in allowed_vars but the skill never reads it. The scan emits a "tighten your manifest" suggestion without lowering the verdict.

The full scoring formula is documented in [scoring.md](scoring.md).

## Forward compatibility

The schema is versionless in v1 — extra fields are ignored. Breaking changes (renames, removed fields) bump to v2 with a `schema_version: 2` declaration in the frontmatter. v1 manifests will be parsed forever; v2 tooling will accept both.
