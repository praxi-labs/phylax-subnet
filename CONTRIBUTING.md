# Contributing to Phylax

We welcome contributions across the stack — detection rules, sandbox
instrumentation, scoring tweaks, runtime integrations, and corpora.

## Priority areas

1. **Detection patterns** — new patterns for emerging attack techniques
   (prompt-injection branches, dependency confusion, malicious model
   weights).
2. **Corpora expansion** — public, reproducible malicious skill samples
   and matched benign-but-suspicious near-misses.
3. **Runtime integration guides** — concrete recipes for LangChain,
   CrewAI, OpenClaw, and other agent frameworks.
4. **False-positive analysis** — surface miner outputs that mis-classify
   common idioms so we can tighten the corpora.

## Workflow

1. Open an issue describing the change before writing significant code.
2. Fork → feature branch → PR.
3. Run the local test suite: `pytest tests/ -v`.
4. Format with `ruff format` and lint with `ruff check`.
5. Sign your commits — we follow the DCO (Developer Certificate of Origin).

## What we won't merge

- Live exploits or zero-days without a coordinated-disclosure plan.
- Corpora additions that target real, live malicious actors (we test
  detection, not attribution).
- Changes that break SSSA schema compatibility without a major version
  bump.
- Detection rules without unit-test coverage in `tests/test_pipeline.py`.

## Code style

- Python 3.10+ syntax allowed (`X | Y` union, structural pattern matching).
- Public APIs documented with concise docstrings. Internal helpers
  do not need docstrings — clear names are preferred.
- No `print()` in library code. Use `phylax.utils.logging.get_logger`.

## Reporting security issues

If you find a vulnerability in Phylax itself (not in a skill it scans),
please email security@phylax.network and **do not** open a public issue.
We will respond within 72 hours.

## Code of Conduct

Be kind. Be specific. Assume good faith. Disagreements about design are
welcome; personal attacks are not.
