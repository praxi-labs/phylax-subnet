# Packages Corpus

A package is an npm, PyPI, or similar library. The defining fact about package attacks
is that **most malice happens at install time and on import**, before the package is
ever used. A malicious `postinstall` hook or a `setup.py` that runs code on install is
the signature attack.

## Artifact layout (PyPI-style example)

```
packages/known-bad/postinstall-exec/
├── setup.py          install script; the install hook lives here
├── pyproject.toml    package metadata
├── src/
│   └── helper/__init__.py
└── label.json        the ground truth
```

An npm-style package would instead carry a `package.json` with a `scripts.postinstall`
entry. The principle is the same: the manifest declares lifecycle hooks, and the hooks
are where install-time malice runs.

## How a package is analysed

Packages are a **detonation track**. The miner's agent installs and imports the package
in the sandbox, which triggers install hooks and import-time behavior, and observes what
happens. The probe is threaded through and the fs/network/process traces are captured.

The evidence is **dual-plane plus lifecycle and supply chain**:

- **action plane**: canonical capabilities exercised at runtime.
- **context plane**: present but minor, because a package is code, not reasoning
  injection. It matters only if the package feeds adversarial content into an agent.
- **lifecycle**: what ran at **install time** (postinstall / setup.py hooks) versus at
  **import time** (side effects on import). This is the distinctive package surface.
- **supply_chain**: the SBOM, dependency CVEs, typosquatting, dependency confusion, and
  maintainer signals.

The **evidence gate** is: probe in traces, trace hashes consistent, action plane
populated, and the lifecycle observed (did install execute code, did import have side
effects).

## Why lifecycle is the heart of it

A package can look clean as source and still attack you the moment you install it,
because the install hook runs arbitrary code before you import anything. So the agent
must observe the install phase, not just the runtime. Packages also lean on the
Cryptography and Keys capabilities, because crypto-wallet-stealing packages are one of
the most common real attacks on npm and PyPI.

## Finding categories for packages

- `install_hook_exec`: code runs during installation (the most important package signal).
- `import_side_effect`: behavior triggered merely by importing the package.
- `typosquat`: a name engineered to be confused with a popular package.
- `dependency_confusion`: resolves to a malicious internal-looking package.
- `dependency_cve`: a dependency carries a known vulnerability.
- `credential_theft`: reads and exfiltrates secrets or environment.
- `crypto_wallet_access`: touches wallet keys or signs transactions.

## known-good vs known-bad

- `known-good/`: clean packages with no custom install hook and ordinary dependencies, so
  findings are empty. Measures false positives.
- `known-bad/`: malicious packages that should return BLOCK, with the expected findings and
  the `lifecycle` and `supply_chain` blocks populated.

See `_label.example.json` for the full label format.
