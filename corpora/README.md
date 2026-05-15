# Phylax Corpora

Ground-truth datasets used by validators to score miners (whitepaper §7).

## Families

| Directory | Family | Purpose |
|---|---|---|
| `known_bad/`   | Known-Bad   | Confirmed malicious bundles. Miners should produce `BLOCK`. |
| `known_good/`  | Known-Good  | Benign bundles with clean behaviour. Miners should produce `ALLOW`. |
| `near_miss/`   | Near-Miss   | Benign code that *looks* dangerous (shell exec, large blobs). Penalises over-blocking. |
| `adversarial/` | Adversarial | Obfuscated malware, delayed triggers, prompt-injection payloads. Tests evasion resistance. |
| `canaries/`    | Canary      | Private — never committed. Validators place hidden tasks here to detect overfitting. |
| `regression/`  | Regression  | Pinned historical samples. Detects behavioural drift across miner software versions. |
| `synthetic/`   | Synthetic   | Algorithmically generated each round by `phylax.validator.synth`. |

The validator loader pulls from all seven directories. Empty directories (e.g. `canaries/`, `synthetic/`) are tolerated.

## Task format

Each task is a JSON file matching [`schema.json`](schema.json). Bundles can be sourced three ways:

1. `bundle_url` — public HTTP URL the validator can fetch.
2. `bundle_bytes_b64` — base64 of the raw bundle bytes (use for tiny corpus tasks).
3. Generated at runtime by `SyntheticGenerator` (the bundle lives in memory).

## Adding a task

1. Build or obtain a skill bundle (zip).
2. Compute `sha256:<hex>` of the zip — that is the canonical `bundle_hash`.
3. Either host the zip somewhere the validator can fetch it, or embed it inline via `bundle_bytes_b64`.
4. Write the JSON file in the appropriate family directory.
5. Open a PR following [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Disclosure

Do not contribute live exploits or zero-days. All malicious samples must be:

- Already public (e.g. published in CVE writeups, malware sample databases), or
- Synthetic — written specifically as a test case, with no real victims.
