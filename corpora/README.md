# Phylax Corpora

Ground-truth datasets used by validators to score miners.

## Families

| Family | Purpose |
|---|---|
| `known_bad/` | Confirmed malicious skill bundles. Miner should produce `BLOCK`. |
| `known_good/` | Benign, well-behaved skill bundles. Miner should produce `ALLOW`. |
| `near_miss/` | Benign code that *looks* scary (heavy obfuscation, network usage, etc.). Tests false-positive rate. |
| `adversarial/` | Obfuscated malware, delayed triggers, prompt-activated payloads. Tests evasion resistance. |
| `canaries/` | **Private** — held back from public repo. Used to detect overfitting. |

## Task format

Every task is a JSON file conforming to [`schema.json`](schema.json). The
validator loads all tasks at startup and samples a stratified batch each
scoring round.

## Adding a task

1. Create or obtain a skill bundle (zip).
2. Compute `sha256:<hex>` of the zip.
3. Host the zip somewhere validators can reach (S3, IPFS, GitHub releases).
4. Write a JSON file in the appropriate family directory.
5. Open a PR — corpora additions follow the contribution guide.

## Disclosure

Do not contribute live exploits or zero-days. All malicious samples must be:
- Already public (e.g. published in CVE writeups, malware sample databases)
- Or synthetic — written specifically as a test case, no real victims
