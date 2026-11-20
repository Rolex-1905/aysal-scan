# Aysal-Scan 🔐

> **Status: in active development (`1.1.0.dev` series).** The latest *published* release on PyPI is 1.0.2. The code on `main` is substantially newer and is not yet released; install it from source (below).

> **A**nalyze **Y**our **S**ecrets **A**nd **L**eaks — find leaked credentials in git repositories, check which ones are still live, and score how urgent each leak is.

[![CI](https://github.com/Rolex-1905/aysal-scan/actions/workflows/aysal-scan.yml/badge.svg)](https://github.com/Rolex-1905/aysal-scan/actions/workflows/aysal-scan.yml)
[![PyPI](https://img.shields.io/pypi/v/aysal-scan)](https://pypi.org/project/aysal-scan/)
[![Python](https://img.shields.io/pypi/pyversions/aysal-scan)](https://pypi.org/project/aysal-scan/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Aysal-Scan finds secrets (API keys, tokens, private keys, connection strings), and then answers the
questions that decide what you do next:

| Question | How Aysal-Scan answers it |
|---|---|
| Is the credential still live? | Read-only provider API checks (opt-out with `--no-blast-radius`) |
| What can it do? | Privilege level (admin / write / read) from the provider's response |
| Is it still in my code, or only in history? | `in_head` flag from a HEAD comparison |
| How long has it been exposed? | First-introducing commit date |
| What should I do about it? | Provider-specific revoke steps + history clean-up |
| What first? | A 0–100 **risk score** with every contributing factor listed |

## Where it fits (honest positioning)

[TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Gitleaks](https://github.com/gitleaks/gitleaks)
are mature, fast Go tools with far larger rule sets and communities. Aysal-Scan is a **Python** tool
that trades raw speed and breadth for **context**: it tries to tell you which leaks matter and why,
and it is designed to be easy to read, extend and audit. If you need maximum throughput over huge
monorepos or hundreds of detectors, use those tools — or run them alongside this one.

## Install

```bash
# Development version (this repository's main branch):
pip install "git+https://github.com/Rolex-1905/aysal-scan@main"
pip install "aysal-scan[ui] @ git+https://github.com/Rolex-1905/aysal-scan@main"   # + interactive mode

# Last published release (older, 1.0.2):
pip install aysal-scan
```

> Use a virtual environment. Mixing global packages is the most common cause of install errors.

## Quick start

```bash
aysal-scan scan .                          # scan the working tree (verifies found credentials)
aysal-scan scan . --no-blast-radius        # offline: no API calls
aysal-scan scan --staged                   # pre-commit: only the lines being added
aysal-scan scan --commits 20               # last 20 commits of this branch
aysal-scan scan --full-history             # every commit on every branch and tag
aysal-scan scan https://github.com/org/repo --full-history
aysal-scan scan . --report sarif -o results.sarif
aysal-scan ui                              # guided interactive mode
```

### ⚠ Verification uses the credentials it finds

By default, Aysal-Scan makes **read-only** requests to each provider (for example
`sts:GetCallerIdentity` for AWS, `GET /user` for GitHub) *using the leaked credential* to see whether
it still works. This can appear in the credential owner's audit logs and may require authorization
when you scan **someone else's** repository (e.g. a client engagement). Use `--no-blast-radius`
(or `AYSAL_SCAN_NO_VERIFY=1`) when you are not authorised to use the credentials. Checks are
read-only, rate-limited per provider and time-limited. A bad-format or unverifiable value is never
reported as "active".

## Speed

* `--jobs N` (default automatic): trees of 300+ files are scanned by worker processes; `--jobs 1` forces a
  single process. Output is identical either way.
* Directory walking prunes skipped folders such as `node_modules`; history scans stream one `git log -p`
  (git 2.31+). `--max-time` bounds a long history scan.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; nothing at or above `--fail-on` (default `HIGH`) |
| `1` | Scan completed; secrets at or above `--fail-on` found |
| `2` | The scan **could not run**: bad path, not a git repository, invalid option/config, clone failure |

A scan that cannot run never reports "clean" (this includes unexpected internal errors, which also exit `2`; set `AYSAL_SCAN_DEBUG=1` for the traceback). `--min-severity` only limits what is **displayed**;
pass/fail always considers every finding. `--no-fail` suppresses exit `1`, never exit `2`.

## Severity and risk score

**Severity** answers *what kind of secret is this?* and is then adjusted by evidence:

| Evidence | Effect |
|---|---|
| Credential verified **revoked / expired** | Lowered to `LOW` |
| Verified **live** and the severity was below `HIGH` | Raised to `HIGH` |
| Verified **live with admin-level privileges** | Raised to `CRITICAL` |
| Checker says it is harmless by design (expired JWT, Supabase `anon` key, test-mode Stripe key) | Lowered to `LOW` |
| Example/template file (`.env.example`, `*.sample`) | One level lower |
| Local/dev-looking database host | `MEDIUM` instead of `HIGH` |
| Could not verify (rate limit, network, unsupported provider) | Unchanged, tagged `unverified` |

**Risk score (0–100)** answers *how urgent is this leak?* from independent factors, all listed in
the report (`--verbose` in the terminal): validity (live +40 / unverified +20 / revoked ≤12 total),
privilege (+25 admin … +8 read), exposure (present now +15 / history-only +5), age (≥30 d +5,
≥365 d +10), spread (+3), credential class (0–15), and context penalties (example file −25,
public-by-design key −15). Findings are ordered by severity, then score.

## Supported secrets

Detection covers about 40 rules. “Verify” means a read-only provider check exists; everything else
is detected and scored without a network call.

| Group | Detected | Verify |
|---|---|---|
| Cloud | AWS access keys (`AKIA`, temporary `ASIA`), GCP service-account JSON, Azure client secrets, Google API keys, Google OAuth client secrets | AWS ✔ · Google API ✔ · GCP / Azure: manual review |
| Source control & registries | GitHub (`ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`), GitLab, npm, PyPI, Docker Hub | GitHub ✔ · GitLab ✔ · npm ✔ · PyPI: manual |
| AI / ML | OpenAI, Anthropic, Hugging Face | ✔ all three |
| Payments & SaaS | Stripe (live / restricted / test / publishable), SendGrid, Twilio, Slack (bot / user / webhook), Heroku, DigitalOcean, Shopify, Telegram, Databricks, Postman, Linear, Notion, PlanetScale, Supabase | Stripe ✔ · SendGrid ✔ · Twilio ✔ · Slack ✔ · Heroku ✔ · DigitalOcean ✔ |
| Crypto & connection strings | Private keys (RSA, EC, DSA, OpenSSH, PKCS#8, encrypted, PGP), age secret keys, database URLs (Postgres, MySQL, MongoDB, Redis, AMQP, MSSQL), JWTs | JWT: decoded (signature cannot be verified) |
| Heuristic | `password=`/`token=`-style assignments (placeholder- and code-reference-filtered), high-entropy strings | — |

Plus your own rules (below).

## Configuration: `aysal-scan.toml`

Defaults and custom rules live in `aysal-scan.toml` in the current directory (or `--config PATH`).
Command-line flags always win over the file.

```toml
min_severity = "MEDIUM"
fail_on = "HIGH"
no_blast_radius = false
max_file_size_mb = 5
allow_list = ["<finding id>"]

[[rules]]
id = "acme-internal-token"
description = "ACME internal API token"
regex = 'acme_[a-z0-9]{32}'
severity = "HIGH"            # CRITICAL | HIGH | MEDIUM | LOW | INFO
secret_group = 0             # capture group holding the secret
keywords = ["acme"]          # optional: the line must contain one of these
entropy = 3.0                # optional: minimum Shannon entropy
```

## Suppressing a finding

Put a marker on the line itself — no ignore file needed:

```python
API_KEY = "sk_live_..."   # aysal-scan:allow
```

`gitleaks:allow` and `pragma: allowlist secret` work too. For whole files or folders use
`AysalScanignore`; to suppress by finding id use `--allow-list`.

## Encoded secrets

Base64 values are decoded and rescanned, so a Kubernetes `Secret`, a `Basic` auth header or an encoded
token is found (tagged `decoded-base64`). One level only; binary data and prose are ignored.

## Compliance mapping

Each finding carries `cwe` (CWE-798 hard-coded credentials, CWE-259 hard-coded password, CWE-321
hard-coded cryptographic key, CWE-522 insufficiently protected credentials) and `owasp` (Top 10 2021
A07 / A02) in JSON, SARIF (shown in GitHub code scanning) and Markdown output.

## Ignoring files: `AysalScanignore`

Uses **real gitignore syntax** (negation `!`, `**`, anchoring `/`, directory `dir/`):

```gitignore
tests/fixtures/
*.example
**/generated/
!important/secrets-to-keep-scanning.env
```

By default Aysal-Scan skips lock files, build output, `node_modules`, virtualenvs (detected by
`pyvenv.cfg`), binaries, files over 5 MB and symlinks, and **reports how many it skipped**. It does
**not** skip `logs/`, `bin/`, `env/` or `tmp/`, because real secrets live there.

## Scanning untrusted repositories

A repository you are scanning can contain its own `AysalScanignore` — and a hostile one can contain
`*` to hide everything. When you scan code you do not control (client engagements, bug bounty,
downloaded samples) use:

```bash
aysal-scan scan ./client-repo --no-ignore-file --no-blast-radius
# or supply a trusted ignore file of your own:
aysal-scan scan ./client-repo --ignore-file ~/my.ignore
```

Terminal output escapes all untrusted text; symlinks are never followed; oversized and binary files
are skipped; ids in reports can be salted (`AYSAL_SCAN_ID_SALT`) so shared reports do not expose a
crackable SHA-256 of weak secrets.

## CI usage (GitHub Actions)

The packaged Action and Docker image are rebuilt only when a release is published, so until then use the CLI
directly. This works today and exercises exactly the code on `main`:

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  aysal-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # needed to scan full history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/Rolex-1905/aysal-scan@main"
      - name: Scan tree and history (fails on HIGH or worse)
        run: |
          aysal-scan scan . --no-blast-radius --fail-on HIGH \
            --output-sarif aysal.sarif --output-markdown aysal.md
          aysal-scan scan . --full-history --no-blast-radius --fail-on HIGH
      - run: cat aysal.md >> "$GITHUB_STEP_SUMMARY"
        if: always()
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aysal.sarif
```

## Pre-commit

```bash
aysal-scan install-hook          # installs a git pre-commit hook for this repository
```

or with the `pre-commit` framework (pin `rev` to a commit SHA once you depend on it):

```yaml
repos:
  - repo: https://github.com/Rolex-1905/aysal-scan
    rev: main
    hooks:
      - id: aysal-scan          # fast, offline, only the lines being added
```

## Reports

`--report terminal|json|html|sarif|markdown` (`-o FILE`). JSON and SARIF go to **stdout** when no file
is given and all progress messages go to **stderr**, so `aysal-scan scan . --report json > out.json`
is always valid JSON. SARIF uses repo-relative paths, static rule metadata and GitHub's
`security-severity`, and supports `--sarif-baseline` so only *new* findings alert.

## Verifying the verifiers

`scripts/live_verify.py` checks each provider checker against the real API using your own throwaway
credentials; see `docs/LIVE_VERIFICATION.md` for free ways to get them. Anthropic, OpenAI and DigitalOcean
checkers cannot be tested for free and are covered by mocked tests only.

## Benchmark

`benchmarks/` contains a labelled synthetic corpus and a runner that scores any scanner on
precision/recall (adapters for Gitleaks and TruffleHog are included but unverified — see
`benchmarks/README.md`). The corpus is synthetic and written by this project's author: it is a
regression guard, **not** evidence of superiority.

## Limitations

- Slower than Go scanners; very large histories take time (`--max-time`, `--commits` help).
- Verified providers are a subset of detected ones; other credentials are detected and scored only.
- Hex-only and base32 secrets are found only when a keyword (`token`, `secret`, `key`…) is nearby.
- Passphrase-style passwords made of letters only are skipped by the code-reference filter.
- A JWT's signature, and GCP/Azure credentials, cannot be verified without using them.
- `AysalScanignore` is read from the working tree for historical commits as well.
- History scans examine added lines; secrets that only existed in deleted files are found via the
  commit that added them, but secrets in binary files are not.

## License

MIT © 2026 Neeraj Mudunuru
