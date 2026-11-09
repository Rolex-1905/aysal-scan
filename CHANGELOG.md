# Changelog

All notable changes to Aysal-Scan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0rc1] - 2026-10-21

A ground-up hardening release. Every item below was reproduced against 1.0.2 before being fixed,
and has a regression test.

### Breaking / behaviour changes
- **Exit code 2** now means "the scan could not run" (missing path, not a git repository, invalid
  option or config, clone failure). Previously these printed "No secrets found" and exited 0.
- `--report json|sarif|markdown` print to **stdout** when `-o` is not given (previously SARIF wrote
  a default file). Progress and status messages go to **stderr**.
- Invalid `--report` / `--min-severity` values are errors instead of silently falling back.
- Credentials verified **revoked** are lowered to `LOW`; verified **live + admin** become `CRITICAL`.
  A JWT is never reported "active" (its signature cannot be verified); expired and public `anon`
  JWTs become `LOW`; live Stripe **test** keys stay `LOW`.
- **Finding ids changed** for private keys (now the key body, not the header), GCP service accounts
  (now key id + email), and entropy findings (the `NAME=` prefix is no longer hashed). Existing
  `--allow-list` entries and SARIF baselines for those findings must be regenerated.
- History findings point at the commit that **introduced** the secret; later occurrences are listed
  as extra locations. `--full-history` now scans **every ref**, not only HEAD.
- `AysalScanignore` uses real gitignore semantics (`pathspec`): negation, `**`, anchoring.
- The `INFO`/entropy noise inside PEM blocks, and the secret half of paired AWS/Twilio credentials,
  are no longer reported as separate findings.
- The GitHub Action image now runs as root (a GitHub requirement) and reads its inputs correctly.

### Added
- **Risk score** (0-100) with listed factors, `in_head` (still present at HEAD) and exposure age.
- ~20 new detectors: Anthropic, Hugging Face, GitLab, DigitalOcean, Docker Hub, Shopify, Telegram,
  Databricks, Postman, Linear, Notion, PlanetScale, Supabase, Google OAuth secrets, age keys, Stripe
  restricted keys, Slack user/app tokens, AWS temporary keys, extra GitHub token types, DSA / encrypted
  / PGP private keys, Heroku `HRKU-` tokens.
- Verifiers for Anthropic, Hugging Face, GitLab and DigitalOcean on a strict shared HTTP classifier.
- `--fail-on`, `--config` (`aysal-scan.toml` with custom rules), `--ignore-file`, `--no-ignore-file`,
  `--max-file-size`, `--max-time`, `--output-markdown`, `--report markdown`, `AYSAL_SCAN_NO_VERIFY`.
- Provider-specific remediation text for every secret type.
- Scan-quality reporting: skipped / unreadable / oversized files and partial history appear as warnings.
- SARIF: repo-relative paths, static rule metadata, GitHub `security-severity`, `partialFingerprints`.
- `benchmarks/` labelled corpus + precision/recall runner; `SECURITY.md` with the threat model.
- Windows + Linux, Python 3.11 + 3.12 CI matrix; coverage gate raised to 80%.

### Fixed - security
- Terminal output injection: a crafted JWT claim or file name could crash the scan, render a
  clickable link, or spoof a green "PASSED". All untrusted text is escaped; JWT claims are sanitised.
- HTML report summary fields are escaped.
- Symlinks are no longer followed out of the scanned tree.
- A repository's own `AysalScanignore` can be disabled for untrusted repos.
- Non-OpenAI keys (e.g. Anthropic) were sent to `api.openai.com`; the `sk-` rule is now bounded.
- The Slack webhook checker can only contact `hooks.slack.com`.
- Reports no longer contain the local scan path; id hashes can be salted (`AYSAL_SCAN_ID_SALT`).

### Fixed - correctness
- OpenAI, Stripe, npm, SendGrid, Twilio, GitHub and Slack treated HTTP 403/429/5xx as an active key.
  Only a real 200 is "active"; transient errors are retried and reported as unverified.
- Stripe test keys were reported as LIVE and escalated to HIGH.
- Google checker accepted invalid keys (Maps answers HTTP 200 + `REQUEST_DENIED`).
- AWS: real boto3 timeouts (was 60 s), exact `AdministratorAccess` match, root credentials,
  partial IAM results kept, temporary `ASIA` keys no longer misreported as revoked.
- GCP service-account JSON never reached its checker; every service-account file shared one id.
  Distinct private keys shared one id (header-only fingerprint).
- Verification delay was quadratic (50 findings ~ 3.5 min offline); now per-provider throttling.
- `--staged` ignored the skip rules and `AysalScanignore`, failed from sub-directories and on
  non-ASCII file names, and scanned unchanged lines. History line numbers were relative to the
  added-lines blob; merged secrets were attributed to the merge commit.
- Lock files (`package-lock.json`, `pnpm-lock.yaml`) were scanned; `logs/`, `bin/`, `env/`, `tmp/`
  were skipped; skip fragments matched by substring; single-file scans of anything under `tmp/`,
  `build/`, `output/`... returned nothing.
- AKIA keys matched inside longer tokens; DB URL placeholders were HIGH and `redis://:pw@` was missed;
  code references (`process.env.X`) matched the Azure rule.
- GitHub Action ignored all its inputs (dash drops `INPUT_MIN-SEVERITY`); non-ASCII/UTF-8-BOM ignore
  files broke the first pattern; HTML "Copy ID" reverted to "Copy".
- Release workflows could publish untested code and moved Docker `latest` for any tag; they now
  require passing tests and `tag == v<version>`.

### Performance
- Directory walking prunes skipped directories (60,000 files under `node_modules`: 4.4 s -> 0.3 s).

---

## [1.0.1] — 2026-06-19

Patch fixes folded into the v1.0.0 release tag (package version bumped
to 1.0.1 because 1.0.0 was already published to PyPI before these fixes
landed - PyPI never allows reusing a version number).

### Fixed
- JWT tokens were producing up to 4 findings instead of 1 — the entropy
  fallback's tokenizer split JWTs on their dot separators, and the
  resulting fragments didn't match the JWT pattern in isolation. Fixed
  with span-overlap detection between named-pattern matches and entropy
  tokens on the same line.
- Slack bot token regex required exactly 11-digit ID segments; real
  tokens vary 6-14 digits per segment and were silently missed.
- `AysalScanignore` didn't cover `tests/conftest.py`,
  `tests/test_blast_radius.py`, or `tests/test_blast_radius_checkers.py`,
  causing the tool to flag its own test fixtures on self-scan.
- Removed unused `PyGithub` dependency — never imported anywhere in the
  codebase.

---

## [1.0.0] — 2026-06-19

First production-ready release. Builds on 0.1.0 with critical correctness
fixes, expanded test coverage, and several new capabilities identified
during a full production-readiness review.

### Added
- SARIF 2.1.0 output format for GitHub Security tab integration (`--report sarif`)
- SARIF baseline suppression (`--sarif-baseline`) — previously-seen findings are
  marked `unchanged` instead of re-alerting on every scan
- `--output-json` and `--output-sarif` flags — produce multiple report formats in a single scan
- `--allow-list` flag — suppress known findings by ID (comma-separated finding IDs)
- `--verbose` / `-V` flag — shows per-finding blast radius debug info (check_performed, is_active)
- GCP Service Account JSON detection (CRITICAL severity, auto-detected by JSON structure)
- Azure Client Secret detection (HIGH severity, context-aware pattern)
- Stripe test key detection — `sk_test_` (LOW) and `pk_test_` (INFO)
- Retry with exponential backoff on blast radius HTTP calls (handles 429, 5xx, timeouts)
- Time budget (120s) on git history enumeration — full-history scans on very large
  repos now degrade gracefully instead of hanging indefinitely
- Partial-history warning — `--commits N` now warns when older commits were skipped
- Interactive HTML report — collapsible findings, severity filter, copy-to-clipboard
  for masked secrets and finding IDs
- `tests/conftest.py` — shared pytest fixtures for fake git repos, secret content, and mock HTTP responses
- `tests/test_blast_radius_checkers.py` — full test coverage for AWS, Azure, Generic,
  Google, Heroku, JWT, PyPI, SendGrid, Slack, Slack Webhook, Twilio checkers, and the
  retry/backoff logic in `base.py`
- Coverage gate — CI fails if coverage drops below 60%
- `CONTRIBUTING.md` — full contributor guide including how to add new secret types
- GitHub issue templates for bug reports and feature requests
- `LICENSE` — MIT
- `GCPServiceAccountChecker` blast radius checker
- `AzureChecker` blast radius checker

### Changed
- `action.yml` now pulls the pre-built GHCR image (`docker://ghcr.io/rolex-1905/aysal-scan:latest`)
  instead of rebuilding the Dockerfile on every Action run
- AWS checker now enumerates group-attached and inline IAM policies in addition to
  directly-attached user policies — previously a key with `AdministratorAccess`
  granted via group membership was reported as "could not enumerate"
- Blast radius checks now run with a staggered start (0.5s apart) and `max_workers=3`
  instead of firing all checks simultaneously, reducing 429 rate-limit responses
  from providers like GitHub
- GENERIC pattern now requires a minimum entropy floor and an expanded dummy-value
  list, eliminating false positives on `.env` values like `localhost`, `development`, `production`
- `questionary` moved to optional dependency — install with `pip install aysal-scan[ui]`
- `__version__` now reads from package metadata via `importlib.metadata` — `pyproject.toml` is the single source of truth
- `entrypoint.sh` rewritten — single scan pass produces HTML + JSON + SARIF simultaneously (was two separate scans)
- CI workflow split into two jobs — `test` (pytest + coverage) and `secret-scan` (self-scan)
- `BaseChecker` extended with `check_with_retry()` — all blast radius checks use it automatically
- Retry detection in `base.py` now matches on the literal `"HTTP {code}"` substring
  instead of a bare status-code string, preventing false retries on unrelated
  error text that happens to contain a number like "500"
- `ui()` rescan loop now resolves (clones) the target once and reuses it across
  "Rescan same target" — previously it re-cloned remote repos on every iteration

### Fixed
- `yourusername` placeholder replaced with `Rolex-1905` in README and action.yml
- Copyright year corrected to 2026
- Duplicate `run_blast_radius` function removed from `blast_radius/__init__.py`
- `test_scan_commits_finds_secret` missing `self` parameter in `TestScanCommits`
- `scan_commits` (git history scanning) now applies the same skip rules as directory
  scanning — previously committed `node_modules/`, lock files, and other ignored
  paths were scanned in full git history, producing large numbers of false positives
- `scan_commits` now loads `AysalScanignore` patterns for its own target instead of
  inheriting stale ignore-pattern state left over from a previous scan in the same
  process — a thread-local cache leak that could cause legitimate findings to be
  silently skipped

---

## [0.1.0] — 2026-06-18

### Added
- Initial release
- Regex-based detection for 17 secret types
- Shannon entropy analysis for high-entropy string detection
- Git history, staged changes, and commit scanning
- Deduplication — same secret in N commits reported once with all locations
- Blast radius engine — 13 provider-specific checkers running concurrently
- AWS IAM check via `sts:GetCallerIdentity`
- GitHub token scope and repo access check
- OpenAI key validation
- Stripe live key balance check
- Slack bot token `auth.test` check
- Slack webhook probe
- Twilio account status check
- SendGrid scope list
- npm `whoami` check
- PyPI token check
- Heroku account check
- Google API key probe
- JWT decode and expiry check
- Generic high-entropy fallback checker
- Terminal reporter with Rich formatting
- JSON reporter for CI pipelines
- HTML report for GitHub Actions artifacts
- GitHub Action (`action.yml`) with Docker support
- Interactive UI mode (`aysal-scan ui`) powered by questionary
- GitHub URL auto-clone — scan any public repo directly
- `AysalScanignore` support (same syntax as `.gitignore`)
- Pre-commit hook support
- Exit code 1 on CRITICAL or HIGH findings (CI/CD compatible)
- `--no-fail`, `--no-blast-radius`, `--min-severity` flags

---

[Unreleased]: https://github.com/Rolex-1905/aysal-scan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Rolex-1905/aysal-scan/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/Rolex-1905/aysal-scan/releases/tag/v0.1.0