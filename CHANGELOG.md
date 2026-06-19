# Changelog

All notable changes to Aysal-Scan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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