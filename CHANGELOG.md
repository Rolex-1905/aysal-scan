# Changelog

All notable changes to Aysal-Scan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- SARIF 2.1.0 output format for GitHub Security tab integration (`--report sarif`)
- `--output-json` and `--output-sarif` flags — produce multiple report formats in a single scan
- GCP Service Account JSON detection (CRITICAL severity, auto-detected by JSON structure)
- Azure Client Secret detection (HIGH severity, context-aware pattern)
- Stripe test key detection — `sk_test_` (LOW) and `pk_test_` (INFO)
- Retry with exponential backoff on blast radius HTTP calls (handles 429, 5xx, timeouts)
- `tests/conftest.py` — shared pytest fixtures for fake git repos, secret content, and mock HTTP responses
- Coverage gate — CI fails if coverage drops below 70%
- `CONTRIBUTING.md` — full contributor guide including how to add new secret types
- GitHub issue templates for bug reports and feature requests
- `GCPServiceAccountChecker` blast radius checker
- `AzureChecker` blast radius checker

### Changed
- `questionary` moved to optional dependency — install with `pip install aysal-scan[ui]`
- `__version__` now reads from package metadata via `importlib.metadata` — `pyproject.toml` is the single source of truth
- `entrypoint.sh` rewritten — single scan pass produces HTML + JSON + SARIF simultaneously (was two separate scans)
- CI workflow split into two jobs — `test` (pytest + coverage) and `secret-scan` (self-scan)
- `BaseChecker` extended with `check_with_retry()` — all blast radius checks use it automatically

### Fixed
- `yourusername` placeholder replaced with `Rolex-1905` in README and action.yml
- Copyright year corrected to 2026
- Duplicate `run_blast_radius` function removed from `blast_radius/__init__.py`
- `test_scan_commits_finds_secret` missing `self` parameter in `TestScanCommits`

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

[Unreleased]: https://github.com/Rolex-1905/aysal-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Rolex-1905/aysal-scan/releases/tag/v0.1.0