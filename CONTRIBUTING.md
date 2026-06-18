# Contributing to Aysal-Scan

Thank you for your interest in contributing. This document covers everything
you need to get started.

---

## Dev setup

```bash
git clone https://github.com/Rolex-1905/aysal-scan
cd aysal-scan
pip install -e ".[dev,ui]"
```

Requires Python 3.11+.

---

## Running tests

```bash
# Full test suite with coverage
pytest

# Skip slow git integration tests
pytest -m "not slow"

# Single file
pytest tests/test_patterns.py -v
```

Coverage must stay above 70% or CI will block the PR.

---

## Project structure
aysal_scan/
```

├── cli.py               # Typer CLI entry point
├── models.py            # Pydantic models — Finding, ScanReport etc.
├── scanner/
│   ├── patterns.py      # Regex patterns — add new secret types here
│   ├── entropy.py       # Shannon entropy analysis
│   ├── file_scanner.py  # File + directory scanning
│   ├── git_utils.py     # Git history, staged, commit scanning
│   └── deduplicator.py  # Deduplicate findings across commits
├── blast_radius/
│   ├── base.py          # BaseChecker — extend this for new providers
│   ├── init.py          # Dispatcher + concurrent runner
│   └── *.py             # One file per provider
└── reporter/
    ├── terminal.py      # Rich terminal output
    ├── json_report.py   # JSON output
    ├── html_report.py   # HTML report
    └── sarif_report.py  # SARIF for GitHub Security tab
```
---

## Adding a new secret type

1. Add the type to `SecretType` enum in `models.py`
2. Add a `SecretPattern` entry in `scanner/patterns.py`
3. Create `blast_radius/yourprovider.py` extending `BaseChecker`
4. Register it in `blast_radius/__init__.py`
5. Add detection test in `tests/test_patterns.py`
6. Add blast radius test in `tests/test_blast_radius.py`

Follow the existing checkers (e.g. `github.py`) as a template.
All blast radius checks must be **read-only** — never modify anything.

---

## Adding a new output format

1. Create `reporter/yourformat_report.py`
2. Wire it into the `_run_scan` block in `cli.py`
3. Add `--report yourformat` to the help text

---

## Pull request checklist

- [ ] Tests pass locally (`pytest`)
- [ ] Coverage did not drop below 70%
- [ ] New secret type has both a pattern test and a blast radius test
- [ ] Blast radius checker never raises exceptions (catch everything)
- [ ] Raw secret values are never stored or logged — masked only
- [ ] `AysalScanignore` updated if your changes introduce false positives

---

## Commit style
feat: add Azure client secret detection

fix: retry backoff on GitHub 429 responses

test: add GCP service account fixtures

docs: update CONTRIBUTING with new provider guide

---

## Reporting a bug

Use the bug report template — `.github/ISSUE_TEMPLATE/bug_report.md`.
Include your Python version, OS, and the command you ran.
**Never include real secrets in bug reports.**

---

## Suggesting a new secret type

Use the feature request template and include:
- The provider name
- The regex pattern (if you know it)
- What the blast radius check would call

---

## License

By contributing you agree your changes will be released under the MIT license.