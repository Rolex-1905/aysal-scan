# Contributing to Aysal-Scan

Thank you for helping! This project is security tooling, so correctness and honesty matter more
than feature count.

## Setup

```bash
git clone https://github.com/Rolex-1905/aysal-scan.git
cd aysal-scan
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1      Linux/macOS: source .venv/bin/activate
pip install -e ".[dev,ui]"
pytest            # must pass; coverage gate is 80%
```

## Ground rules

1. **Every bug fix ships with a regression test** that fails without the fix.
2. **Never fail open.** A scan that cannot run exits `2`; a check that cannot verify returns
   `is_active=None`, never `True`.
3. **Only an HTTP 200 means "active".** Use `BaseChecker.classify_status` in every checker.
4. **Escape untrusted text** (`rich.markup.escape`, `html.escape`) before it reaches any output.
5. **Verification is read-only** and goes only to the provider the secret's format identifies.
6. **Test fixtures must not be real credentials.** Build realistic-looking ones at runtime
   (`"sk_live_" + "a1B2c3D4" * 3`) so GitHub push protection does not block the push.
7. Do not claim anything in the README that a test does not demonstrate.

## Adding a detector

1. Add a `SecretType` in `models.py` and a rule in `scanner/patterns.py` (anchor prefixes with
   boundaries; add a `validator`/`min_entropy` if the format is loose).
2. Add provider-specific guidance in `remediation.py`.
3. If the provider has a safe read-only endpoint, add a checker in `blast_radius/` built on
   `classify_status`, register it in `blast_radius/__init__.py`, and test 200 / 401 / 403 / 429 / 5xx.
4. Add cases to `tests/test_scanner_v2.py` and, for benchmark coverage, `benchmarks/corpus.py`.

## Commit style

`feat:`, `fix:`, `docs:`, `test:`, `chore:` — with a short imperative summary.

## Releases

Bump `version` in `pyproject.toml`, update `CHANGELOG.md`, tag `v<version>` (it **must** match;
the publish workflows refuse otherwise). PyPI versions are immutable — never reuse one.
