# Benchmarks

```bash
python benchmarks/run.py --corpus realistic --aysal aysal-scan --gitleaks gitleaks --trufflehog trufflehog
python benchmarks/run.py --aysal aysal-scan                        # this version
python benchmarks/run.py --aysal /path/to/v1/aysal-scan --aysal aysal-scan   # compare two versions
python benchmarks/run.py --aysal aysal-scan --gitleaks gitleaks --trufflehog trufflehog
```

`corpus.py` writes one file per case (33 files with one real-looking secret, 20 decoys such as
placeholders, code references, hashes and slugs). Scoring is **file-level**. Values are generated at
runtime from a fixed seed, are not real credentials, and are never sent anywhere.

## Read this before quoting any number
* The corpus is **synthetic and written by the tool's author, alongside the fixes it tests.** It is a
  regression guard. A perfect score on it means "the cases the author thought of pass", not
  "the scanner is accurate".
* The Gitleaks and TruffleHog adapters were exercised against Gitleaks 8.30.1 and TruffleHog 3.99.8
  (run with `--no-verification`). Re-check them if you use other versions.
* For a publishable evaluation: add real-world leak datasets, hold out cases that were not used while
  tuning, report confidence intervals, pin tool versions and rule sets, and measure time/memory.

## Two corpora

| Corpus | Values | Purpose |
|---|---|---|
| `synthetic` (default) | random strings shaped like credentials | regression guard for this project's own rules |
| `realistic` | structurally valid: real generated keys, markers, checksums (`pip install aysal-scan[bench]`) | fairer cross-tool comparison |

`synthetic` systematically penalises tools that validate format (key parsing, embedded markers,
checksums): on it TruffleHog 3.99.8 recalled 0.58, on `realistic` 0.86. Use `realistic` for any comparison.

## Snapshot (2026-11-12; Aysal-Scan 1.1.0.dev2, Gitleaks 8.30.1, TruffleHog 3.99.8 `--no-verification`)

`realistic` corpus, file level, 28 positives / 20 decoys:

| Tool | TP | FN | FP | Precision | Recall |
|---|---|---|---|---|---|
| Aysal-Scan | 28 | 0 | 0 | 1.00 | 1.00 |
| Gitleaks | 25 | 3 | 0 | 1.00 | 0.89 |
| TruffleHog | 24 | 4 | 0 | 1.00 | 0.86 |

What the misses are: Gitleaks' default config has no rule for database URLs or generic passwords;
TruffleHog missed an encrypted private key, a Google API key (a detector that normally relies on verification),
a PyPI token and a generic password. **This corpus was written alongside Aysal-Scan's rules**, so it favours
categories Aysal-Scan targets; it says nothing about the other tools' strengths (hundreds of provider
detectors, speed, verification). Do not present it as a ranking.
