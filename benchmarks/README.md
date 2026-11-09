# Benchmarks

```bash
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
* The Gitleaks and TruffleHog adapters follow their documented JSON formats but have not been
  exercised in this project's CI; check them against your installed versions.
* For a publishable evaluation: add real-world leak datasets, hold out cases that were not used while
  tuning, report confidence intervals, pin tool versions and rule sets, and measure time/memory.
