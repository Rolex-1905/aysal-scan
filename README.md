# 🔐 Aysal-Scan

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.1-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?style=flat-square&logo=github-actions&logoColor=white" />
</p>

<p align="center">
  <a href="https://www.linkedin.com/in/neeraj-mudunuru-79130a29a/">
    <img src="https://img.shields.io/badge/Author-Neeraj%20Mudunuru-0A66C2?style=flat-square&logo=linkedin&logoColor=white" />
  </a>
</p>

<p align="center">
  <b>Detect leaked secrets in your git repos — and find out exactly what damage they can cause.</b>
</p>

<p align="center">
  Every other tool tells you <b>"you have a leaked key."</b><br/>
  Aysal-Scan tells you <b>"you have a leaked AWS key — it has AdministratorAccess on your production account. Here's how to fix it."</b>
</p>

---

## The Difference

| Feature | TruffleHog / GitLeaks | **Aysal-Scan** |
|:---|:---:|:---:|
| Regex-based detection | ✅ | ✅ |
| Shannon entropy analysis | ✅ | ✅ |
| Git history scanning | ✅ | ✅ |
| **Is the key still active?** | ❌ | ✅ |
| **What permissions does it have?** | ❌ | ✅ |
| **Plain English remediation** | ❌ | ✅ |
| **Severity score with blast radius** | ❌ | ✅ |
| **Scan any GitHub URL directly** | ❌ | ✅ |
| **Interactive UI mode** | ❌ | ✅ |

---

## Real-World Demo

Scanning a test repo with a live canary AWS key:

```
aysal-scan scan https://github.com/trufflesecurity/test_keys
```

```
╭─────────────────────────── 🔴 [CRITICAL] AWS Access Key ────────────────────────────╮
│   File    :  new_key (line 2)                                                        │
│   Secret  :  AKIA************ZAM2                                                    │
│                                                                                      │
│   Blast Radius:                                                                      │
│     Key status  : ACTIVE                                                             │
│     Account     : Account: 052310077262 | User: canarytokens.com@@c20nnjzl...        │
│     Permission  : Could not enumerate — insufficient IAM permissions                 │
│                                                                                      │
│   Fix: 1. Go to AWS IAM Console → Users → Security Credentials                      │
│        2. Deactivate this access key immediately                                     │
│        3. Rotate + store in AWS Secrets Manager                                      │
│        4. Remove from git history with: git filter-repo                              │
╰──────────────────────────────────────────────────────────────────────────────────────╯

✗ FAILED — secrets detected  |  Exit code: 1
```

> The blast radius engine called `sts:GetCallerIdentity` against live AWS, confirmed the key is **active**, retrieved the **real account ID**, and escalated severity to CRITICAL — all automatically.

---

## Install

```bash
pip install aysal-scan
```

Or from source:

```bash
git clone https://github.com/Rolex-1905/aysal-scan
cd aysal-scan
pip install -e .
```

Requires Python 3.11+

---

## Quick Start

```bash
# Scan current directory
aysal-scan scan .

# Interactive mode — guided, no flags needed
aysal-scan ui
```

---

## All Commands

```bash
# ── Scan targets ────────────────────────────────────────────────────────────
aysal-scan scan .                                      # current directory
aysal-scan scan /path/to/repo                          # specific path
aysal-scan scan secrets.env                            # single file
aysal-scan scan https://github.com/username/repo       # GitHub URL (auto-clones)

# ── Git modes ───────────────────────────────────────────────────────────────
aysal-scan scan --staged                               # staged changes only
aysal-scan scan --commits 20                           # last 20 commits
aysal-scan scan --full-history                         # entire git history

# ── Output formats ──────────────────────────────────────────────────────────
aysal-scan scan . --report json                        # JSON (for CI pipelines)
aysal-scan scan . --report html --output report.html   # HTML report

# ── Filters & options ───────────────────────────────────────────────────────
aysal-scan scan . --min-severity HIGH                  # HIGH and CRITICAL only
aysal-scan scan . --no-blast-radius                    # skip API checks (offline)
aysal-scan scan . --no-fail                            # always exit 0
aysal-scan scan . --allow-list <id1>,<id2>             # suppress known findings by ID
aysal-scan scan . --verbose                            # show detailed blast radius debug output
aysal-scan scan . --report sarif --sarif-baseline old.sarif  # only alert on genuinely new findings
```

---

## Supported Providers & Blast Radius Checks

| Secret Type | Detection | Blast Radius Check |
|:---|:---:|:---|
| AWS Access Key | Regex | `sts:GetCallerIdentity` → IAM policy list |
| GitHub Token (PAT / OAuth) | Regex | `/user` → scopes → repo access |
| OpenAI API Key | Regex | `/v1/models` → billing exposure |
| Stripe Secret Key | Regex | `/v1/balance` → live account access |
| Stripe Publishable Key | Regex | Auto LOW |
| Twilio Account SID | Regex | `/Accounts/{SID}` → status check |
| SendGrid API Key | Regex | `/v3/scopes` → permission list |
| Slack Bot Token | Regex | `auth.test` → workspace + permissions |
| Slack Webhook URL | Regex | Probe → active/inactive check |
| npm Token | Regex | `registry.npmjs.org/-/whoami` |
| PyPI Token | Regex | Manual review (no safe verify endpoint) |
| GCP Service Account JSON | JSON structure | Auto CRITICAL (project ID + client email parsed) |
| Azure Client Secret | Context-aware regex | Manual review (tenant ID required to verify) |
| Heroku API Key | Regex | `/account` → email + app access |
| Google API Key | Regex | Probe enabled APIs |
| JWT Token | Regex | Decode header + expiry check |
| Private Key (RSA / EC / SSH) | Regex | Auto CRITICAL |
| Database URL (Postgres, MySQL, Redis, MongoDB) | Regex | Auto HIGH |
| High Entropy String | Shannon entropy > 4.5 | Flagged for manual review |

---

## Severity Levels

| Level | Meaning | Exit Code |
|:---|:---|:---:|
| 🔴 **CRITICAL** | Key is active + has admin/write access | `1` |
| 🟠 **HIGH** | Key is active + significant read access | `1` |
| 🟡 **MEDIUM** | Key appears valid but check failed or timed out | `0` |
| 🔵 **LOW** | Test/publishable key — limited exposure | `0` |
| ⚪ **INFO** | Likely a secret, unconfirmed | `0` |

Exit code `1` on any CRITICAL or HIGH finding. Override with `--no-fail`.

---

## GitHub Actions

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0

  - name: Aysal-Scan Secret Scan
    uses: Rolex-1905/aysal-scan@v1.0.0
    with:
      path: '.'
      min-severity: 'HIGH'
      no-blast-radius: 'false'
      fail-on-findings: 'true'

  - name: Upload HTML Report
    uses: actions/upload-artifact@v4
    if: always()
    with:
      name: aysal-scan-report
      path: aysal-scan-report.html
      retention-days: 30

  - name: Upload SARIF to GitHub Security tab
    uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: aysal-scan-results.sarif
      category: aysal-scan
```

---

## Pre-commit Hook

**Recommended — remote repo mode** (auto-installs, always up to date):

```yaml
repos:
  - repo: https://github.com/Rolex-1905/aysal-scan
    rev: v1.0.0
    hooks:
      - id: aysal-scan               # fast — no API calls, offline safe
```

**With blast radius checks** (slower — calls provider APIs):

```yaml
repos:
  - repo: https://github.com/Rolex-1905/aysal-scan
    rev: v1.0.0
    hooks:
      - id: aysal-scan-with-blast-radius
```

**Local mode** (if you have aysal-scan already installed):

```yaml
repos:
  - repo: local
    hooks:
      - id: aysal-scan
        name: Aysal-Scan — secret detection
        entry: aysal-scan scan --staged --no-blast-radius
        language: system
        pass_filenames: false
```

Install pre-commit and activate:

```bash
pip install pre-commit
pre-commit install
```

---

## Ignoring Files

Aysal-Scan automatically skips `node_modules/`, `.git/`, `dist/`, `build/`,
`*.min.js`, lock files, and binary files.

For custom rules, create an `AysalScanignore` file in your repo root
(same syntax as `.gitignore`):

```gitignore
# Ignore test fixtures with intentional fake keys
tests/test_cli.py
tests/test_patterns.py

# Ignore example config files
*.example
*.sample
config.example.env
```

---

## How Blast Radius Works

When a secret is detected, Aysal-Scan calls the provider's API using
**read-only operations only** to answer three questions:

1. **Is this key still active?**
2. **What can it access?**
3. **How bad is it if someone already has it?**

All checks run concurrently with a 10-second timeout per provider.
A failed or timed-out check degrades gracefully to **MEDIUM** rather than
crashing the scan. The raw secret is never stored — only the masked value
(`AKIA****XMPL`) appears in any output or report.

---

## Project Structure

```
aysal_scan/
├── cli.py                    # Typer CLI + interactive UI
├── models.py                 # Pydantic models (Finding, ScanReport, etc.)
├── scanner/
│   ├── patterns.py           # Regex patterns for 17+ secret types
│   ├── entropy.py            # Shannon entropy analysis
│   ├── file_scanner.py       # File + directory scanning
│   ├── git_utils.py          # Git history, staged, commit scanning
│   └── deduplicator.py       # Deduplicate across commits
├── blast_radius/
│   ├── aws.py                # AWS IAM checks via STS (user, group, inline policies)
│   ├── github.py             # GitHub API scope check
│   ├── openai_checker.py     # OpenAI key validation
│   ├── stripe.py             # Stripe balance check
│   ├── slack.py              # Slack auth.test
│   ├── slack_webhook.py      # Slack webhook probe
│   ├── twilio.py             # Twilio account check
│   ├── sendgrid.py           # SendGrid scope list
│   ├── npm.py                # npm whoami
│   ├── pypi.py                # PyPI — flags for manual review (no safe verify endpoint)
│   ├── heroku.py             # Heroku account check
│   ├── google.py             # Google API probe
│   ├── gcp.py                 # GCP Service Account JSON parsing
│   ├── azure.py                # Azure Client Secret — manual review
│   ├── jwt_checker.py        # JWT decode + expiry
│   ├── base.py                 # Retry/backoff wrapper shared by all checkers
│   └── generic.py            # Fallback for unknown types
└── reporter/
    ├── terminal.py           # Rich-formatted terminal output
    ├── json_report.py        # JSON output for CI
    ├── html_report.py        # Interactive HTML report (collapsible, filterable)
    └── sarif_report.py        # SARIF 2.1.0 for GitHub Security tab
```

---

## Tech Stack

Built with **Python 3.11+** ·
[Typer](https://typer.tiangolo.com/) ·
[Rich](https://github.com/Textualize/rich) ·
[Pydantic v2](https://docs.pydantic.dev/) ·
[httpx](https://www.python-httpx.org/) ·
[boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) ·
[GitPython](https://gitpython.readthedocs.io/)

---

## License

MIT © 2026 Aysal-Scan

---

<p align="center">
  Built by <a href="https://www.linkedin.com/in/neeraj-mudunuru-79130a29a/"><b>Neeraj Mudunuru</b></a>
</p>