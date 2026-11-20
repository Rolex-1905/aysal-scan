# Testing the verifiers against real APIs (free)

Mocked unit tests show the checkers follow our reading of each provider's API. Only a **live call**
shows they match reality. `scripts/live_verify.py` makes that call for credentials **you** own.

> **Only test credentials you created yourself.** Never use a credential found in someone else's
> repository, a leak dump or a client's code: using it can be unlawful even if the call is read-only.

## How it works

1. Create a throwaway credential at the provider (table below; all of these are free).
2. Put it in an environment variable. It is never written to disk, passed as an argument or printed.
3. Run the script once while the credential is valid, then revoke it and run again.

```powershell
$env:AYSAL_LIVE_GITHUB = "ghp_..."            # your own throwaway token
python scripts/live_verify.py --expect active  # expect: github  ACTIVE   privilege=...
# revoke the token on github.com/settings/tokens, then:
python scripts/live_verify.py --expect revoked # expect: github  REVOKED
Remove-Item Env:AYSAL_LIVE_GITHUB
```

`--expect` makes the script exit 1 on a mismatch, so a wrong verdict cannot go unnoticed.
`python scripts/live_verify.py --list` prints every provider and variable.

## Free throwaway credentials

| Provider | Variable | How to get one (free) | Notes |
|---|---|---|---|
| GitHub | `AYSAL_LIVE_GITHUB` | Settings → Developer settings → Personal access tokens | Create one with **no scopes** first, then one with `repo`, to see privilege change |
| GitLab | `AYSAL_LIVE_GITLAB` | User settings → Access tokens (scope `read_api`) | |
| Hugging Face | `AYSAL_LIVE_HUGGINGFACE` | Settings → Access Tokens (a *read* token) | Also try a *write* token |
| npm | `AYSAL_LIVE_NPM` | Account → Access Tokens | |
| Slack | `AYSAL_LIVE_SLACK` | Create a free workspace, a Slack app, install it, copy the bot token | |
| Stripe | `AYSAL_LIVE_STRIPE` | Dashboard in **test mode** → Developers → API keys (`sk_test_...`) | Test keys cannot move real money |
| SendGrid | `AYSAL_LIVE_SENDGRID` | Free plan → Settings → API Keys | Sign-up may require approval |
| Twilio | `AYSAL_LIVE_TWILIO` | Free trial account; value is `ACCOUNT_SID:AUTH_TOKEN` | Trial needs phone verification |
| AWS | `AYSAL_LIVE_AWS` | Generate an AWS **canarytoken** at canarytokens.org; value is `ACCESS_KEY_ID:SECRET` | Free, needs no AWS account. Using it alerts *you*, which is the point |
| Google | `AYSAL_LIVE_GOOGLE` | Google Cloud project → APIs & Services → Credentials → API key; enable *YouTube Data API v3* | I believe no billing is needed for that API; verify when you create it |

**Not free** (skip unless you already have them): Anthropic and OpenAI need prepaid credit; DigitalOcean
requires a payment card. Their checkers are covered by mocked tests only, and the README says so.

## What to look for

* A valid credential must report `ACTIVE`; a revoked one `REVOKED` — never `UNVERIFIED` for either.
* `privilege=` should match what you granted (for example a no-scope GitHub token should not say `admin`).
* Anything unexpected is a real bug: open an issue with the **provider name and the status line only**
  (the line never contains the credential).
