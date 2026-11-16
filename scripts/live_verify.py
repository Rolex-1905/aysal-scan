#!/usr/bin/env python3
"""Check Aysal-Scan's provider verifiers against the REAL provider APIs.

Mocked tests prove the code follows my reading of each API; only a live call proves it matches
reality. Use this with YOUR OWN throwaway credentials only. Never test credentials you found
in someone else's repository: using them can be illegal.

Credentials are read from environment variables (never from files, never from arguments) and are
never printed. Typical flow:

    set AYSAL_LIVE_GITHUB=ghp_yourtoken            # PowerShell: $env:AYSAL_LIVE_GITHUB="ghp_..."
    python scripts/live_verify.py --expect active  # the token works  -> expect ACTIVE
    # ... now revoke the token at the provider ...
    python scripts/live_verify.py --expect revoked # same token, now dead -> expect REVOKED

See docs/LIVE_VERIFICATION.md for how to get a free throwaway credential for each provider.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Optional

from aysal_scan.blast_radius.anthropic_checker import AnthropicChecker
from aysal_scan.blast_radius.aws import AWSChecker
from aysal_scan.blast_radius.digitalocean import DigitalOceanChecker
from aysal_scan.blast_radius.github import GitHubChecker
from aysal_scan.blast_radius.gitlab import GitLabChecker
from aysal_scan.blast_radius.google import GoogleChecker
from aysal_scan.blast_radius.huggingface import HuggingFaceChecker
from aysal_scan.blast_radius.npm import NpmChecker
from aysal_scan.blast_radius.openai_checker import OpenAIChecker
from aysal_scan.blast_radius.sendgrid import SendGridChecker
from aysal_scan.blast_radius.slack import SlackChecker
from aysal_scan.blast_radius.stripe import StripeChecker
from aysal_scan.blast_radius.twilio import TwilioChecker
from aysal_scan.models import BlastRadiusResult

# name -> (environment variable, checker factory, value format, free to obtain?)
PROVIDERS: dict[str, tuple[str, Callable, str, str]] = {
    "github": ("AYSAL_LIVE_GITHUB", GitHubChecker, "personal access token", "free"),
    "gitlab": ("AYSAL_LIVE_GITLAB", GitLabChecker, "personal access token", "free"),
    "huggingface": ("AYSAL_LIVE_HUGGINGFACE", HuggingFaceChecker, "access token", "free"),
    "npm": ("AYSAL_LIVE_NPM", NpmChecker, "access token", "free"),
    "slack": ("AYSAL_LIVE_SLACK", SlackChecker, "bot token xoxb-...", "free"),
    "stripe": ("AYSAL_LIVE_STRIPE", StripeChecker, "TEST-mode secret key sk_test_...", "free (test mode)"),
    "sendgrid": ("AYSAL_LIVE_SENDGRID", SendGridChecker, "API key SG....", "free tier"),
    "twilio": ("AYSAL_LIVE_TWILIO", TwilioChecker, "ACCOUNT_SID:AUTH_TOKEN", "free trial"),
    "aws": ("AYSAL_LIVE_AWS", AWSChecker, "ACCESS_KEY_ID:SECRET_ACCESS_KEY", "free via a canarytoken"),
    "google": ("AYSAL_LIVE_GOOGLE", GoogleChecker, "API key AIza...", "free (no billing needed for YouTube Data API)"),
    "anthropic": ("AYSAL_LIVE_ANTHROPIC", AnthropicChecker, "API key sk-ant-...", "paid (prepaid credit)"),
    "openai": ("AYSAL_LIVE_OPENAI", OpenAIChecker, "API key sk-...", "paid (prepaid credit)"),
    "digitalocean": ("AYSAL_LIVE_DIGITALOCEAN", DigitalOceanChecker, "API token dop_v1_...", "needs a payment card"),
}


def status_of(result: BlastRadiusResult) -> str:
    if result.check_performed and result.is_active is True:
        return "ACTIVE"
    if result.check_performed and result.is_active is False:
        return "REVOKED"
    return "UNVERIFIED"


def run_one(name: str, secret: str) -> BlastRadiusResult:
    _env, factory, _fmt, _cost = PROVIDERS[name]
    return factory().check_with_retry(secret)


def format_line(name: str, result: BlastRadiusResult, verdict: str = "") -> str:
    """One report line. Deliberately contains no part of the credential."""
    parts = [f"{name:<12}", f"{status_of(result):<10}"]
    parts.append(f"privilege={result.privilege or '-'}")
    if result.account_info:
        parts.append(f"account={result.account_info}")
    if result.check_error:
        parts.append(f"error={result.check_error}")
    if verdict:
        parts.append(verdict)
    return "  ".join(parts)


def main(argv: Optional[list[str]] = None, environ: Optional[dict] = None) -> int:
    env = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description="Verify Aysal-Scan checkers against real provider APIs.")
    ap.add_argument("--expect", choices=["any", "active", "revoked"], default="any",
                    help="fail (exit 1) unless every tested credential has this status")
    ap.add_argument("--only", help="comma-separated provider names to test")
    ap.add_argument("--list", action="store_true", help="list providers and the environment variables they read")
    args = ap.parse_args(argv)

    if args.list:
        for name, (var, _f, fmt, cost) in PROVIDERS.items():
            print(f"{name:<12} {var:<26} {fmt:<36} {cost}")
        return 0

    wanted = [n.strip() for n in args.only.split(",")] if args.only else list(PROVIDERS)
    unknown = [n for n in wanted if n not in PROVIDERS]
    if unknown:
        print(f"Unknown provider(s): {', '.join(unknown)}. Use --list.", file=sys.stderr)
        return 2

    tested = mismatches = 0
    for name in wanted:
        var = PROVIDERS[name][0]
        secret = env.get(var, "").strip()
        if not secret:
            continue
        tested += 1
        result = run_one(name, secret)
        verdict = ""
        if args.expect != "any":
            ok = status_of(result) == args.expect.upper()
            verdict = "OK" if ok else f"MISMATCH (expected {args.expect.upper()})"
            mismatches += 0 if ok else 1
        print(format_line(name, result, verdict))

    if tested == 0:
        print("No credentials found. Set one of the AYSAL_LIVE_* variables (see --list).", file=sys.stderr)
        return 2
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
