"""
blast_radius dispatcher: routes each Finding to its provider checker, applies the evidence to
the finding's severity, and runs network checks concurrently with per-provider rate limiting.
"""
from __future__ import annotations

import concurrent.futures
import threading
import time
from typing import Callable, Optional

from aysal_scan.blast_radius.anthropic_checker import AnthropicChecker
from aysal_scan.blast_radius.aws import AWSChecker
from aysal_scan.blast_radius.azure import AzureChecker
from aysal_scan.blast_radius.digitalocean import DigitalOceanChecker
from aysal_scan.blast_radius.gcp import GCPServiceAccountChecker
from aysal_scan.blast_radius.generic import GenericChecker
from aysal_scan.blast_radius.github import GitHubChecker
from aysal_scan.blast_radius.gitlab import GitLabChecker
from aysal_scan.blast_radius.google import GoogleChecker
from aysal_scan.blast_radius.heroku import HerokuChecker
from aysal_scan.blast_radius.huggingface import HuggingFaceChecker
from aysal_scan.blast_radius.jwt_checker import JWTChecker
from aysal_scan.blast_radius.npm import NpmChecker
from aysal_scan.blast_radius.openai_checker import OpenAIChecker
from aysal_scan.blast_radius.pypi import PyPIChecker
from aysal_scan.blast_radius.sendgrid import SendGridChecker
from aysal_scan.blast_radius.slack import SlackChecker
from aysal_scan.blast_radius.slack_webhook import SlackWebhookChecker
from aysal_scan.blast_radius.stripe import StripeChecker
from aysal_scan.blast_radius.twilio import TwilioChecker
from aysal_scan.models import BlastRadiusResult, Finding, SecretType, Severity
from aysal_scan.remediation import remediation_for

_stripe = StripeChecker()
_slack = SlackChecker()

# Secret types whose verification makes a request to the provider's API.
_NETWORK_CHECKERS = {
    SecretType.AWS_ACCESS_KEY: AWSChecker(),
    SecretType.GITHUB_TOKEN: GitHubChecker(),
    SecretType.GITLAB_TOKEN: GitLabChecker(),
    SecretType.OPENAI_KEY: OpenAIChecker(),
    SecretType.ANTHROPIC_KEY: AnthropicChecker(),
    SecretType.HUGGINGFACE_TOKEN: HuggingFaceChecker(),
    SecretType.DIGITALOCEAN_TOKEN: DigitalOceanChecker(),
    SecretType.STRIPE_SECRET: _stripe,
    SecretType.STRIPE_RESTRICTED: _stripe,
    SecretType.STRIPE_TEST_SECRET: _stripe,
    SecretType.NPM_TOKEN: NpmChecker(),
    SecretType.SENDGRID: SendGridChecker(),
    SecretType.SLACK_BOT: _slack,
    SecretType.SLACK_TOKEN: _slack,
    SecretType.SLACK_WEBHOOK: SlackWebhookChecker(),
    SecretType.TWILIO: TwilioChecker(),
    SecretType.HEROKU: HerokuChecker(),
    SecretType.GOOGLE_API: GoogleChecker(),
}

# Checkers that never touch the network (decode / static analysis only).
_LOCAL_CHECKERS = {
    SecretType.PYPI_TOKEN: PyPIChecker(),
    SecretType.JWT: JWTChecker(),
    SecretType.GCP_SERVICE_ACCOUNT: GCPServiceAccountChecker(),
    SecretType.AZURE_CLIENT_SECRET: AzureChecker(),
}

_GENERIC = GenericChecker()

NETWORK_SECRET_TYPES = frozenset(_NETWORK_CHECKERS)


def _get_checker(finding: Finding):
    return (
        _NETWORK_CHECKERS.get(finding.secret_type)
        or _LOCAL_CHECKERS.get(finding.secret_type)
        or _GENERIC
    )


def needs_network(finding: Finding) -> bool:
    return finding.secret_type in NETWORK_SECRET_TYPES


# ---------------------------------------------------------------------------
# Evidence -> severity
# ---------------------------------------------------------------------------

def _resolve(finding: Finding, br: BlastRadiusResult) -> tuple[Severity, list[str]]:
    severity = finding.severity
    tags = list(finding.tags)

    def tag(t: str) -> None:
        if t not in tags:
            tags.append(t)

    if br.suggested_severity is not None:
        # A checker may only ever LOWER severity (expired JWT, public key, test-mode key).
        if br.suggested_severity.rank > severity.rank:
            severity = br.suggested_severity
        if br.is_active is False:
            tag("verified-revoked")
        elif br.is_active is None:
            tag("unverified")
    elif br.check_performed and br.is_active is False:
        tag("verified-revoked")
        if severity.rank < Severity.LOW.rank:
            severity = Severity.LOW          # a dead credential is no longer an emergency
    elif br.check_performed and br.is_active is True:
        tag("verified-active")
        if severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO):
            severity = Severity.HIGH         # a live credential is at least HIGH
        if br.privilege == "admin":
            severity = Severity.CRITICAL     # live + admin-level access
    else:
        tag("unverified")
    return severity, tags


def _finalize_remediation(finding: Finding, br: BlastRadiusResult, used_generic: bool) -> None:
    if used_generic or not br.remediation:
        br.remediation = remediation_for(finding.secret_type)


def run_blast_radius(finding: Finding, raw_value: str) -> Finding:
    """Verify one finding; returns an updated copy (the input is not mutated)."""
    checker = _get_checker(finding)
    result = checker.check_with_retry(raw_value)
    _finalize_remediation(finding, result, used_generic=checker is _GENERIC)
    severity, tags = _resolve(finding, result)
    return finding.model_copy(update={"blast_radius": result, "severity": severity, "tags": tags})


# ---------------------------------------------------------------------------
# Concurrent execution with per-provider throttling
# ---------------------------------------------------------------------------

class _Throttle:
    """Allow at most one request start per ``interval`` seconds *per provider*."""

    def __init__(self, interval: float):
        self.interval = interval
        self._next: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next.get(key, 0.0))
            self._next[key] = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


def run_blast_radius_concurrent(
    findings: list[Finding],
    raw_values: dict[str, str],
    max_workers: int = 4,
    interval: float = 0.25,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> list[Finding]:
    """Verify findings; order of the returned list matches the input.

    Findings that need no network call are resolved immediately. Network checks run in a
    thread pool, throttled per provider so one provider is never hammered.
    """
    results: list[Optional[Finding]] = [None] * len(findings)
    remote: list[int] = []
    done = 0
    total = len(findings)

    for i, f in enumerate(findings):
        if needs_network(f):
            remote.append(i)
        else:
            results[i] = run_blast_radius(f, raw_values.get(f.id, ""))
            done += 1
    if on_progress and done:
        on_progress(done, total)

    throttle = _Throttle(interval)

    def task(i: int) -> tuple[int, Finding]:
        f = findings[i]
        throttle.wait(type(_get_checker(f)).__name__)
        return i, run_blast_radius(f, raw_values.get(f.id, ""))

    if remote:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for i, updated in ex.map(task, remote):
                results[i] = updated
                done += 1
                if on_progress:
                    on_progress(done, total)

    return [r for r in results if r is not None]
