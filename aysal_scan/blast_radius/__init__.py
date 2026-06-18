"""
blast_radius/__init__.py — dispatcher that routes each Finding to its
provider-specific checker and runs all checks concurrently.
"""
from __future__ import annotations

import concurrent.futures

from aysal_scan.models import BlastRadiusResult, Finding, SecretType, Severity
from aysal_scan.blast_radius.aws import AWSChecker
from aysal_scan.blast_radius.github import GitHubChecker
from aysal_scan.blast_radius.openai_checker import OpenAIChecker
from aysal_scan.blast_radius.stripe import StripeChecker
from aysal_scan.blast_radius.npm import NpmChecker
from aysal_scan.blast_radius.sendgrid import SendGridChecker
from aysal_scan.blast_radius.slack import SlackChecker
from aysal_scan.blast_radius.twilio import TwilioChecker
from aysal_scan.blast_radius.pypi import PyPIChecker
from aysal_scan.blast_radius.heroku import HerokuChecker
from aysal_scan.blast_radius.generic import GenericChecker
from aysal_scan.blast_radius.jwt_checker import JWTChecker
from aysal_scan.blast_radius.google import GoogleChecker
from aysal_scan.blast_radius.slack_webhook import SlackWebhookChecker
from aysal_scan.blast_radius.gcp import GCPServiceAccountChecker
from aysal_scan.blast_radius.azure import AzureChecker

# Every named SecretType maps to a dedicated checker
_CHECKERS = {
    SecretType.AWS_ACCESS_KEY: AWSChecker(),
    SecretType.GITHUB_TOKEN: GitHubChecker(),
    SecretType.OPENAI_KEY: OpenAIChecker(),
    SecretType.STRIPE_SECRET: StripeChecker(),
    SecretType.NPM_TOKEN: NpmChecker(),
    SecretType.SENDGRID: SendGridChecker(),
    SecretType.SLACK_BOT: SlackChecker(),
    SecretType.SLACK_WEBHOOK: SlackWebhookChecker(),
    SecretType.TWILIO: TwilioChecker(),
    SecretType.PYPI_TOKEN: PyPIChecker(),
    SecretType.HEROKU: HerokuChecker(),
    SecretType.JWT: JWTChecker(),
    SecretType.GOOGLE_API: GoogleChecker(),
    SecretType.GCP_SERVICE_ACCOUNT: GCPServiceAccountChecker(),
    SecretType.STRIPE_TEST_SECRET: StripeChecker(),
    SecretType.STRIPE_TEST_PUBLISHABLE: StripeChecker(),
    SecretType.AZURE_CLIENT_SECRET: AzureChecker(),
}

_GENERIC = GenericChecker()


def _get_checker(finding: Finding):
    return _CHECKERS.get(finding.secret_type, _GENERIC)


def run_blast_radius(finding: Finding, raw_value: str) -> Finding:
    checker = _get_checker(finding)

    result = checker.check_with_retry(raw_value)

    # Upgrade severity when key is confirmed active
    updated_severity = finding.severity
    if result.is_active is True:
        if finding.severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO):
            updated_severity = Severity.HIGH

    return finding.model_copy(
        update={"severity": updated_severity, "blast_radius": result}
    )


def run_blast_radius_concurrent(
    findings: list[Finding],
    raw_values: dict[str, str],
    max_workers: int = 6,
) -> list[Finding]:
    if not findings:
        return findings

    def _check_one(f: Finding) -> Finding:
        return run_blast_radius(f, raw_values.get(f.id, ""))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        return list(ex.map(_check_one, findings))