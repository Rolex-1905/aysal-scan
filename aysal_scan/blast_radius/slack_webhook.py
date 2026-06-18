"""Slack Webhook URL blast radius checker."""
from __future__ import annotations

import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class SlackWebhookChecker(BaseChecker):
    """
    We do NOT send a test message — that would visibly spam the user's Slack.
    Instead we send a payload that Slack rejects with a known error code
    if the webhook is invalid, without ever posting to the channel.
    """

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            # Send empty JSON — valid webhooks return "no_text" error (not "invalid_webhook")
            resp = httpx.post(
                secret_value,
                json={},
                timeout=self.TIMEOUT,
            )

            body = resp.text.strip()

            if resp.status_code == 404 or body in ("invalid_webhook", "no_webhook"):
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Slack webhook URL is invalid or has been revoked.",
                    remediation="Remove from git history.",
                )

            # "no_text" = webhook is valid, we just didn't provide a message
            if body == "no_text" or resp.status_code == 400:
                return BlastRadiusResult(
                    is_active=True,
                    check_performed=True,
                    risk_summary=(
                        "ACTIVE Slack webhook URL. Anyone with this URL can post "
                        "messages to the associated Slack channel silently."
                    ),
                    remediation=(
                        "1. Go to api.slack.com/apps → your app → Incoming Webhooks\n"
                        "2. Revoke this webhook URL immediately\n"
                        "3. Remove from git history with: git filter-repo"
                    ),
                )

            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=f"Unexpected response: HTTP {resp.status_code} — {body[:100]}",
                risk_summary="Could not determine webhook status. Treat as active.",
                remediation="Manually revoke at api.slack.com/apps.",
            )

        except Exception as exc:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(exc),
                risk_summary="Could not verify webhook. Treat as active.",
                remediation="Manually revoke at api.slack.com/apps.",
            )