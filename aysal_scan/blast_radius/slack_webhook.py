"""Slack Webhook URL checker."""
from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult

_ALLOWED_PREFIX = "https://hooks.slack.com/services/"


class SlackWebhookChecker(BaseChecker):
    """Never posts a visible message: an empty JSON body makes a live webhook answer
    ``no_text`` (HTTP 400) without delivering anything. The URL host is verified so this
    checker can only ever contact hooks.slack.com."""

    PROVIDER = "Slack webhook"

    def check(self, secret_value: str) -> BlastRadiusResult:
        if not secret_value.startswith(_ALLOWED_PREFIX):
            return BlastRadiusResult(
                is_active=None, check_performed=False,
                risk_summary="Webhook URL is not a hooks.slack.com URL; not contacted.",
            )
        try:
            resp = httpx.post(secret_value, json={}, timeout=self.TIMEOUT)
            status = self.status_of(resp)
            body = (getattr(resp, "text", "") or "").strip()

            if status in (404, 410) or body in ("invalid_webhook", "no_webhook", "no_service"):
                return BlastRadiusResult(
                    is_active=False, check_performed=True,
                    risk_summary="Slack webhook URL is invalid or has been revoked.",
                    remediation="Remove from git history.",
                )
            if body == "no_text" or status == 400:
                return BlastRadiusResult(
                    is_active=True, check_performed=True,
                    risk_summary=(
                        "ACTIVE Slack webhook URL. Anyone with this URL can post "
                        "messages to the associated Slack channel silently (phishing risk)."
                    ),
                    privilege="write",
                )
            return BlastRadiusResult(
                is_active=None, check_performed=True,
                check_error=f"Unexpected response: HTTP {status} — {body[:100]}",
                risk_summary="Could not determine webhook status. Treat as active.",
                remediation="Manually revoke at api.slack.com/apps.",
            )
        except Exception as exc:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(exc),
                risk_summary="Could not verify webhook. Treat as active.",
                remediation="Manually revoke at api.slack.com/apps.",
            )
