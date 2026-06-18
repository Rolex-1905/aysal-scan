"""Heroku API key blast radius checker."""
from __future__ import annotations

import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class HerokuChecker(BaseChecker):
    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.heroku.com/account",
                headers={
                    "Authorization": f"Bearer {secret_value}",
                    "Accept": "application/vnd.heroku+json; version=3",
                },
                timeout=self.TIMEOUT,
            )

            if resp.status_code == 401:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Heroku API key is revoked or invalid.",
                    remediation="No immediate action required — key is inactive.",
                )

            if resp.status_code == 200:
                data = resp.json()
                email = data.get("email", "unknown")
                name = data.get("name", "")
                return BlastRadiusResult(
                    is_active=True,
                    check_performed=True,
                    account_info=f"{email} ({name})",
                    permissions=["account:read", "apps:manage"],
                    risk_summary=(
                        f"Active Heroku API key. Account: {email}. "
                        "Can manage all Heroku apps, dynos, add-ons, and config vars."
                    ),
                    remediation=(
                        "Revoke at https://dashboard.heroku.com/account/applications "
                        "then rotate all Heroku app config vars."
                    ),
                )

            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=f"Unexpected HTTP {resp.status_code}",
                risk_summary="Could not determine key status.",
                remediation="Manually verify and revoke at Heroku dashboard.",
            )

        except Exception as exc:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(exc),
                risk_summary="Blast radius check failed — treat key as active.",
                remediation="Manually verify and revoke at Heroku dashboard.",
            )