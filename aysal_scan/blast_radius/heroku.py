"""Heroku API key checker."""
from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class HerokuChecker(BaseChecker):
    PROVIDER = "Heroku"

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
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early

            data = self.json_or_empty(resp)
            email = data.get("email", "unknown")
            name = data.get("name", "")
            return BlastRadiusResult(
                is_active=True, check_performed=True,
                account_info=f"{email} ({name})",
                permissions=["account:read", "apps:manage"],
                risk_summary=(
                    f"Active Heroku API key. Account: {email}. "
                    "Can manage all Heroku apps, dynos, add-ons, and config vars."
                ),
                privilege="admin",
            )
        except Exception as exc:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(exc),
                risk_summary="Blast radius check failed — treat key as active.",
                remediation="Manually verify and revoke at Heroku dashboard.",
            )
