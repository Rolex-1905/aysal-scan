from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class SendGridChecker(BaseChecker):
    PROVIDER = "SendGrid"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early

            scopes = [s for s in self.json_or_empty(resp).get("scopes", []) if isinstance(s, str)]
            has_mail = any("mail" in s for s in scopes)
            has_full = any("admin" in s or "full" in s for s in scopes)
            risk = "ACTIVE SendGrid API key."
            if has_full:
                risk += " Has full account access including billing and subusers."
                privilege = "admin"
            elif has_mail:
                risk += " Can send emails on behalf of your domain — phishing risk."
                privilege = "write"
            else:
                privilege = "read"
            return BlastRadiusResult(
                is_active=True, check_performed=True, permissions=scopes[:10],
                risk_summary=risk, privilege=privilege,
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually revoke at app.sendgrid.com/settings/api_keys.",
            )
