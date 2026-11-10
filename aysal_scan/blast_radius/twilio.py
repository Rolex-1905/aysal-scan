from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class TwilioChecker(BaseChecker):
    """``secret_value`` is ``"ACCOUNT_SID:AUTH_TOKEN"``; a lone SID cannot be verified."""

    PROVIDER = "Twilio"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            parts = secret_value.split(":")
            if len(parts) != 2:
                return BlastRadiusResult(
                    is_active=None,
                    check_performed=False,
                    risk_summary="Twilio Account SID found. Auth Token needed to verify. Manual review required.",
                    remediation=(
                        "1. Go to console.twilio.com\n"
                        "2. Check if this SID matches your account\n"
                        "3. Rotate your Auth Token immediately if so\n"
                        "4. Remove from git history with: git filter-repo"
                    ),
                )
            account_sid, auth_token = parts
            resp = httpx.get(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json",
                auth=(account_sid, auth_token),
                timeout=self.TIMEOUT,
            )
            early = self.classify_status(self.status_of(resp))
            if early is not None:
                return early

            data = self.json_or_empty(resp)
            status = str(data.get("status", "unknown"))
            friendly_name = str(data.get("friendly_name", "unknown"))
            if status != "active":
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    account_info=f"Account: {friendly_name} | Status: {status}",
                    risk_summary=f"Twilio credentials are valid but the account is '{status}', so it cannot be used.",
                )
            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"Account: {friendly_name} | Status: {status}",
                permissions=["Full account access — SMS, calls, phone numbers"],
                risk_summary=(
                    f"ACTIVE Twilio account '{friendly_name}'. "
                    "Can send SMS/calls billed to your account."
                ),
                privilege="admin",
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify. Treat as active.",
                remediation="Manually check at console.twilio.com.",
            )
