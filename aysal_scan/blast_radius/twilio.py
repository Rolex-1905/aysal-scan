import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class TwilioChecker(BaseChecker):

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
            if resp.status_code == 401:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Twilio credentials are invalid or revoked.",
                    remediation="Remove from git history.",
                )
            data = resp.json()
            status = data.get("status", "unknown")
            friendly_name = data.get("friendly_name", "unknown")
            return BlastRadiusResult(
                is_active=status == "active",
                check_performed=True,
                account_info=f"Account: {friendly_name} | Status: {status}",
                permissions=["Full account access — SMS, calls, phone numbers"],
                risk_summary=(
                    f"ACTIVE Twilio account '{friendly_name}'. "
                    "Can send SMS/calls billed to your account."
                ),
                remediation=(
                    "1. Go to console.twilio.com → Account → Auth Tokens\n"
                    "2. Rotate your Auth Token immediately\n"
                    "3. Check usage logs for unauthorized activity\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify. Treat as active.",
                remediation="Manually check at console.twilio.com.",
            )