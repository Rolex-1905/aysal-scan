import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class SendGridChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )
            if resp.status_code == 401:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="SendGrid key is invalid or revoked.",
                    remediation="Remove from git history.",
                )
            scopes = resp.json().get("scopes", [])
            has_mail = any("mail" in s for s in scopes)
            has_full = any("admin" in s or "full" in s for s in scopes)
            risk = "ACTIVE SendGrid API key."
            if has_full:
                risk += " Has full account access including billing and subusers."
            elif has_mail:
                risk += " Can send emails on behalf of your domain — phishing risk."
            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                permissions=scopes[:10],
                risk_summary=risk,
                remediation=(
                    "1. Go to app.sendgrid.com → Settings → API Keys\n"
                    "2. Revoke this key immediately\n"
                    "3. Check sent email logs for unauthorized sends\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually revoke at app.sendgrid.com/settings/api_keys.",
            )