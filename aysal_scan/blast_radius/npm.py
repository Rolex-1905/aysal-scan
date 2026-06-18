import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class NpmChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://registry.npmjs.org/-/whoami",
                headers={"Authorization": f"Bearer {secret_value}"},
                timeout=self.TIMEOUT,
            )

            if resp.status_code in (401, 403):
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="npm token is invalid or revoked.",
                    remediation="Remove from git history.",
                )

            username = resp.json().get("username", "unknown")

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"npm user: {username}",
                permissions=["Publish packages under this account"],
                risk_summary=(
                    f"ACTIVE npm token for user '{username}'. "
                    "Can publish malicious packages to npm registry."
                ),
                remediation=(
                    "1. Go to npmjs.com → Account → Access Tokens\n"
                    "2. Revoke this token immediately\n"
                    "3. Audit recent publishes for tampering\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify token. Treat as active.",
                remediation="Manually revoke at npmjs.com/settings/tokens.",
            )
