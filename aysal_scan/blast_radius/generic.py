from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class GenericChecker(BaseChecker):
    """
    Fallback checker for secret types that don't have a specific checker.
    Cannot verify — just returns a safe default result.
    """

    def check(self, secret_value: str) -> BlastRadiusResult:
        return BlastRadiusResult(
            is_active=None,
            check_performed=False,
            risk_summary="Automated blast radius check not available for this secret type. Manual review required.",
            remediation=(
                "1. Identify the service this credential belongs to\n"
                "2. Revoke or rotate the credential in that service's dashboard\n"
                "3. Remove from git history with: git filter-repo\n"
                "4. Store future secrets in a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault)"
            ),
        )
