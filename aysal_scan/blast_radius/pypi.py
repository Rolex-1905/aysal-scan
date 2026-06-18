from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class PyPIChecker(BaseChecker):
    """
    PyPI has no lightweight auth-verification endpoint.
    The only write endpoint is the upload API which we must never call.
    We flag the finding for mandatory manual review rather than
    falsely reporting every token as active or inactive.
    """

    def check(self, secret_value: str) -> BlastRadiusResult:
        return BlastRadiusResult(
            is_active=None,
            check_performed=False,
            risk_summary=(
                "PyPI token detected. Automated verification is not possible "
                "without performing a write operation. Treat as active and revoke immediately."
            ),
            remediation=(
                "1. Go to pypi.org/manage/account/token/\n"
                "2. Identify and revoke this token immediately\n"
                "3. Audit recent package releases for unauthorized uploads\n"
                "4. Remove from git history with: git filter-repo"
            ),
        )