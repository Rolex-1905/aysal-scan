"""Azure Client Secret blast radius checker.

Azure client secrets cannot be verified without a tenant ID and client ID,
which are separate values not always co-located with the secret.
We flag for manual review rather than attempting an API call.
"""
from __future__ import annotations

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class AzureChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            # Azure client secrets follow a predictable format:
            # 32-40 chars, mix of letters/digits/special chars
            # We cannot verify without tenant_id + client_id so we
            # flag as manual review with clear remediation steps.
            length = len(secret_value)
            looks_valid = length >= 32

            return BlastRadiusResult(
                is_active=None,  # cannot verify without tenant/client ID
                check_performed=True,
                account_info="Azure tenant and client ID required for full verification",
                permissions=["Unknown — manual review required"],
                resources=["Azure AD application and associated resources"],
                risk_summary=(
                    f"Azure Client Secret found (length: {length}). "
                    "Cannot auto-verify without tenant ID and client ID. "
                    f"{'Value matches expected format — treat as active.' if looks_valid else 'Value is shorter than expected — may be a placeholder.'}"
                ),
                remediation=(
                    "1. Go to portal.azure.com → Azure Active Directory → App registrations\n"
                    "2. Find the application using this secret\n"
                    "3. Under 'Certificates & secrets' delete this secret immediately\n"
                    "4. Generate a new secret and store it in Azure Key Vault\n"
                    "5. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as exc:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(exc),
                risk_summary="Could not analyse Azure secret. Treat as active.",
                remediation="Manually review at portal.azure.com → Azure Active Directory → App registrations.",
            )