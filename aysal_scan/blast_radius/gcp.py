"""GCP service-account key checker (metadata only — never authenticates with the key)."""
from __future__ import annotations

import json

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class GCPServiceAccountChecker(BaseChecker):
    """The scanner hands this checker the key's *metadata* as JSON
    (``project_id``, ``client_email``, ``private_key_id``) — the private key itself is not kept.

    We deliberately never call Google with the key: it would need google-auth and would put
    entries in the owner's audit log. The result is therefore "unverified" (is_active=None),
    and the finding stays CRITICAL because service-account keys do not expire by default.
    """

    PROVIDER = "GCP"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            start = secret_value.find("{")
            if start == -1:
                return BlastRadiusResult(
                    is_active=None, check_performed=False,
                    risk_summary="Could not extract GCP service account JSON.",
                    remediation="Manually locate and revoke this service account in GCP IAM console.",
                )
            data = json.loads(secret_value[start:])
            project_id = data.get("project_id", "unknown")
            client_email = data.get("client_email", "unknown")
            key_id = data.get("private_key_id", "unknown")

            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                account_info=f"Project: {project_id} | SA: {client_email}",
                permissions=["Unknown — manual IAM review required"],
                resources=[f"Project: {project_id}"],
                risk_summary=(
                    f"GCP Service Account key found for '{client_email}' "
                    f"in project '{project_id}' (key ID: {key_id}). "
                    "Not verified automatically (doing so would use the key). "
                    "Treat as ACTIVE — service account keys do not expire by default."
                ),
                remediation=(
                    "1. Go to console.cloud.google.com → IAM → Service Accounts\n"
                    f"2. Find '{client_email}'\n"
                    "3. Delete this key under the 'Keys' tab immediately\n"
                    "4. Review audit logs for unauthorized usage\n"
                    "5. Remove from git history with: git filter-repo"
                ),
            )
        except json.JSONDecodeError:
            return BlastRadiusResult(
                is_active=None, check_performed=True,
                check_error="Could not parse service account JSON",
                risk_summary="Partial GCP service account JSON found. Treat as active.",
                remediation="Manually review and revoke at console.cloud.google.com → IAM → Service Accounts.",
            )
        except Exception as exc:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(exc),
                risk_summary="Could not verify GCP key. Treat as active.",
                remediation="Manually review at console.cloud.google.com → IAM → Service Accounts.",
            )
