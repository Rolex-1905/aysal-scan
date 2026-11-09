from __future__ import annotations

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult

_ADMIN_POLICY = "AdministratorAccess"
_WRITE_POLICIES = ("PowerUserAccess", "IAMFullAccess")

_REMEDIATION = (
    "1. Go to AWS IAM Console → Users → Security Credentials\n"
    "2. Deactivate this access key immediately\n"
    "3. Rotate to a new key and store it in AWS Secrets Manager\n"
    "4. Review CloudTrail for activity by this key, then remove it from git history with: git filter-repo"
)


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


class AWSChecker(BaseChecker):
    """Verifies an AWS access key with sts:GetCallerIdentity and enumerates IAM policies.

    ``secret_value`` is ``"ACCESS_KEY_ID:SECRET_ACCESS_KEY"`` (the scanner pairs them);
    a lone key ID cannot be verified. Temporary ``ASIA`` keys also need a session token,
    so they are reported as unverifiable instead of being mistaken for revoked keys.
    """

    PROVIDER = "AWS"

    def check(self, secret_value: str) -> BlastRadiusResult:
        parts = secret_value.split(":")
        if len(parts) != 2:
            return BlastRadiusResult(
                is_active=None,
                check_performed=False,
                risk_summary="AWS key ID found but no secret key detected. Manual verification required.",
                remediation="Search your codebase for the matching AWS_SECRET_ACCESS_KEY and rotate both at AWS IAM Console.",
            )
        access_key, secret_key = parts

        if access_key.startswith("ASIA"):
            return BlastRadiusResult(
                is_active=None,
                check_performed=False,
                risk_summary=(
                    "Temporary AWS credentials (ASIA...) need a session token to be verified. "
                    "They expire automatically, but may still be live right now."
                ),
                remediation=_REMEDIATION,
            )

        try:
            import boto3
            from botocore.config import Config

            cfg = Config(
                connect_timeout=self.TIMEOUT,
                read_timeout=self.TIMEOUT,
                retries={"max_attempts": 1},
            )
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name="us-east-1",
            )
            sts = session.client("sts", config=cfg)
            identity = sts.get_caller_identity()

            account_id = identity.get("Account", "unknown")
            arn = identity.get("Arn", "unknown")
            is_root = arn.endswith(":root")
            user_name = None if is_root else (arn.split("/")[-1] if "/" in arn else None)

            permissions: list[str] = []
            is_admin = is_root
            is_write = False
            enumeration_failed = False

            if is_root:
                permissions.append("ROOT account credentials (unrestricted)")
            elif user_name:
                iam = session.client("iam", config=cfg)

                def add(label: str, base_name: str) -> None:
                    nonlocal is_admin, is_write
                    if label not in permissions:
                        permissions.append(label)
                    if base_name == _ADMIN_POLICY:
                        is_admin = True
                    elif base_name in _WRITE_POLICIES:
                        is_write = True

                try:
                    for p in iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []):
                        add(p["PolicyName"], p["PolicyName"])
                except Exception:
                    enumeration_failed = True
                try:
                    for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
                        add(f"{name} (inline)", "")
                except Exception:
                    enumeration_failed = True
                try:
                    for group in iam.list_groups_for_user(UserName=user_name).get("Groups", []):
                        gname = group["GroupName"]
                        try:
                            for p in iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", []):
                                add(f"{p['PolicyName']} (via group: {gname})", p["PolicyName"])
                        except Exception:
                            enumeration_failed = True
                except Exception:
                    enumeration_failed = True

                if not permissions and enumeration_failed:
                    permissions = ["Could not enumerate — insufficient IAM permissions"]
                elif enumeration_failed:
                    permissions.append("(list may be incomplete — some IAM calls were denied)")

            privilege = "admin" if is_admin else ("write" if is_write else None)
            display_user = "root" if is_root else (user_name or arn)

            if is_admin:
                summary = (
                    "ACTIVE key with AdministratorAccess on your AWS account. "
                    "Full read/write access to all services."
                    if not is_root
                    else "ACTIVE ROOT account credentials. Unrestricted access to the entire AWS account."
                )
            else:
                summary = f"ACTIVE key for user '{display_user}' on account {account_id}."

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"Account: {account_id} | User: {display_user}",
                permissions=permissions,
                resources=["ALL AWS services"] if is_admin else ["See permissions above"],
                risk_summary=summary,
                remediation=_REMEDIATION,
                privilege=privilege,
            )

        except Exception as exc:
            code = _error_code(exc)
            text = str(exc)
            if code in {"InvalidClientTokenId", "AuthFailure"} or "InvalidClientTokenId" in text or "AuthFailure" in text:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Key appears to be inactive or already revoked.",
                    remediation="Confirm revocation in AWS IAM Console. Remove from git history anyway.",
                )
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=text,
                risk_summary="Could not verify key status. Treat as active.",
                remediation="Manually verify and revoke at AWS IAM Console.",
            )
