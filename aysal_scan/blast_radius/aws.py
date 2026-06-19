from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class AWSChecker(BaseChecker):
    """
    Checks an AWS Access Key by calling sts:GetCallerIdentity
    and listing attached IAM policies.
    """

    def check(self, secret_value: str) -> BlastRadiusResult:
        # secret_value here is "ACCESS_KEY_ID:SECRET_ACCESS_KEY" or just the key ID
        # In practice the scanner finds AKIA... — we need both key + secret to call AWS.
        # We attempt GetCallerIdentity; if we only have the key ID, we flag as MEDIUM.
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError

            parts = secret_value.split(":")
            if len(parts) == 2:
                access_key, secret_key = parts
            else:
                # Only the key ID found — can't authenticate, flag for manual review
                return BlastRadiusResult(
                    is_active=None,
                    check_performed=False,
                    risk_summary="AWS key ID found but no secret key detected. Manual verification required.",
                    remediation="Search your codebase for the matching AWS_SECRET_ACCESS_KEY and rotate both at AWS IAM Console.",
                )

            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()

            account_id = identity.get("Account", "unknown")
            arn = identity.get("Arn", "unknown")
            user_name = arn.split("/")[-1] if "/" in arn else arn

            # Try to list all policies: user-attached, group-attached, and inline
            permissions: list[str] = []
            try:
                iam = session.client("iam")

                # 1. Directly attached user policies
                user_policies = iam.list_attached_user_policies(UserName=user_name)
                for p in user_policies.get("AttachedPolicies", []):
                    permissions.append(p["PolicyName"])

                # 2. Inline user policies
                inline = iam.list_user_policies(UserName=user_name)
                for name in inline.get("PolicyNames", []):
                    permissions.append(f"{name} (inline)")

                # 3. Group-attached policies (the most common missed case)
                groups = iam.list_groups_for_user(UserName=user_name)
                for group in groups.get("Groups", []):
                    gname = group["GroupName"]
                    group_policies = iam.list_attached_group_policies(GroupName=gname)
                    for p in group_policies.get("AttachedPolicies", []):
                        label = f"{p['PolicyName']} (via group: {gname})"
                        if label not in permissions:
                            permissions.append(label)

            except Exception:
                permissions = ["Could not enumerate — insufficient IAM permissions"]

            is_admin = any("AdministratorAccess" in p for p in permissions)

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                account_info=f"Account: {account_id} | User: {user_name}",
                permissions=permissions,
                resources=["ALL AWS services"] if is_admin else ["See permissions above"],
                risk_summary=(
                    "ACTIVE key with AdministratorAccess on your AWS account. "
                    "Full read/write access to all services." if is_admin
                    else f"ACTIVE key for user '{user_name}' on account {account_id}."
                ),
                remediation=(
                    "1. Go to AWS IAM Console → Users → Security Credentials\n"
                    "2. Deactivate this access key immediately\n"
                    "3. Rotate to a new key and store it in AWS Secrets Manager\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as e:
            error_msg = str(e)
            if "InvalidClientTokenId" in error_msg or "AuthFailure" in error_msg:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Key appears to be inactive or already revoked.",
                    remediation="Confirm revocation in AWS IAM Console. Remove from git history anyway.",
                )
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify key status. Treat as active.",
                remediation="Manually verify and revoke at AWS IAM Console.",
            )
