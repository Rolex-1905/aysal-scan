import httpx
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


class StripeChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            resp = httpx.get(
                "https://api.stripe.com/v1/balance",
                auth=(secret_value, ""),
                timeout=self.TIMEOUT,
            )

            if resp.status_code == 401:
                return BlastRadiusResult(
                    is_active=False,
                    check_performed=True,
                    risk_summary="Stripe key is invalid or revoked.",
                    remediation="Remove from git history. Confirm revocation in Stripe Dashboard.",
                )

            balance = resp.json()
            available = balance.get("available", [])
            amounts = [
                f"{a['amount'] / 100:.2f} {a['currency'].upper()}"
                for a in available
            ]

            return BlastRadiusResult(
                is_active=True,
                check_performed=True,
                permissions=["Full Stripe API access (live key)"],
                resources=[f"Balance: {', '.join(amounts)}"] if amounts else ["Balance: unknown"],
                risk_summary=(
                    "ACTIVE Stripe LIVE secret key. Full access to payments, "
                    "customers, subscriptions, and payouts."
                ),
                remediation=(
                    "1. Go to dashboard.stripe.com/apikeys\n"
                    "2. Roll (rotate) this key immediately\n"
                    "3. Check for unauthorized charges or refunds\n"
                    "4. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as e:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually roll key at dashboard.stripe.com/apikeys.",
            )
