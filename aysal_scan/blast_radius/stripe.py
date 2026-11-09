from __future__ import annotations

import httpx

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult, Severity


class StripeChecker(BaseChecker):
    """Verifies Stripe *secret* (sk_) and *restricted* (rk_) keys. Publishable keys cannot be
    verified (and are public by design), so the dispatcher never sends them here."""

    PROVIDER = "Stripe"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            is_test = secret_value.startswith(("sk_test_", "rk_test_"))
            is_restricted = secret_value.startswith("rk_")
            mode = "TEST" if is_test else "LIVE"

            resp = httpx.get(
                "https://api.stripe.com/v1/balance",
                auth=(secret_value, ""),
                timeout=self.TIMEOUT,
            )
            status = self.status_of(resp)

            if status == 403 and is_restricted:
                # A restricted key without permission to read the balance is still a valid key.
                return BlastRadiusResult(
                    is_active=True, check_performed=True,
                    permissions=["Restricted key (cannot read balance; other permissions unknown)"],
                    risk_summary=f"ACTIVE Stripe {mode} restricted key. Its exact permissions depend on how it was scoped.",
                    privilege=None,
                )
            early = self.classify_status(status)
            if early is not None:
                return early

            available = self.json_or_empty(resp).get("available", [])
            amounts = [
                f"{a['amount'] / 100:.2f} {a['currency'].upper()}"
                for a in available if isinstance(a, dict) and "amount" in a and "currency" in a
            ]
            if is_test:
                summary = "ACTIVE Stripe TEST key. It cannot move real money, but exposes test-mode data."
                permissions = ["Stripe API access (test mode)"]
                privilege = None
                suggested = Severity.LOW  # a live test-mode key must never be escalated
            elif is_restricted:
                summary = "ACTIVE Stripe LIVE restricted key with access to live-mode data."
                permissions = ["Restricted live key (balance readable)"]
                privilege = "write"
                suggested = None
            else:
                summary = (
                    "ACTIVE Stripe LIVE secret key. Full access to payments, "
                    "customers, subscriptions, and payouts."
                )
                permissions = ["Full Stripe API access (live key)"]
                privilege = "admin"
                suggested = None
            return BlastRadiusResult(
                is_active=True, check_performed=True, permissions=permissions,
                resources=[f"Balance: {', '.join(amounts)}"] if amounts else ["Balance: unknown"],
                risk_summary=summary, privilege=privilege,
                suggested_severity=suggested,
            )
        except Exception as e:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=str(e),
                risk_summary="Could not verify key. Treat as active.",
                remediation="Manually roll key at dashboard.stripe.com/apikeys.",
            )
