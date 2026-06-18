"""JWT token blast radius checker — decode and check expiry."""
from __future__ import annotations

import base64
import json
import time

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


def _b64_decode(segment: str) -> dict:
    """Decode a base64url-encoded JWT segment."""
    padding = 4 - len(segment) % 4
    segment += "=" * (padding % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


class JWTChecker(BaseChecker):

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            parts = secret_value.split(".")
            if len(parts) != 3:
                return BlastRadiusResult(
                    is_active=None,
                    check_performed=False,
                    risk_summary="Could not parse JWT structure.",
                    remediation="Manually inspect and revoke if valid.",
                )

            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])

            alg = header.get("alg", "unknown")
            sub = payload.get("sub", "")
            iss = payload.get("iss", "")
            exp = payload.get("exp")

            now = time.time()
            if exp is not None:
                is_expired = now > exp
                expiry_note = (
                    f"EXPIRED at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(exp))}"
                    if is_expired
                    else f"Valid until {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(exp))}"
                )
                is_active = not is_expired
            else:
                is_expired = False
                expiry_note = "No expiry claim (exp) — token may be permanent."
                is_active = True

            risk = f"JWT token found. Algorithm: {alg}. {expiry_note}."
            if iss:
                risk += f" Issuer: {iss}."
            if sub:
                risk += f" Subject: {sub}."
            if not is_expired:
                risk += " Token is still valid — anyone with it can authenticate."

            return BlastRadiusResult(
                is_active=is_active,
                check_performed=True,
                account_info=f"iss={iss or 'unknown'} sub={sub or 'unknown'}",
                permissions=[f"Algorithm: {alg}"],
                risk_summary=risk,
                remediation=(
                    "1. Identify the service that issued this token\n"
                    "2. Revoke the token or the signing key in that service\n"
                    "3. Remove from git history with: git filter-repo"
                ),
            )

        except Exception as exc:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=str(exc),
                risk_summary="Could not decode JWT. Treat as active.",
                remediation="Manually inspect and revoke if valid.",
            )