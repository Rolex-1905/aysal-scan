"""JWT checker — decode and assess; a signature can never be verified from the token alone."""
from __future__ import annotations

import base64
import json
import re
import time

from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult, Severity

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PUBLIC_ROLES = {"anon", "anon_key", "publishable"}


def _b64_decode(segment: str) -> dict:
    """Decode a base64url-encoded JWT segment."""
    padding = 4 - len(segment) % 4
    segment += "=" * (padding % 4)
    data = json.loads(base64.urlsafe_b64decode(segment))
    if not isinstance(data, dict):
        raise ValueError("JWT segment is not a JSON object")
    return data


def _clean(value: object, limit: int = 80) -> str:
    """Claims are attacker-controlled: strip control characters and truncate before display."""
    text = _CONTROL.sub("", str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


class JWTChecker(BaseChecker):
    PROVIDER = "JWT"

    def check(self, secret_value: str) -> BlastRadiusResult:
        try:
            parts = secret_value.split(".")
            if len(parts) != 3:
                return BlastRadiusResult(
                    is_active=None, check_performed=False,
                    risk_summary="Could not parse JWT structure.",
                    remediation="Manually inspect and revoke if valid.",
                )

            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])

            alg = _clean(header.get("alg", "unknown"), 20)
            sub = _clean(payload.get("sub", ""))
            iss = _clean(payload.get("iss", ""))
            role = _clean(payload.get("role", ""), 30)
            exp = payload.get("exp")

            expired = False
            if isinstance(exp, (int, float)) and not isinstance(exp, bool):
                when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(exp))
                expired = time.time() > exp
                expiry_note = f"EXPIRED at {when}" if expired else f"Valid until {when}"
            else:
                expiry_note = "No expiry claim (exp) — token may be permanent."

            risk = f"JWT token found. Algorithm: {alg}. {expiry_note}."
            if iss:
                risk += f" Issuer: {iss}."
            if sub:
                risk += f" Subject: {sub}."

            suggested = None
            if expired:
                is_active = False
                suggested = Severity.LOW
            else:
                is_active = None  # signature cannot be checked: validity is unknown
                risk += " Token is still valid by its claims; its signature cannot be verified without the signing key."
                if role.lower() in _PUBLIC_ROLES:
                    suggested = Severity.LOW
                    risk += (
                        f" Role '{role}' marks this as a public client-side key "
                        "(e.g. Supabase anon) that is designed to be embedded in apps."
                    )

            return BlastRadiusResult(
                is_active=is_active,
                check_performed=True,
                account_info=f"iss={iss or 'unknown'} sub={sub or 'unknown'}",
                permissions=[f"Algorithm: {alg}"],
                risk_summary=risk,
                suggested_severity=suggested,
            )

        except Exception as exc:
            return BlastRadiusResult(
                is_active=None, check_performed=True, check_error=_clean(exc, 200),
                risk_summary="Could not decode JWT. Treat as active.",
                remediation="Manually inspect the token and revoke it if valid.",
            )
