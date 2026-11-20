"""Map findings to CWE and OWASP Top 10 (2021) identifiers.

* CWE-798  Use of Hard-coded Credentials        (default for provider tokens / API keys)
* CWE-259  Use of Hard-coded Password           (password assignments, database URLs)
* CWE-321  Use of Hard-coded Cryptographic Key  (private keys, age identities)
* CWE-522  Insufficiently Protected Credentials (JWTs that carry credentials)

OWASP Top 10 2021 lists CWE-798 and CWE-259 under A07 (Identification and Authentication
Failures) and CWE-321 under A02 (Cryptographic Failures).
"""
from __future__ import annotations

from typing import Iterable

from aysal_scan.models import Finding, SecretType

OWASP_NAMES = {
    "A02:2021": "Cryptographic Failures",
    "A07:2021": "Identification and Authentication Failures",
}

_DEFAULT = ("CWE-798", "A07:2021")
_MAPPING: dict[SecretType, tuple[str, str]] = {
    SecretType.PRIVATE_KEY: ("CWE-321", "A02:2021"),
    SecretType.AGE_SECRET_KEY: ("CWE-321", "A02:2021"),
    SecretType.GENERIC: ("CWE-259", "A07:2021"),
    SecretType.DATABASE_URL: ("CWE-259", "A07:2021"),
    SecretType.JWT: ("CWE-522", "A07:2021"),
}


def classify(secret_type: SecretType) -> tuple[str, str]:
    """Return ``(cwe_id, owasp_id)`` for a secret type."""
    return _MAPPING.get(secret_type, _DEFAULT)


def owasp_label(owasp_id: str) -> str:
    return f"{owasp_id} {OWASP_NAMES.get(owasp_id, '')}".strip()


def apply_compliance(findings: Iterable[Finding]) -> list[Finding]:
    """Attach ``cwe`` / ``owasp`` to every finding (in place) and return them."""
    out = list(findings)
    for f in out:
        cwe, owasp = classify(f.secret_type)
        f.cwe = [cwe]
        f.owasp = owasp
    return out
