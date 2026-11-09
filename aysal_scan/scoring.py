"""Risk score (0-100) combining *evidence* about a leaked credential.

Severity answers "what kind of secret is this?". The risk score answers "how urgently
should I act on THIS leak?" by combining independent, explainable factors:

    validity   verified live (+40) / unverified (+20) / verified revoked (0, score capped at 12)
    privilege  admin (+25) / write (+15) / read (+8) / unknown-but-active (+10)   [live keys only]
    exposure   present now (+15) / history only (+5) / unknown (+10)
    age        exposed >= 365 days (+10) / >= 30 days (+5)                         [history scans]
    spread     found in more than one place (+3)
    type       how damaging this class of secret usually is (0-15)
    context    example/template file (-25), public client-side key (-15)

Every finding carries its ``risk_factors`` so the number is never a black box.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Iterable, Optional

from aysal_scan.models import Finding, SecretType

_TYPE_POINTS: dict[SecretType, int] = {
    SecretType.AWS_ACCESS_KEY: 15, SecretType.PRIVATE_KEY: 15, SecretType.STRIPE_SECRET: 15,
    SecretType.GCP_SERVICE_ACCOUNT: 15, SecretType.AGE_SECRET_KEY: 15,
    SecretType.DATABASE_URL: 12,
    SecretType.JWT: 5, SecretType.SLACK_WEBHOOK: 6, SecretType.GENERIC: 5,
    SecretType.HIGH_ENTROPY: 2, SecretType.STRIPE_PUBLISHABLE: 0,
    SecretType.STRIPE_TEST_PUBLISHABLE: 0, SecretType.STRIPE_TEST_SECRET: 2,
    SecretType.GOOGLE_API: 8, SecretType.CUSTOM: 8,
}
_DEFAULT_TYPE_POINTS = 10
# Matches made by entropy / assignment heuristics rather than a provider-specific format.
_HEURISTIC_TYPES = {SecretType.HIGH_ENTROPY, SecretType.GENERIC}
_PRIVILEGE_POINTS = {"admin": 25, "write": 15, "read": 8, None: 10}


def _age_days(commit_date: Optional[str], today: date) -> Optional[int]:
    if not commit_date:
        return None
    try:
        return (today - datetime.strptime(commit_date[:10], "%Y-%m-%d").date()).days
    except ValueError:
        return None


def score_finding(f: Finding, today: Optional[date] = None) -> tuple[int, list[str]]:
    today = today or date.today()
    br = f.blast_radius
    score = 0
    factors: list[str] = []

    verified = br is not None and br.check_performed
    active = verified and br.is_active is True
    revoked = verified and br.is_active is False

    if active:
        score += 40
        factors.append("credential verified live (+40)")
        pts = _PRIVILEGE_POINTS.get(br.privilege, 10)
        score += pts
        label = {"admin": "admin-level privileges", "write": "write privileges",
                 "read": "read-only privileges"}.get(br.privilege, "privileges unknown")
        factors.append(f"{label} (+{pts})")
    elif revoked:
        factors.append("credential verified revoked/expired (0)")
    elif f.secret_type in _HEURISTIC_TYPES:
        score += 5
        factors.append("heuristic match, not a recognised credential format (+5)")
    else:
        score += 20
        factors.append("validity not verified — assume live (+20)")

    if f.commit_hash is None or f.in_head is True:
        score += 15
        factors.append("still present in the code (+15)")
    elif f.in_head is False:
        score += 5
        factors.append("history only — removed from HEAD (+5)")
    else:
        score += 10
        factors.append("present in git history (+10)")

    days = _age_days(f.commit_date, today)
    if days is not None and days >= 365:
        score += 10
        factors.append(f"exposed {days} days (+10)")
    elif days is not None and days >= 30:
        score += 5
        factors.append(f"exposed {days} days (+5)")

    if f.locations:
        score += 3
        factors.append(f"found in {len(f.locations) + 1} places (+3)")

    type_pts = _TYPE_POINTS.get(f.secret_type, _DEFAULT_TYPE_POINTS)
    if type_pts:
        score += type_pts
        factors.append(f"{f.secret_type.value} credential class (+{type_pts})")

    if "example-file" in f.tags:
        score -= 25
        factors.append("example/template file (-25)")
    if br is not None and br.suggested_severity is not None and "public" in br.risk_summary.lower():
        score -= 15
        factors.append("public client-side key by design (-15)")

    if revoked:
        score = min(score, 12)
    return max(0, min(100, score)), factors


def apply_scores(findings: Iterable[Finding], today: Optional[date] = None) -> list[Finding]:
    """Attach ``risk_score`` / ``risk_factors`` to every finding (in place) and return them."""
    out = list(findings)
    for f in out:
        f.risk_score, f.risk_factors = score_finding(f, today)
    return out
