from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from aysal_scan.models import BlastRadiusResult

_RETRYABLE_ERROR = re.compile(r"HTTP (?:429|5\d\d)\b")


class BaseChecker(ABC):
    """Base class for every provider verifier.

    Contract
    --------
    * Read-only provider calls only; never modify anything.
    * Never raise: put problems in ``check_error``.
    * Use ``classify_status`` for every HTTP response so that only a real 200 is
      ever reported as an active credential (v1 treated 403/429 as "active").
    """

    TIMEOUT = 10        # seconds per API call
    MAX_RETRIES = 3     # attempts before giving up
    PROVIDER = ""       # human-readable provider name (defaults to the class name)

    @property
    def provider_name(self) -> str:
        return self.PROVIDER or type(self).__name__.replace("Checker", "")

    @abstractmethod
    def check(self, secret_value: str) -> BlastRadiusResult:
        """Verify the credential. See class docstring for the contract."""

    # ------------------------------------------------------------------ helpers

    def classify_status(
        self,
        status: int,
        *,
        inactive: tuple[int, ...] = (401,),
        ok: tuple[int, ...] = (200,),
    ) -> Optional[BlastRadiusResult]:
        """Map an HTTP status to a result, or return None when the call succeeded.

        * ``ok``       -> None (caller continues parsing the body)
        * ``inactive`` -> credential rejected: ``is_active=False``
        * anything else (403, 404, 429, 5xx...) -> **unverified**, never "active".
          The message contains ``HTTP <code>`` so retryable codes are retried.
        """
        if status in ok:
            return None
        name = self.provider_name
        if status in inactive:
            return BlastRadiusResult(
                is_active=False,
                check_performed=True,
                risk_summary=f"{name} credential is invalid, expired or revoked.",
                remediation=(
                    "No active exposure through this credential. Still remove it from "
                    "git history and confirm it was rotated."
                ),
            )
        return BlastRadiusResult(
            is_active=None,
            check_performed=True,   # we did try; the error explains why it is unverified
            check_error=f"{name} returned HTTP {status}; could not verify.",
            risk_summary=(
                f"Could not verify this {name} credential (HTTP {status}). "
                "Treat it as active until you confirm otherwise."
            ),
            remediation="Manually verify the credential and revoke it if it is still valid.",
        )

    @staticmethod
    def status_of(resp: Any) -> int:
        """HTTP status as an int (APIs that always answer 200 may be mocked without one)."""
        status = getattr(resp, "status_code", 200)
        return status if isinstance(status, int) else 200

    @staticmethod
    def json_or_empty(resp: Any) -> dict:
        try:
            data = resp.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def check_with_retry(self, secret_value: str) -> BlastRadiusResult:
        """Run ``check`` with exponential backoff on transient failures (HTTP 429/5xx, exceptions)."""
        last_error = ""
        for attempt in range(self.MAX_RETRIES):
            try:
                result = self.check(secret_value)
                if (
                    result.check_error
                    and _RETRYABLE_ERROR.search(result.check_error)
                    and attempt < self.MAX_RETRIES - 1
                ):
                    last_error = result.check_error
                    time.sleep(2 ** attempt)  # 1s, 2s
                    continue
                return result
            except Exception as exc:  # checkers should not raise, but never crash the scan
                last_error = str(exc)
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)

        return BlastRadiusResult(
            is_active=None,
            check_performed=True,
            check_error=f"Failed after {self.MAX_RETRIES} attempts: {last_error}",
            risk_summary="Blast radius check failed after retries. Treat as active.",
            remediation="Manually verify and revoke this credential.",
        )

    @staticmethod
    def mask(value: str) -> str:
        n = len(value)
        if n <= 8:
            return "****"
        if n <= 16:
            return value[:2] + "*" * (n - 4) + value[-2:]
        return value[:4] + "*" * (n - 8) + value[-4:]
