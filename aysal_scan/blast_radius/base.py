from __future__ import annotations

import time
from abc import ABC, abstractmethod

from aysal_scan.models import BlastRadiusResult


class BaseChecker(ABC):
    TIMEOUT = 10        # seconds per API call
    MAX_RETRIES = 3     # attempts before giving up
    RETRY_CODES = {429, 500, 502, 503, 504}  # retry on these HTTP status codes

    @abstractmethod
    def check(self, secret_value: str) -> BlastRadiusResult:
        """
        Call the provider API with the secret and return a BlastRadiusResult.
        NEVER raise exceptions — catch everything and set check_error instead.
        NEVER modify any resources — read-only API calls only.
        """
        pass

    def check_with_retry(self, secret_value: str) -> BlastRadiusResult:
        """
        Wraps check() with exponential backoff retry logic.
        Retries on transient HTTP errors (429, 5xx) and network timeouts.
        Falls back gracefully on all other exceptions.
        """
        last_error: str = ""

        for attempt in range(self.MAX_RETRIES):
            try:
                result = self.check(secret_value)

                # Retry if we got a retryable HTTP status (checker must set check_error)
                if (
                    result.check_error
                    and any(str(code) in result.check_error for code in self.RETRY_CODES)
                    and attempt < self.MAX_RETRIES - 1
                ):
                    wait = 2 ** attempt  # 1s, 2s, 4s
                    time.sleep(wait)
                    last_error = result.check_error
                    continue

                return result

            except Exception as exc:
                last_error = str(exc)
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                continue

        return BlastRadiusResult(
            is_active=None,
            check_performed=True,
            check_error=f"Failed after {self.MAX_RETRIES} attempts: {last_error}",
            risk_summary="Blast radius check failed after retries. Treat as active.",
            remediation="Manually verify and revoke this credential.",
        )

    @staticmethod
    def mask(value: str) -> str:
        if len(value) <= 8:
            return "****"
        return value[:4] + "*" * (len(value) - 8) + value[-4:]