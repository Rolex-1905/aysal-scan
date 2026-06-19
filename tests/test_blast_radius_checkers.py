"""
Tests for previously-untested blast radius checkers:
AWS, Azure, Generic, Google, Heroku, JWT, PyPI, SendGrid, Slack,
Slack Webhook, Twilio — plus the retry/backoff logic in base.py.
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from aysal_scan.blast_radius.aws import AWSChecker
from aysal_scan.blast_radius.azure import AzureChecker
from aysal_scan.blast_radius.generic import GenericChecker
from aysal_scan.blast_radius.google import GoogleChecker
from aysal_scan.blast_radius.heroku import HerokuChecker
from aysal_scan.blast_radius.jwt_checker import JWTChecker
from aysal_scan.blast_radius.pypi import PyPIChecker
from aysal_scan.blast_radius.sendgrid import SendGridChecker
from aysal_scan.blast_radius.slack import SlackChecker
from aysal_scan.blast_radius.slack_webhook import SlackWebhookChecker
from aysal_scan.blast_radius.twilio import TwilioChecker
from aysal_scan.blast_radius.base import BaseChecker
from aysal_scan.models import BlastRadiusResult


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------
class TestAWSChecker:
    def test_no_secret_key_only_access_key(self):
        result = AWSChecker().check("AKIAIOSFODNN7EXAMPLE")
        assert result.check_performed is False
        assert result.is_active is None
        assert "secret key" in result.risk_summary.lower()

    @patch("boto3.Session")
    def test_active_key_with_admin_policy(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/deploy-bot",
        }
        mock_iam = MagicMock()
        mock_iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]
        }
        mock_session.client.side_effect = lambda name: mock_sts if name == "sts" else mock_iam

        result = AWSChecker().check("AKIAEXAMPLE:secretkeyvalue1234567890")
        assert result.is_active is True
        assert result.check_performed is True
        assert "AdministratorAccess" in result.permissions
        assert "ALL AWS services" in result.resources
        assert "deploy-bot" in result.account_info

    @patch("boto3.Session")
    def test_invalid_credentials_marked_inactive(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = Exception("InvalidClientTokenId: The token is invalid")
        mock_session.client.return_value = mock_sts

        result = AWSChecker().check("AKIAEXAMPLE:badsecret")
        assert result.is_active is False
        assert result.check_performed is True


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------
class TestAzureChecker:
    def test_format_valid_length_flags_manual_review(self):
        result = AzureChecker().check("a" * 36)
        assert result.is_active is None
        assert result.check_performed is True
        assert "tenant" in result.risk_summary.lower()
        assert "matches expected format" in result.risk_summary

    def test_short_value_flagged_as_placeholder(self):
        result = AzureChecker().check("short")
        assert "placeholder" in result.risk_summary.lower()


# ---------------------------------------------------------------------------
# Generic fallback
# ---------------------------------------------------------------------------
class TestGenericChecker:
    def test_always_returns_manual_review(self):
        result = GenericChecker().check("anything-at-all")
        assert result.check_performed is False
        assert result.is_active is None
        assert "manual review" in result.risk_summary.lower()


# ---------------------------------------------------------------------------
# Google API key
# ---------------------------------------------------------------------------
class TestGoogleChecker:
    @patch("aysal_scan.blast_radius.google.httpx.get")
    def test_valid_key_detected(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {}
        mock_get.return_value = resp

        result = GoogleChecker().check("AIzaFAKEKEY")
        assert result.is_active is True
        assert result.check_performed is True

    @patch("aysal_scan.blast_radius.google.httpx.get")
    def test_invalid_key_detected(self, mock_get):
        resp = MagicMock()
        resp.status_code = 403
        resp.json.return_value = {"error": {"errors": [{"reason": "keyInvalid"}]}}
        mock_get.return_value = resp

        result = GoogleChecker().check("AIzaINVALIDKEY")
        assert result.is_active is False

    @patch("aysal_scan.blast_radius.google.httpx.get")
    def test_network_failure_degrades_gracefully(self, mock_get):
        mock_get.side_effect = Exception("connection refused")
        result = GoogleChecker().check("AIzaFAKEKEY")
        assert result.is_active is None
        assert result.check_performed is True


# ---------------------------------------------------------------------------
# Heroku
# ---------------------------------------------------------------------------
class TestHerokuChecker:
    @patch("aysal_scan.blast_radius.heroku.httpx.get")
    def test_active_key(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"email": "dev@example.com", "name": "Dev"}
        mock_get.return_value = resp

        result = HerokuChecker().check("fake-heroku-key")
        assert result.is_active is True
        assert "dev@example.com" in result.account_info

    @patch("aysal_scan.blast_radius.heroku.httpx.get")
    def test_revoked_key(self, mock_get):
        resp = MagicMock()
        resp.status_code = 401
        mock_get.return_value = resp

        result = HerokuChecker().check("revoked-key")
        assert result.is_active is False

    @patch("aysal_scan.blast_radius.heroku.httpx.get")
    def test_unexpected_status_sets_check_error(self, mock_get):
        resp = MagicMock()
        resp.status_code = 500
        mock_get.return_value = resp

        result = HerokuChecker().check("some-key")
        assert result.is_active is None
        assert "HTTP 500" in result.check_error


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
class TestJWTChecker:
    def _make_jwt(self, payload: dict) -> str:
        import base64, json
        def b64(d):
            raw = json.dumps(d).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        header = {"alg": "HS256", "typ": "JWT"}
        return f"{b64(header)}.{b64(payload)}.fakesignature"

    def test_expired_token_marked_inactive(self):
        token = self._make_jwt({"sub": "user1", "exp": int(time.time()) - 3600})
        result = JWTChecker().check(token)
        assert result.is_active is False
        assert "EXPIRED" in result.risk_summary

    def test_valid_token_with_future_expiry(self):
        token = self._make_jwt({"sub": "user1", "exp": int(time.time()) + 3600})
        result = JWTChecker().check(token)
        assert result.is_active is True
        assert "still valid" in result.risk_summary.lower()

    def test_token_with_no_expiry_treated_as_active(self):
        token = self._make_jwt({"sub": "user1"})
        result = JWTChecker().check(token)
        assert result.is_active is True
        assert "no expiry" in result.risk_summary.lower()

    def test_wrong_segment_count_not_parsed(self):
        """A string with the wrong number of dot-separated segments fails the
        structural check before any decoding is attempted."""
        result = JWTChecker().check("not-a-jwt-at-all")
        assert result.check_performed is False
        assert result.is_active is None

    def test_undecodable_segments_handled_gracefully(self):
        """Three segments that don't decode as valid base64/JSON still
        degrade gracefully via the except branch, not the structural check."""
        result = JWTChecker().check("not.a.validjwt!!!")
        assert result.check_performed is True
        assert result.is_active is None
        assert result.check_error


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------
class TestPyPIChecker:
    def test_always_flags_manual_review_never_calls_network(self):
        result = PyPIChecker().check("pypi-fake-token")
        assert result.check_performed is False
        assert result.is_active is None
        assert "revoke" in result.risk_summary.lower()


# ---------------------------------------------------------------------------
# SendGrid
# ---------------------------------------------------------------------------
class TestSendGridChecker:
    @patch("aysal_scan.blast_radius.sendgrid.httpx.get")
    def test_active_key_with_mail_scope(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"scopes": ["mail.send", "alerts.read"]}
        mock_get.return_value = resp

        result = SendGridChecker().check("SG.fake")
        assert result.is_active is True
        assert "phishing" in result.risk_summary.lower()

    @patch("aysal_scan.blast_radius.sendgrid.httpx.get")
    def test_revoked_key(self, mock_get):
        resp = MagicMock()
        resp.status_code = 401
        mock_get.return_value = resp

        result = SendGridChecker().check("SG.revoked")
        assert result.is_active is False


# ---------------------------------------------------------------------------
# Slack bot token
# ---------------------------------------------------------------------------
class TestSlackChecker:
    @patch("aysal_scan.blast_radius.slack.httpx.post")
    def test_active_bot_token(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {"ok": True, "team": "Acme", "user": "bot", "bot_id": "B123"}
        resp.headers = {"x-oauth-scopes": "chat:write,files:write"}
        mock_post.return_value = resp

        result = SlackChecker().check("xoxb-fake")
        assert result.is_active is True
        assert "Acme" in result.account_info
        assert "Can send messages" in result.risk_summary

    @patch("aysal_scan.blast_radius.slack.httpx.post")
    def test_revoked_token(self, mock_post):
        resp = MagicMock()
        resp.json.return_value = {"ok": False, "error": "token_revoked"}
        resp.headers = {}
        mock_post.return_value = resp

        result = SlackChecker().check("xoxb-revoked")
        assert result.is_active is False


# ---------------------------------------------------------------------------
# Slack Webhook
# ---------------------------------------------------------------------------
class TestSlackWebhookChecker:
    @patch("aysal_scan.blast_radius.slack_webhook.httpx.post")
    def test_active_webhook_no_text_response(self, mock_post):
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "no_text"
        mock_post.return_value = resp

        result = SlackWebhookChecker().check("https://hooks.slack.com/services/FAKE")
        assert result.is_active is True

    @patch("aysal_scan.blast_radius.slack_webhook.httpx.post")
    def test_revoked_webhook(self, mock_post):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "invalid_webhook"
        mock_post.return_value = resp

        result = SlackWebhookChecker().check("https://hooks.slack.com/services/REVOKED")
        assert result.is_active is False


# ---------------------------------------------------------------------------
# Twilio
# ---------------------------------------------------------------------------
class TestTwilioChecker:
    def test_sid_without_auth_token_flags_manual_review(self):
        result = TwilioChecker().check("ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert result.check_performed is False
        assert result.is_active is None

    @patch("aysal_scan.blast_radius.twilio.httpx.get")
    def test_active_account(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": "active", "friendly_name": "My Project"}
        mock_get.return_value = resp

        result = TwilioChecker().check("ACfakeSID:faketoken1234567890123456")
        assert result.is_active is True
        assert "My Project" in result.account_info

    @patch("aysal_scan.blast_radius.twilio.httpx.get")
    def test_revoked_credentials(self, mock_get):
        resp = MagicMock()
        resp.status_code = 401
        mock_get.return_value = resp

        result = TwilioChecker().check("ACfakeSID:badtoken")
        assert result.is_active is False


# ---------------------------------------------------------------------------
# base.py — retry/backoff logic
# ---------------------------------------------------------------------------
class _FlakyChecker(BaseChecker):
    """Test double: fails with a retryable error N times, then succeeds."""
    def __init__(self, fail_times: int, error_code: int = 500):
        self.fail_times = fail_times
        self.error_code = error_code
        self.calls = 0

    def check(self, secret_value: str) -> BlastRadiusResult:
        self.calls += 1
        if self.calls <= self.fail_times:
            return BlastRadiusResult(
                is_active=None,
                check_performed=True,
                check_error=f"Unexpected HTTP {self.error_code}",
            )
        return BlastRadiusResult(is_active=True, check_performed=True, risk_summary="ok")


class _AlwaysNonRetryableChecker(BaseChecker):
    def __init__(self):
        self.calls = 0

    def check(self, secret_value: str) -> BlastRadiusResult:
        self.calls += 1
        return BlastRadiusResult(
            is_active=None,
            check_performed=True,
            check_error="Error on line 500 of response body",  # contains "500" but NOT "HTTP 500"
        )


class TestRetryLogic:
    @patch("time.sleep", return_value=None)
    def test_retries_then_succeeds(self, mock_sleep):
        checker = _FlakyChecker(fail_times=2)
        result = checker.check_with_retry("secret")
        assert result.is_active is True
        assert checker.calls == 3
        assert mock_sleep.call_count == 2

    @patch("time.sleep", return_value=None)
    def test_exhausts_retries_and_returns_last_error(self, mock_sleep):
        """After MAX_RETRIES attempts all returning a retryable error, the
        checker stops retrying and returns the final attempt's result as-is."""
        checker = _FlakyChecker(fail_times=10)  # never succeeds
        result = checker.check_with_retry("secret")
        assert result.is_active is None
        assert "HTTP 500" in result.check_error
        assert checker.calls == checker.MAX_RETRIES

    @patch("time.sleep", return_value=None)
    def test_non_retryable_error_does_not_retry(self, mock_sleep):
        """
        Regression test for the fragile-substring-match bug: an error message
        that happens to contain '500' but not in 'HTTP 500' format must NOT
        trigger a retry.
        """
        checker = _AlwaysNonRetryableChecker()
        result = checker.check_with_retry("secret")
        assert checker.calls == 1  # no retry attempted
        mock_sleep.assert_not_called()