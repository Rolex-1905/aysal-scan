"""Verification-engine regression tests (v1 audit): status handling, severity rules,
rate limiting, provider routing, risk scoring."""
from __future__ import annotations

import time
from datetime import date
from unittest.mock import MagicMock, patch

import pytest

from aysal_scan.blast_radius import (
    NETWORK_SECRET_TYPES,
    needs_network,
    run_blast_radius,
    run_blast_radius_concurrent,
)
from aysal_scan.blast_radius.anthropic_checker import AnthropicChecker
from aysal_scan.blast_radius.aws import AWSChecker
from aysal_scan.blast_radius.digitalocean import DigitalOceanChecker
from aysal_scan.blast_radius.github import GitHubChecker
from aysal_scan.blast_radius.gitlab import GitLabChecker
from aysal_scan.blast_radius.google import GoogleChecker
from aysal_scan.blast_radius.huggingface import HuggingFaceChecker
from aysal_scan.blast_radius.npm import NpmChecker
from aysal_scan.blast_radius.openai_checker import OpenAIChecker
from aysal_scan.blast_radius.sendgrid import SendGridChecker
from aysal_scan.blast_radius.stripe import StripeChecker
from aysal_scan.blast_radius.twilio import TwilioChecker
from aysal_scan.models import BlastRadiusResult, Finding, SecretType, Severity
from aysal_scan.scanner.file_scanner import scan_content
from aysal_scan.scoring import apply_scores, score_finding


def resp(status=200, body=None, headers=None, text=""):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body if body is not None else {}
    r.headers = headers or {}
    r.text = text
    return r


def finding(stype=SecretType.OPENAI_KEY, severity=Severity.HIGH, **kw):
    base = dict(id="x" * 8, secret_type=stype, severity=severity, file_path="a.py",
                line_number=1, masked_value="abcd****wxyz")
    base.update(kw)
    return Finding(**base)


# --------------------------------------------------------------------------
# A non-200 response is NEVER an active key
# --------------------------------------------------------------------------

@pytest.mark.parametrize("checker,secret", [
    (OpenAIChecker(), "sk-x"), (StripeChecker(), "sk_live_x"), (NpmChecker(), "npm_x"),
    (SendGridChecker(), "SG.x"), (GitHubChecker(), "ghp_x"), (AnthropicChecker(), "sk-ant-x"),
    (HuggingFaceChecker(), "hf_x"), (GitLabChecker(), "glpat-x"), (DigitalOceanChecker(), "dop_v1_x"),
])
@pytest.mark.parametrize("status", [403, 404, 429, 500, 503])
def test_error_statuses_are_unverified_not_active(checker, secret, status):
    if isinstance(checker, NpmChecker) and status == 403:
        pytest.skip("npm answers 403 for rejected tokens")
    with patch("httpx.get", return_value=resp(status, {"error": {"message": "nope"}})):
        r = checker.check(secret)
    assert r.is_active is None
    assert f"HTTP {status}" in (r.check_error or "")


@pytest.mark.parametrize("checker,secret", [
    (OpenAIChecker(), "sk-x"), (StripeChecker(), "sk_live_x"), (NpmChecker(), "npm_x"),
    (SendGridChecker(), "SG.x"), (AnthropicChecker(), "sk-ant-x"), (HuggingFaceChecker(), "hf_x"),
    (GitLabChecker(), "glpat-x"), (DigitalOceanChecker(), "dop_v1_x"),
])
def test_401_is_inactive(checker, secret):
    with patch("httpx.get", return_value=resp(401)):
        assert checker.check(secret).is_active is False


def test_twilio_429_is_unverified_and_suspended_account_is_not_active():
    with patch("httpx.get", return_value=resp(429)):
        r = TwilioChecker().check("ACfake:tok")
    assert r.is_active is None and "HTTP 429" in r.check_error
    with patch("httpx.get", return_value=resp(200, {"status": "suspended", "friendly_name": "X"})):
        r = TwilioChecker().check("ACfake:tok")
    assert r.is_active is False and "ACTIVE" not in r.risk_summary


def test_retryable_status_is_retried_then_reported():
    calls = []

    def fake_get(*a, **k):
        calls.append(1)
        return resp(429)

    with patch("httpx.get", side_effect=fake_get), patch("time.sleep"):
        r = OpenAIChecker().check_with_retry("sk-x")
    assert len(calls) == OpenAIChecker.MAX_RETRIES
    assert r.is_active is None


# --------------------------------------------------------------------------
# Stripe key modes
# --------------------------------------------------------------------------

def test_stripe_test_key_is_labelled_test_and_never_escalated():
    f = finding(SecretType.STRIPE_TEST_SECRET, Severity.LOW)
    with patch("httpx.get", return_value=resp(200, {"available": [{"amount": 100, "currency": "usd"}]})):
        out = run_blast_radius(f, "sk_test_" + "a" * 24)
    assert "TEST" in out.blast_radius.risk_summary and "LIVE" not in out.blast_radius.risk_summary
    assert out.severity == Severity.LOW


def test_stripe_live_key_is_labelled_live_and_critical():
    f = finding(SecretType.STRIPE_SECRET, Severity.CRITICAL)
    with patch("httpx.get", return_value=resp(200, {"available": []})):
        out = run_blast_radius(f, "sk_live_" + "a" * 24)
    assert "LIVE" in out.blast_radius.risk_summary and out.severity == Severity.CRITICAL


def test_stripe_restricted_key_403_is_still_a_live_key():
    with patch("httpx.get", return_value=resp(403, {"error": {}})):
        r = StripeChecker().check("rk_live_" + "a" * 24)
    assert r.is_active is True


def test_publishable_keys_are_never_sent_to_stripe():
    assert SecretType.STRIPE_PUBLISHABLE not in NETWORK_SECRET_TYPES
    assert SecretType.STRIPE_TEST_PUBLISHABLE not in NETWORK_SECRET_TYPES


# --------------------------------------------------------------------------
# Google: every realistic "invalid key" shape
# --------------------------------------------------------------------------

MAPS_INVALID = resp(200, {"error_message": "The provided API key is invalid.", "results": [], "status": "REQUEST_DENIED"})
YT_INVALID = resp(400, {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
                                   "errors": [{"reason": "badRequest"}], "status": "INVALID_ARGUMENT",
                                   "details": [{"reason": "API_KEY_INVALID"}]}})
LEGACY_INVALID = resp(403, {"error": {"errors": [{"reason": "keyInvalid"}]}})


def test_google_invalid_key_shapes_are_inactive():
    with patch("aysal_scan.blast_radius.google.httpx.get", side_effect=[MAPS_INVALID, YT_INVALID]):
        assert GoogleChecker().check("AIza" + "x" * 35).is_active is False
    with patch("aysal_scan.blast_radius.google.httpx.get", side_effect=[LEGACY_INVALID, LEGACY_INVALID]):
        assert GoogleChecker().check("AIza" + "x" * 35).is_active is False


def test_google_valid_but_api_not_enabled_is_still_active():
    denied = resp(200, {"status": "REQUEST_DENIED", "error_message": "This API project is not authorized to use this API."})
    with patch("aysal_scan.blast_radius.google.httpx.get", side_effect=[denied, resp(403, {"error": {"errors": [{"reason": "accessNotConfigured"}]}})]):
        assert GoogleChecker().check("AIza" + "x" * 35).is_active is True


def test_google_working_key_lists_enabled_apis():
    with patch("aysal_scan.blast_radius.google.httpx.get", side_effect=[resp(200, {"status": "OK"}), YT_INVALID]):
        r = GoogleChecker().check("AIza" + "x" * 35)
    assert r.is_active is True and "Maps Geocoding" in r.permissions[0]


# --------------------------------------------------------------------------
# AWS
# --------------------------------------------------------------------------

def test_aws_temporary_key_is_unverifiable_not_revoked():
    r = AWSChecker().check("ASIA" + "A" * 16 + ":" + "s" * 40)
    assert r.is_active is None and r.check_performed is False
    assert "session token" in r.risk_summary


def _aws_session(policies, arn="arn:aws:iam::123456789012:user/bot"):
    session = MagicMock()
    sts, iam = MagicMock(), MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": arn}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": [{"PolicyName": p} for p in policies]}
    iam.list_user_policies.return_value = {"PolicyNames": []}
    iam.list_groups_for_user.return_value = {"Groups": []}
    session.client.side_effect = lambda name, **kw: sts if name == "sts" else iam
    return session


def test_aws_amplify_admin_policy_is_not_full_admin():
    with patch("boto3.Session", return_value=_aws_session(["AdministratorAccess-Amplify"])):
        r = AWSChecker().check("AKIA" + "A" * 16 + ":" + "s" * 40)
    assert r.privilege is None and "ALL AWS services" not in r.resources


def test_aws_exact_administrator_access_is_admin():
    with patch("boto3.Session", return_value=_aws_session(["AdministratorAccess"])):
        r = AWSChecker().check("AKIA" + "A" * 16 + ":" + "s" * 40)
    assert r.privilege == "admin"


def test_aws_root_credentials_are_admin():
    with patch("boto3.Session", return_value=_aws_session([], arn="arn:aws:iam::123456789012:root")):
        r = AWSChecker().check("AKIA" + "A" * 16 + ":" + "s" * 40)
    assert r.privilege == "admin" and "ROOT" in r.risk_summary


def test_aws_client_uses_real_timeouts():
    session = _aws_session([])
    with patch("boto3.Session", return_value=session):
        AWSChecker().check("AKIA" + "A" * 16 + ":" + "s" * 40)
    cfg = session.client.call_args_list[0].kwargs["config"]
    assert cfg.connect_timeout == AWSChecker.TIMEOUT and cfg.read_timeout == AWSChecker.TIMEOUT


# --------------------------------------------------------------------------
# Provider routing (end to end: scanner -> dispatcher)
# --------------------------------------------------------------------------

def test_anthropic_key_goes_to_anthropic_never_to_openai():
    key = "sk-ant-api03-" + "Ab1_" * 23
    findings, raw = scan_content("K=" + key, "x.env")
    f = [x for x in findings if x.secret_type == SecretType.ANTHROPIC_KEY][0]
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        return resp(401)

    with patch("httpx.get", side_effect=fake_get):
        out = run_blast_radius(f, raw[f.id])
    assert seen == ["https://api.anthropic.com/v1/models"]
    assert out.blast_radius.is_active is False


def test_gcp_service_account_reaches_the_checker_with_parseable_metadata():
    import json
    sa = json.dumps({
        "type": "service_account", "project_id": "proj-a", "private_key_id": "k1",
        "client_email": "sa@proj-a.iam.gserviceaccount.com",
        "private_key": "-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" * 2 + "\n-----END PRIVATE KEY-----\n",
    }, indent=2)
    findings, raw = scan_content(sa, "sa.json")
    out = run_blast_radius(findings[0], raw[findings[0].id])
    assert "sa@proj-a.iam.gserviceaccount.com" in out.blast_radius.account_info
    assert out.severity == Severity.CRITICAL  # unverified service-account key stays CRITICAL


# --------------------------------------------------------------------------
# Severity rules
# --------------------------------------------------------------------------

def test_revoked_key_drops_to_low():
    f = finding(SecretType.GITHUB_TOKEN, Severity.HIGH)
    with patch("httpx.get", return_value=resp(401)):
        out = run_blast_radius(f, "ghp_x")
    assert out.severity == Severity.LOW and "verified-revoked" in out.tags


def test_active_key_with_admin_scope_becomes_critical():
    f = finding(SecretType.GITHUB_TOKEN, Severity.HIGH)
    ok = resp(200, {"login": "u"}, {"X-OAuth-Scopes": "repo, delete_repo, admin:org"})
    with patch("httpx.get", side_effect=[ok, resp(200, {}, {})]):
        out = run_blast_radius(f, "ghp_x")
    assert out.severity == Severity.CRITICAL and out.blast_radius.privilege == "admin"


def test_active_key_with_write_scope_stays_high():
    f = finding(SecretType.GITHUB_TOKEN, Severity.HIGH)
    ok = resp(200, {"login": "u"}, {"X-OAuth-Scopes": "repo"})
    with patch("httpx.get", side_effect=[ok, resp(200, {}, {})]):
        assert run_blast_radius(f, "ghp_x").severity == Severity.HIGH


def test_fine_grained_github_token_is_not_reported_as_having_no_scopes():
    ok = resp(200, {"login": "u"}, {})   # no X-OAuth-Scopes header
    with patch("httpx.get", side_effect=[ok, resp(200, {}, {})]):
        r = GitHubChecker().check("github_pat_x")
    assert "fine-grained" in r.risk_summary.lower() and "none" not in r.risk_summary.lower()


def test_unverified_finding_keeps_severity_and_is_tagged():
    f = finding(SecretType.OPENAI_KEY, Severity.HIGH)
    with patch("httpx.get", return_value=resp(429)), patch("time.sleep"):
        out = run_blast_radius(f, "sk-x")
    assert out.severity == Severity.HIGH and "unverified" in out.tags


def test_jwt_without_expiry_is_not_escalated_to_high():
    import base64, json

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    tok = f"{seg({'alg': 'HS256'})}.{seg({'sub': 'u'})}.{'A' * 43}"
    f = finding(SecretType.JWT, Severity.MEDIUM)
    assert run_blast_radius(f, tok).severity == Severity.MEDIUM


def test_remediation_is_provider_specific_for_unverifiable_types():
    f = finding(SecretType.DOCKERHUB_TOKEN, Severity.HIGH)
    out = run_blast_radius(f, "dckr_pat_x")
    assert "Docker Hub" in out.blast_radius.remediation


def test_input_finding_is_not_mutated():
    f = finding(SecretType.GITHUB_TOKEN, Severity.HIGH)
    with patch("httpx.get", return_value=resp(401)):
        run_blast_radius(f, "ghp_x")
    assert f.blast_radius is None and f.severity == Severity.HIGH


# --------------------------------------------------------------------------
# Concurrency / rate limiting
# --------------------------------------------------------------------------

def test_non_network_findings_never_sleep():
    findings = [finding(SecretType.HIGH_ENTROPY, Severity.INFO, id=f"id{i}") for i in range(300)]
    start = time.monotonic()
    out = run_blast_radius_concurrent(findings, {})
    assert time.monotonic() - start < 5          # v1 needed ~hours for 300 findings
    assert len(out) == 300


def test_results_keep_input_order():
    findings = [finding(SecretType.OPENAI_KEY, Severity.HIGH, id=f"id{i}") for i in range(6)]
    with patch("httpx.get", return_value=resp(401)):
        out = run_blast_radius_concurrent(findings, {}, interval=0)
    assert [f.id for f in out] == [f.id for f in findings]


def test_same_provider_requests_are_spaced_out():
    findings = [finding(SecretType.OPENAI_KEY, Severity.HIGH, id=f"id{i}") for i in range(4)]
    stamps = []

    def fake_get(*a, **k):
        stamps.append(time.monotonic())
        return resp(401)

    with patch("httpx.get", side_effect=fake_get):
        run_blast_radius_concurrent(findings, {}, interval=0.15)
    stamps.sort()
    assert all(b - a >= 0.12 for a, b in zip(stamps, stamps[1:]))


def test_progress_callback_reaches_total():
    findings = [finding(SecretType.HIGH_ENTROPY, Severity.INFO, id=f"id{i}") for i in range(3)]
    seen = []
    run_blast_radius_concurrent(findings, {}, on_progress=lambda d, t: seen.append((d, t)))
    assert seen[-1] == (3, 3)


def test_needs_network_matches_checker_table():
    assert needs_network(finding(SecretType.GITHUB_TOKEN))
    assert not needs_network(finding(SecretType.JWT))
    assert not needs_network(finding(SecretType.PRIVATE_KEY))


# --------------------------------------------------------------------------
# Risk score
# --------------------------------------------------------------------------

TODAY = date(2026, 10, 22)


def br(active, privilege=None, **kw):
    return BlastRadiusResult(is_active=active, check_performed=True, privilege=privilege, **kw)


def test_live_admin_key_scores_far_higher_than_unverified():
    live = finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL, blast_radius=br(True, "admin"))
    unknown = finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL)
    assert score_finding(live, TODAY)[0] > score_finding(unknown, TODAY)[0] + 25


def test_revoked_key_is_capped_low():
    f = finding(SecretType.AWS_ACCESS_KEY, Severity.LOW, blast_radius=br(False))
    assert score_finding(f, TODAY)[0] <= 12


def test_history_only_leak_scores_lower_than_present_leak():
    now = finding(commit_hash="abc1234", commit_date="2026-10-01", in_head=True)
    gone = finding(commit_hash="abc1234", commit_date="2026-10-01", in_head=False)
    assert score_finding(now, TODAY)[0] > score_finding(gone, TODAY)[0]


def test_long_exposure_adds_points():
    old = finding(commit_hash="a", commit_date="2024-01-01", in_head=True)
    new = finding(commit_hash="a", commit_date="2026-10-20", in_head=True)
    assert score_finding(old, TODAY)[0] == score_finding(new, TODAY)[0] + 10


def test_example_file_lowers_score_and_is_explained():
    plain = finding()
    example = finding(tags=["example-file"])
    s1, _ = score_finding(plain, TODAY)
    s2, factors = score_finding(example, TODAY)
    assert s1 - s2 == 25 and any("example" in f for f in factors)


def test_score_is_clamped_and_every_factor_is_listed():
    f = finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL, blast_radius=br(True, "admin"),
                commit_hash="a", commit_date="2020-01-01", in_head=True)
    f.locations = [MagicMock()]
    score, factors = score_finding(f, TODAY)
    assert 0 <= score <= 100 and len(factors) >= 5


def test_apply_scores_sets_fields_in_place():
    fs = apply_scores([finding(), finding(id="y" * 8)], TODAY)
    assert all(f.risk_score is not None and f.risk_factors for f in fs)
