"""The live-verification script must never leak a credential and must judge verdicts correctly."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import live_verify as lv  # noqa: E402

from aysal_scan.models import BlastRadiusResult  # noqa: E402

SECRET = "ghp_SUPER_SECRET_TOKEN_VALUE_123456789"


def fake(result):
    return lambda name, secret: result


def active(**kw):
    return BlastRadiusResult(is_active=True, check_performed=True, privilege="read", account_info="GitHub user: me", **kw)


def test_status_mapping():
    assert lv.status_of(active()) == "ACTIVE"
    assert lv.status_of(BlastRadiusResult(is_active=False, check_performed=True)) == "REVOKED"
    assert lv.status_of(BlastRadiusResult(is_active=None, check_performed=True)) == "UNVERIFIED"
    assert lv.status_of(BlastRadiusResult(is_active=True, check_performed=False)) == "UNVERIFIED"


def test_credentials_are_never_printed(monkeypatch, capsys):
    monkeypatch.setattr(lv, "run_one", fake(active(check_error="boom")))
    code = lv.main(["--only", "github"], environ={"AYSAL_LIVE_GITHUB": SECRET})
    out = capsys.readouterr()
    assert code == 0 and "ACTIVE" in out.out and "privilege=read" in out.out
    assert SECRET not in out.out and SECRET not in out.err and "SECRET_TOKEN" not in out.out


def test_expect_active_ok_and_mismatch(monkeypatch, capsys):
    monkeypatch.setattr(lv, "run_one", fake(active()))
    assert lv.main(["--only", "github", "--expect", "active"], environ={"AYSAL_LIVE_GITHUB": SECRET}) == 0
    assert "OK" in capsys.readouterr().out
    assert lv.main(["--only", "github", "--expect", "revoked"], environ={"AYSAL_LIVE_GITHUB": SECRET}) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_unverified_never_satisfies_an_expectation(monkeypatch):
    monkeypatch.setattr(lv, "run_one", fake(BlastRadiusResult(is_active=None, check_performed=True, check_error="HTTP 500")))
    for expect in ("active", "revoked"):
        assert lv.main(["--only", "github", "--expect", expect], environ={"AYSAL_LIVE_GITHUB": SECRET}) == 1


def test_no_credentials_is_exit_2_not_a_false_pass(capsys):
    assert lv.main([], environ={}) == 2
    assert "No credentials found" in capsys.readouterr().err


def test_unknown_provider_is_exit_2(capsys):
    assert lv.main(["--only", "nope"], environ={}) == 2


def test_blank_variable_is_treated_as_unset():
    assert lv.main(["--only", "github"], environ={"AYSAL_LIVE_GITHUB": "   "}) == 2


def test_only_providers_with_credentials_are_tested(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(lv, "run_one", lambda name, secret: (calls.append(name), active())[1])
    lv.main([], environ={"AYSAL_LIVE_GITHUB": "a", "AYSAL_LIVE_NPM": "b"})
    assert sorted(calls) == ["github", "npm"]


def test_list_shows_every_provider_and_its_cost(capsys):
    assert lv.main(["--list"], environ={}) == 0
    out = capsys.readouterr().out
    for name in lv.PROVIDERS:
        assert name in out
    assert "paid" in out and "free" in out


def test_every_provider_has_a_variable_and_a_working_factory():
    for name, (var, factory, fmt, cost) in lv.PROVIDERS.items():
        assert var.startswith("AYSAL_LIVE_") and fmt and cost
        assert hasattr(factory(), "check_with_retry")
