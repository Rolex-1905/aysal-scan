"""install-hook / uninstall-hook."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aysal_scan.cli import HOOK_MARKER, app

runner = CliRunner()
KEY = "sk_live_" + "a1B2c3D4" * 3


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@t.t")
    git(r, "config", "user.name", "t")
    return r


def hook_of(repo: Path) -> Path:
    return repo / ".git" / "hooks" / "pre-commit"


def test_install_creates_an_lf_terminated_marked_hook(repo):
    r = runner.invoke(app, ["install-hook", str(repo)])
    assert r.exit_code == 0
    data = hook_of(repo).read_bytes()
    assert HOOK_MARKER.encode() in data and b"\r\n" not in data and data.startswith(b"#!/bin/sh\n")
    if os.name != "nt":
        assert os.access(hook_of(repo), os.X_OK)


def test_install_is_idempotent(repo):
    runner.invoke(app, ["install-hook", str(repo)])
    first = hook_of(repo).read_text()
    assert runner.invoke(app, ["install-hook", str(repo)]).exit_code == 0
    assert hook_of(repo).read_text() == first


def test_foreign_hook_is_never_overwritten_without_force(repo):
    hook_of(repo).parent.mkdir(parents=True, exist_ok=True)
    hook_of(repo).write_text("#!/bin/sh\necho mine\n")
    r = runner.invoke(app, ["install-hook", str(repo)])
    assert r.exit_code == 2 and "--force" in r.output
    assert hook_of(repo).read_text() == "#!/bin/sh\necho mine\n"


def test_force_backs_up_and_uninstall_restores(repo):
    hook_of(repo).parent.mkdir(parents=True, exist_ok=True)
    hook_of(repo).write_text("#!/bin/sh\necho mine\n")
    assert runner.invoke(app, ["install-hook", str(repo), "--force"]).exit_code == 0
    assert HOOK_MARKER in hook_of(repo).read_text()
    assert (hook_of(repo).parent / "pre-commit.aysal-backup").exists()
    assert runner.invoke(app, ["uninstall-hook", str(repo)]).exit_code == 0
    assert hook_of(repo).read_text() == "#!/bin/sh\necho mine\n"


def test_uninstall_refuses_foreign_hooks_and_tolerates_none(repo):
    assert runner.invoke(app, ["uninstall-hook", str(repo)]).exit_code == 0
    hook_of(repo).parent.mkdir(parents=True, exist_ok=True)
    hook_of(repo).write_text("#!/bin/sh\necho mine\n")
    assert runner.invoke(app, ["uninstall-hook", str(repo)]).exit_code == 2
    assert hook_of(repo).exists()


def test_uninstall_removes_our_hook(repo):
    runner.invoke(app, ["install-hook", str(repo)])
    assert runner.invoke(app, ["uninstall-hook", str(repo)]).exit_code == 0
    assert not hook_of(repo).exists()


def test_non_repository_exits_2(tmp_path):
    assert runner.invoke(app, ["install-hook", str(tmp_path)]).exit_code == 2


def test_custom_hooks_path_is_respected(repo, tmp_path):
    custom = tmp_path / "myhooks"
    git(repo, "config", "core.hooksPath", str(custom))
    assert runner.invoke(app, ["install-hook", str(repo)]).exit_code == 0
    assert HOOK_MARKER in (custom / "pre-commit").read_text()
    assert not hook_of(repo).exists()


def test_install_works_from_a_subdirectory(repo):
    sub = repo / "pkg"
    sub.mkdir()
    assert runner.invoke(app, ["install-hook", str(sub)]).exit_code == 0
    assert hook_of(repo).exists()


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_hook_blocks_a_commit_that_adds_a_secret_and_allows_a_clean_one(repo):
    runner.invoke(app, ["install-hook", str(repo)])
    env = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    if shutil.which("aysal-scan", path=env["PATH"]) is None:
        pytest.skip("aysal-scan console script is not on PATH")

    (repo / "clean.txt").write_text("hello\n")
    git(repo, "add", "clean.txt")
    ok = subprocess.run(["sh", str(hook_of(repo))], cwd=repo, env=env, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr

    (repo / "leak.env").write_text(f"S={KEY}\n")
    git(repo, "add", "leak.env")
    bad = subprocess.run(["sh", str(hook_of(repo))], cwd=repo, env=env, capture_output=True, text=True)
    assert bad.returncode == 1


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_hook_fails_closed_when_the_scanner_is_missing(repo):
    runner.invoke(app, ["install-hook", str(repo)])
    sh = shutil.which("sh")
    env = {"PATH": str(Path(sh).parent)}   # a PATH that cannot contain aysal-scan
    if shutil.which("aysal-scan", path=env["PATH"]):
        pytest.skip("aysal-scan is on the minimal PATH")
    p = subprocess.run([sh, str(hook_of(repo))], cwd=repo, env=env, capture_output=True, text=True)
    assert p.returncode == 1 and "not installed" in p.stderr


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_hook_survives_a_legacy_codepage_output_pipe(repo):
    """Regression: on Windows, piped output used cp1252 and the scanner crashed on its own check
    mark, so the hook returned exit 1 (block) for a CLEAN commit."""
    runner.invoke(app, ["install-hook", str(repo)])
    env = {**os.environ, "PYTHONIOENCODING": "cp1252",
           "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    env.pop("PYTHONUTF8", None)
    if shutil.which("aysal-scan", path=env["PATH"]) is None:
        pytest.skip("aysal-scan console script is not on PATH")
    (repo / "clean.txt").write_text("hello\n")
    git(repo, "add", "clean.txt")
    ok = subprocess.run(["sh", str(hook_of(repo))], cwd=repo, env=env, capture_output=True)
    assert ok.returncode == 0, (ok.stdout + ok.stderr).decode("utf-8", "replace")
    assert b"Traceback" not in ok.stderr
