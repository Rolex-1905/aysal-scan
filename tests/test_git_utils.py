"""
git_utils tests — creates real temp git repos using pytest's tmp_path fixture.

Windows fix: GitPython holds .git/ file handles open on Windows, which prevents
tempfile.TemporaryDirectory from cleaning up. Using tmp_path (pytest manages cleanup)
plus explicit repo.close() + gc.collect() before assertions avoids all PermissionErrors.
"""
from __future__ import annotations

import gc
from pathlib import Path

import git
import pytest

from aysal_scan.scanner.git_utils import scan_staged, scan_commits
from aysal_scan.models import SecretType

_STRIPE_LIVE = "sk" + "_live_" + "a" * 24

def _init_repo(tmp: Path) -> git.Repo:
    repo = git.Repo.init(str(tmp))
    with repo.config_writer() as cw:
        cw.set_value("user", "name", "Test User")
        cw.set_value("user", "email", "test@example.com")
    return repo


def _commit(repo: git.Repo, file_name: str, content: str, message: str = "commit") -> None:
    path = Path(repo.working_dir) / file_name
    path.write_text(content, encoding="utf-8")
    repo.index.add([file_name])
    repo.index.commit(message)


def _close(repo: git.Repo) -> None:
    """Explicitly release all file handles — required on Windows before cleanup."""
    repo.close()
    gc.collect()


# ---------------------------------------------------------------------------
# scan_staged
# ---------------------------------------------------------------------------
class TestScanStaged:
    def test_fresh_repo_no_crash(self, tmp_path):
        """scan_staged must not crash on a repo with no commits (no HEAD)."""
        repo = _init_repo(tmp_path)
        secret_file = tmp_path / "secret.env"
        secret_file.write_text("STRIPE_KEY=" + "sk" + "_live_" + "a"*24 + "\n", encoding="utf-8")
        repo.index.add(["secret.env"])
        try:
            findings, raw, count = scan_staged(tmp_path)
            assert isinstance(findings, list)
            assert isinstance(raw, dict)
        finally:
            _close(repo)

    def test_staged_secret_is_found(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "readme.md", "# hello", "init")
        secret_file = tmp_path / "creds.env"
        secret_file.write_text("STRIPE_KEY=" + "sk" + "_live_" + "a"*24 + "\n", encoding="utf-8")
        repo.index.add(["creds.env"])
        try:
            findings, raw, _ = scan_staged(tmp_path)
            types = [f.secret_type.value for f in findings]
            assert any("Stripe" in t for t in types)
        finally:
            _close(repo)

    def test_staged_clean_file_no_findings(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "readme.md", "# hello", "init")
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("print('hello world')\n", encoding="utf-8")
        repo.index.add(["clean.py"])
        try:
            findings, _, _ = scan_staged(tmp_path)
            assert findings == []
        finally:
            _close(repo)


# ---------------------------------------------------------------------------
# scan_commits
# ---------------------------------------------------------------------------
class TestScanCommits:
    def test_finds_secret_in_commit(self, tmp_path):
        repo = _init_repo(tmp_path)
        _commit(repo, "creds.env", "STRIPE_KEY=" + "sk" + "_live_" + "a"*24 + "\n", "add creds")
        try:
            findings, raw, files, commits, _ = scan_commits(tmp_path, n_commits=1)
            assert any("Stripe" in f.secret_type.value for f in findings)
        finally:
            _close(repo)

    def test_root_commit_no_crash(self, tmp_path):
        """Root commit has no parent — must not crash."""
        repo = _init_repo(tmp_path)
        _commit(repo, "readme.md", "# hello", "root commit")
        try:
            findings, raw, files, commits, _ = scan_commits(tmp_path)
            assert isinstance(findings, list)
        finally:
            _close(repo)

    def test_n_commits_limit_respected(self, tmp_path):
        repo = _init_repo(tmp_path)
        for i in range(5):
            _commit(repo, f"file{i}.txt", f"content {i}", f"commit {i}")
        try:
            _, _, _, commits_scanned, _ = scan_commits(tmp_path, n_commits=3)
            assert commits_scanned == 3
        finally:
            _close(repo)

    def test_deleted_file_not_scanned(self, tmp_path):
        """Secret deleted in the most recent commit should not appear when scanning only that commit."""
        repo = _init_repo(tmp_path)
        _commit(repo, "readme.md", "# hello", "init")
        _commit(repo, "creds.env", "STRIPE_KEY=" + "sk" + "_live_" + "a"*24 + "\n", "add")
        # Delete the secret file
        (tmp_path / "creds.env").unlink()
        repo.index.remove(["creds.env"])
        repo.index.commit("remove creds")
        try:
            # Scan only the deletion commit — added lines = nothing, deleted lines skipped
            findings, _, _, _, _ = scan_commits(tmp_path, n_commits=1)
            assert findings == []
        finally:
            _close(repo)

    def test_same_secret_two_commits_deduped(self, tmp_path):
        """Same secret value introduced twice (e.g. after rebase) → only 1 finding."""
        repo = _init_repo(tmp_path)
        _commit(repo, "a.env", "TOKEN=" + "sk" + "_live_" + "a"*24 + "\n", "first")
        _commit(repo, "b.env", "TOKEN=" + "sk" + "_live_" + "a"*24 + "\n", "second")
        try:
            findings, _, _, _, _ = scan_commits(tmp_path)
            stripe_findings = [f for f in findings if "Stripe" in f.secret_type.value]
            assert len(stripe_findings) == 1
        finally:
            _close(repo)

    def test_scan_commits_finds_secret(self, fake_git_repo_with_secret):
        from aysal_scan.scanner.git_utils import scan_commits
        findings, _, _, commits_scanned, _ = scan_commits(fake_git_repo_with_secret, n_commits=5)
        assert commits_scanned >= 1
        assert any(f.secret_type == SecretType.STRIPE_SECRET for f in findings)
