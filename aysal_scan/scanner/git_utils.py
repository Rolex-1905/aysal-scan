"""Git-aware scanning: staged changes and commit history.

Behaviour guarantees (v2)
-------------------------
* Never fails open: a path that is not a git repository raises ``GitScanError``
  instead of returning "0 findings".
* Line numbers are real file line numbers (parsed from diff hunks), not positions
  inside a concatenated blob of added lines.
* History is walked oldest -> newest, so the *first* commit that introduced a secret
  is the primary location and later re-appearances (and merge commits) become extra
  locations. ``--full-history`` walks every ref, not only HEAD.
* Staged scans honour the same skip rules and ``AysalScanignore`` as directory scans
  and examine only the lines being added.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import git

from aysal_scan.models import Finding, Location
from aysal_scan.scanner.file_scanner import (
    _should_skip,
    load_ignore_patterns_for_root,
    scan_content,
)


class GitScanError(RuntimeError):
    """Raised when a git operation cannot be performed (not a repo, git missing, ...)."""


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _open_repo(repo_path: Path) -> git.Repo:
    try:
        return git.Repo(repo_path, search_parent_directories=True)
    except (git.InvalidGitRepositoryError, git.NoSuchPathError) as exc:
        raise GitScanError(f"Not a git repository: {repo_path}") from exc
    except git.GitCommandNotFound as exc:
        raise GitScanError("The 'git' executable was not found on PATH") from exc


def _repo_root(repo: git.Repo) -> Path:
    return Path(repo.working_tree_dir or repo.git_dir)


def parse_added_lines(patch_text: str) -> list[tuple[int, str]]:
    """Return ``[(real_line_number, text)]`` for every added line in a single-file patch."""
    added: list[tuple[int, str]] = []
    new_line: Optional[int] = None
    for line in patch_text.split("\n"):
        hunk = _HUNK_RE.match(line)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if new_line is None:
            continue
        if line.startswith("+"):
            added.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-") or line.startswith("\\"):
            continue
        else:
            new_line += 1
    return added


def parse_multi_file_diff(diff_text: str) -> dict[str, list[tuple[int, str]]]:
    """Parse ``git diff`` output (many files) into ``{path: [(line_no, text), ...]}``."""
    files: dict[str, list[tuple[int, str]]] = {}
    path: Optional[str] = None
    new_line: Optional[int] = None
    for line in diff_text.split("\n"):
        if line.startswith("diff --git "):
            path, new_line = None, None
            continue
        if new_line is None and line.startswith("+++ "):
            target = line[4:].rstrip("\t")
            if target == "/dev/null":
                path = None
            else:
                path = target[2:] if target.startswith("b/") else target
                files.setdefault(path, [])
            continue
        hunk = _HUNK_RE.match(line)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if path is None or new_line is None:
            continue
        if line.startswith("+"):
            files[path].append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-") or line.startswith("\\"):
            continue
        else:
            new_line += 1
    return files


def _scan_added(path: str, added: list[tuple[int, str]], commit_hash=None, commit_date=None):
    content = "\n".join(text for _, text in added)
    line_map = [n for n, _ in added]
    return scan_content(content, path, line_map=line_map,
                        commit_hash=commit_hash, commit_date=commit_date)


# ---------------------------------------------------------------------------
# Staged changes (pre-commit)
# ---------------------------------------------------------------------------

def scan_staged(repo_path: Path):
    """Scan lines being added in the index. Returns ``(findings, raw_values, staged_file_count)``."""
    repo = _open_repo(Path(repo_path))
    try:
        load_ignore_patterns_for_root(_repo_root(repo))
        try:
            diff_text = repo.git.execute(
                ["git", "-c", "core.quotepath=false", "diff", "--cached", "--unified=0",
                 "--no-color", "--no-ext-diff", "--diff-filter=ACMRT"],
                stdout_as_string=True,
            )
        except git.GitCommandError as exc:
            raise GitScanError(f"git diff --cached failed: {exc}") from exc

        per_file = parse_multi_file_diff(diff_text)
        findings: list[Finding] = []
        raw_values: dict[str, str] = {}
        for file_path, added in per_file.items():
            if not added or _should_skip(Path(file_path)):
                continue
            f, r = _scan_added(file_path, added)
            findings.extend(f)
            raw_values.update(r)
        return findings, raw_values, len(per_file)
    finally:
        repo.close()


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

@dataclass
class HistoryResult:
    findings: list[Finding] = field(default_factory=list)
    raw_values: dict[str, str] = field(default_factory=dict)
    files_changed: int = 0
    commits_scanned: int = 0
    partial_history: bool = False
    warnings: list[str] = field(default_factory=list)


def _iter_commits(repo: git.Repo, n_commits: Optional[int], all_refs: bool):
    """Return (commits oldest->newest, more_history_exists)."""
    try:
        if n_commits:
            newest_first = list(repo.iter_commits(max_count=n_commits + 1))
            more = len(newest_first) > n_commits
            return list(reversed(newest_first[:n_commits])), more
        kwargs = {"all": True} if all_refs else {}
        return list(repo.iter_commits(topo_order=True, reverse=True, **kwargs)), False
    except ValueError:
        return [], False  # repository has no commits yet


def _annotate_in_head(repo: git.Repo, findings: list[Finding], raw_values: dict[str, str]) -> None:
    """Mark whether each secret is still present at HEAD (history-only leaks are lower risk)."""
    try:
        repo.head.commit  # raises ValueError on an empty repo
    except ValueError:
        return
    cache: dict[str, Optional[str]] = {}

    def head_text(path: str) -> Optional[str]:
        if path not in cache:
            try:
                cache[path] = repo.git.show(f"HEAD:{path}")
            except (git.GitCommandError, UnicodeDecodeError):
                cache[path] = None
        return cache[path]

    for f in findings[:2000]:
        raw = raw_values.get(f.id, "")
        needle = raw.split(":", 1)[0] if raw.startswith(("AKIA", "ASIA")) else raw
        if not needle or len(needle) < 8 or f.secret_type.value in ("Private Key", "GCP Service Account"):
            continue
        paths = [f.file_path] + [loc.file_path for loc in f.locations]
        texts = [head_text(p) for p in dict.fromkeys(paths)]
        f.in_head = any(t is not None and needle in t for t in texts)


def scan_commits_ex(
    repo_path: Path,
    n_commits: Optional[int] = None,
    all_refs: bool = False,
    max_seconds: Optional[float] = None,
) -> HistoryResult:
    repo = _open_repo(Path(repo_path))
    result = HistoryResult()
    try:
        load_ignore_patterns_for_root(_repo_root(repo))
        commits, more = _iter_commits(repo, n_commits, all_refs)
        result.partial_history = more
        started = time.monotonic()
        by_id: dict[str, Finding] = {}
        failed_commits = 0

        for commit in commits:
            if max_seconds is not None and time.monotonic() - started > max_seconds:
                result.partial_history = True
                result.warnings.append(
                    f"Stopped after {max_seconds:.0f}s; {len(commits) - result.commits_scanned} "
                    "newer commit(s) were not scanned."
                )
                break
            result.commits_scanned += 1
            commit_hash = commit.hexsha[:7]
            commit_date = commit.committed_datetime.strftime("%Y-%m-%d")
            try:
                diffs = (
                    commit.parents[0].diff(commit, create_patch=True)
                    if commit.parents
                    else commit.diff(git.NULL_TREE, create_patch=True)
                )
            except (git.GitCommandError, ValueError):
                failed_commits += 1
                continue

            for d in diffs:
                if getattr(d, "deleted_file", False) or not d.diff:
                    continue
                result.files_changed += 1
                file_path = d.b_path or d.a_path or "unknown"
                if _should_skip(Path(file_path)):
                    continue
                added = parse_added_lines(d.diff.decode("utf-8", errors="ignore"))
                if not added:
                    continue
                findings, raw_values = _scan_added(file_path, added, commit_hash, commit_date)
                for f in findings:
                    primary = by_id.get(f.id)
                    if primary is None:
                        by_id[f.id] = f
                        result.findings.append(f)
                        result.raw_values[f.id] = raw_values.get(f.id, "")
                    else:
                        loc = Location(file_path=f.file_path, line_number=f.line_number,
                                       commit_hash=commit_hash, commit_date=commit_date)
                        known = {(l.file_path, l.line_number, l.commit_hash) for l in primary.locations}
                        if (loc.file_path, loc.line_number, loc.commit_hash) not in known and not (
                            loc.file_path == primary.file_path
                            and loc.line_number == primary.line_number
                            and loc.commit_hash == primary.commit_hash
                        ):
                            primary.locations.append(loc)

        if failed_commits:
            result.warnings.append(f"{failed_commits} commit(s) could not be diffed and were skipped.")
        _annotate_in_head(repo, result.findings, result.raw_values)
        return result
    finally:
        repo.close()


def scan_commits(repo_path: Path, n_commits: Optional[int] = None, all_refs: bool = False):
    """Backward-compatible wrapper.

    Returns ``(findings, raw_values, files_changed, commits_scanned, partial_history)``.
    """
    r = scan_commits_ex(repo_path, n_commits=n_commits, all_refs=all_refs)
    return r.findings, r.raw_values, r.files_changed, r.commits_scanned, r.partial_history
