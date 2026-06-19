"""
git_utils.py — git-aware scanning helpers.

scan_staged: uses raw git commands instead of GitPython's diff API,
which is unreliable on Windows for staged (never-committed) files:
  - git diff --cached --name-only  → list of staged file paths
  - git show :<path>               → staged file content from object store
  Fresh-repo fallback: enumerate index entries directly.

scan_commits: parent.diff(commit) direction so d.deleted_file reflects
what actually happened in the commit, not its inverse.
"""
from __future__ import annotations

from pathlib import Path

import git

from aysal_scan.models import Finding
from aysal_scan.scanner.file_scanner import scan_content, _should_skip, load_ignore_patterns_for_root

def scan_staged(repo_path: Path) -> tuple[list[Finding], dict[str, str], int]:
    """
    Scan staged (git add) changes only.
    Safe on fresh repos with no commits.
    """
    try:
        repo = git.Repo(repo_path)
        load_ignore_patterns_for_root(repo_path)

        # Step 1 — get list of staged (added/modified) file paths via git directly.
        # --diff-filter=ACMRT excludes deletions so we never try to scan removed files.
        try:
            output = repo.git.diff(
                "--cached", "--name-only", "--diff-filter=ACMRT"
            )
            staged_paths = [p.strip() for p in output.splitlines() if p.strip()]
        except Exception:
            # Fresh repo with no HEAD — git diff --cached fails.
            # Fall back to all stage-0 entries in the index.
            staged_paths = [
                path
                for (path, stage) in repo.index.entries.keys()
                if stage == 0
            ]

        findings: list[Finding] = []
        raw_values: dict[str, str] = {}

        # Step 2 — read each staged file's content directly from the git object store.
        for file_path in staged_paths:
            try:
                content = repo.git.show(f":{file_path}")
                if not content:
                    continue
            except Exception:
                continue

            f, r = scan_content(content, file_path)
            findings.extend(f)
            raw_values.update(r)

        return findings, raw_values, len(staged_paths)

    except Exception:
        return [], {}, 0


def scan_commits(
    repo_path: Path,
    n_commits: int | None = None,
) -> tuple[list[Finding], dict[str, str], int, int, bool]:
    """
    Scan git history by diffing each commit against its parent (added lines only).

    Diff direction: parent.diff(commit) — produces a diff from parent to commit,
    so d.new_file / d.deleted_file reflect what actually happened IN that commit.

    Returns (findings, raw_values, files_changed, commits_scanned).
    """
    try:
        repo = git.Repo(repo_path)
        import time
        _git_start = time.monotonic()
        _GIT_TIME_BUDGET = 120  # seconds — safety valve for huge histories
        all_commits = []
        for c in repo.iter_commits():
            all_commits.append(c)
            if time.monotonic() - _git_start > _GIT_TIME_BUDGET:
                break
        partial_history = n_commits is not None and len(all_commits) > n_commits
        commits = all_commits[:n_commits] if n_commits is not None else all_commits

        all_findings: list[Finding] = []
        all_raw_values: dict[str, str] = {}
        seen_ids: set[str] = set()
        files_changed = 0

        for commit in commits:
            commit_hash = commit.hexsha[:7]
            commit_date = commit.committed_datetime.strftime("%Y-%m-%d")

            try:
                if commit.parents:
                    # Correct direction: parent → commit = what was added/changed
                    diffs = commit.parents[0].diff(commit, create_patch=True)
                else:
                    # Root commit — compare against empty tree
                    diffs = commit.diff(git.NULL_TREE, create_patch=True)
            except Exception:
                continue

            for d in diffs:
                if getattr(d, "deleted_file", False):
                    continue
                files_changed += 1
                try:
                    patch_text = (
                        d.diff.decode("utf-8", errors="ignore") if d.diff else ""
                    )
                    added_lines = "\n".join(
                        line[1:]
                        for line in patch_text.splitlines()
                        if line.startswith("+") and not line.startswith("+++")
                    )
                    if not added_lines:
                        continue

                    file_path = d.b_path or d.a_path or "unknown"
                    if _should_skip(Path(file_path)):
                        continue
                    findings, raw_values = scan_content(
                        added_lines,
                        file_path,
                        commit_hash=commit_hash,
                        commit_date=commit_date,
                    )
                    for f in findings:
                        if f.id not in seen_ids:
                            seen_ids.add(f.id)
                            all_findings.append(f)
                            all_raw_values[f.id] = raw_values.get(f.id, "")
                except Exception:
                    continue

        return all_findings, all_raw_values, files_changed, len(commits), partial_history

    except Exception:
        return [], {}, 0, 0, False