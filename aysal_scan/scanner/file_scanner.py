"""
file_scanner.py — scans individual files and string content for secrets.

Thread-safety: ignore patterns are stored in threading.local() so concurrent
scan_directory calls in different threads never clobber each other's patterns.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
import threading
from pathlib import Path

from aysal_scan.models import Finding, SecretType, Severity
from aysal_scan.scanner.entropy import is_high_entropy_secret
from aysal_scan.scanner.patterns import PATTERNS, GENERIC_DUMMY_VALUES

# ---------------------------------------------------------------------------
# Extensions that are never plain-text source code.
# Scanning these produces only false positives (high-entropy binary noise).
# ---------------------------------------------------------------------------
IGNORE_EXTENSIONS: frozenset[str] = frozenset({
    # --- Images & icons ---
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
    ".svg", ".ico", ".icns",
    # --- Fonts ---
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    # --- Audio / Video ---
    ".mp3", ".mp4", ".wav", ".ogg", ".avi", ".mov", ".mkv", ".flac",
    # --- Documents ---
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    # --- Archives ---
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z", ".tgz",
    # --- Compiled / binary ---
    ".exe", ".dll", ".so", ".dylib", ".bin", ".lib", ".a", ".o",
    ".class",           # Java bytecode
    ".pyc", ".pyo", ".pyd",   # Python bytecode
    ".elc",             # Emacs Lisp compiled
    ".beam",            # Erlang/Elixir compiled
    # --- Mobile ---
    ".apk", ".ipa", ".aab",
    # --- Certificates (binary formats — text PEM is scanned for private keys) ---
    ".p12", ".pfx", ".der",
    # --- Database files ---
    ".db", ".sqlite", ".sqlite3",
    # --- Lock files (dependency graphs, no user secrets) ---
    ".lock",
    # --- Minified / bundled JS & CSS (obfuscated, not secrets) ---
    ".min.js", ".min.css",
    # --- Source maps ---
    ".map",
})

# ---------------------------------------------------------------------------
# Path fragments — if any DIRECTORY component of a file's path matches one
# of these, the file is skipped. The filename itself is never checked here
# so that files like ".env" are scanned (only ".env/" directories are skipped).
# ---------------------------------------------------------------------------
IGNORE_PATH_FRAGMENTS: tuple[str, ...] = (
    # --- Version control ---
    ".git", ".svn", ".hg",

    # --- Python: virtual environments ---
    "venv", ".venv", "env", ".env",
    "virtualenv", ".virtualenv",
    "pyenv", ".pyenv",

    # --- Python: installed packages (never user code) ---
    "site-packages", "dist-packages",

    # --- Python: compiled bytecode ---
    "__pycache__",

    # --- Python: build & packaging ---
    ".eggs", ".tox", ".nox",
    "*.egg-info",

    # --- Node.js: dependencies ---
    "node_modules", "bower_components",
    ".npm", ".yarn", ".pnpm-store",

    # --- Node.js: lock files ---
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",

    # --- Build output (all languages) ---
    "dist", "build", "out", "output",
    "target",           # Java (Maven/Gradle), Rust (Cargo)
    "bin", "obj",       # C/C++, C#
    ".output",          # Nuxt 3
    ".next",            # Next.js
    ".nuxt",            # Nuxt 2
    ".svelte-kit",      # SvelteKit
    ".parcel-cache",    # Parcel
    "_site",            # Jekyll
    "public/build",     # Laravel Mix / Vite
    "htmlcov",          # Python coverage HTML report

    # --- Cache directories ---
    ".cache", ".turbo",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".eslintcache",

    # --- IDE & editor ---
    ".idea",            # JetBrains (IntelliJ, PyCharm, etc.)
    ".vscode",
    ".eclipse",
    ".settings",        # Eclipse project settings

    # --- Infrastructure-as-code: provider cache ---
    ".terraform",

    # --- Ruby: vendored gems ---
    "vendor/bundle", ".bundle",

    # --- Go: vendored dependencies ---
    "vendor",

    # --- iOS / macOS: CocoaPods ---
    "Pods",

    # --- Documentation build output ---
    "docs/_build",      # Sphinx
    "site",             # MkDocs
    "_book",            # GitBook

    # --- Test fixtures (intentional fake/revoked keys) ---
    "tests/fixtures", "test/fixtures",
    "spec/fixtures",
    "__fixtures__", "__mocks__",

    # --- Log & temp directories ---
    "logs", ".logs",
    "tmp", "temp", ".tmp",

    # --- Misc generated ---
    "CHANGELOG",
    ".nyc_output",      # Istanbul/NYC coverage
    "coverage",         # Generic coverage output dir
)

# ---------------------------------------------------------------------------
# AWS secret-key context scanner (pairs AKIA... with its secret access key)
# ---------------------------------------------------------------------------
_AWS_SECRET_KEY_RE = re.compile(
    r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*["\']?'
    r'([A-Za-z0-9/+=]{40})["\']?'
)

# ---------------------------------------------------------------------------
# Twilio auth-token context scanner (pairs AC... SID with its auth token)
# ---------------------------------------------------------------------------
_TWILIO_AUTH_TOKEN_RE = re.compile(
    r'(?:TWILIO_AUTH_TOKEN|auth_token|authToken)\s*[:=]\s*["\']?'
    r'([a-fA-F0-9]{32})["\']?'
)

# ---------------------------------------------------------------------------
# Thread-local ignore-pattern cache
# ---------------------------------------------------------------------------
_local = threading.local()


def _get_ignore_patterns() -> list[str]:
    return getattr(_local, "ignore_patterns", [])


def _load_ignore_patterns(root: Path) -> list[str]:
    """
    Walk upward from *root* looking for a AysalScanignore file,
    mirroring how git walks up for .gitignore.
    """
    search = root if root.is_dir() else root.parent
    while True:
        ignore_file = search / "AysalScanignore"
        if ignore_file.exists():
            lines = ignore_file.read_text(encoding="utf-8").splitlines()
            return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        parent = search.parent
        if parent == search:
            break
        search = parent
    return []


def load_ignore_patterns_for_root(root: Path) -> None:
    """Call once per scan to populate this thread's pattern cache."""
    _local.ignore_patterns = _load_ignore_patterns(root)


def _matches_ignore_pattern(path: Path) -> bool:
    path_str = str(path).replace("\\", "/")
    for pat in _get_ignore_patterns():
        if fnmatch.fnmatch(path_str, pat) or fnmatch.fnmatch(path.name, pat):
            return True
        if any(fnmatch.fnmatch(part, pat.rstrip("/")) for part in path.parts):
            return True
    return False


def _should_skip(path: Path) -> bool:
    # Only check DIRECTORY components (path.parts[:-1]) against ignore fragments,
    # never the filename itself. This means:
    #   - ".env" FILES are scanned (common secret location)
    #   - ".env/" DIRECTORIES are skipped (Python virtualenv)
    #   - System dirs like /tmp never trigger the list when relative paths are used
    dir_parts = set(path.parts[:-1])
    for fragment in IGNORE_PATH_FRAGMENTS:
        # Support multi-segment fragments like "vendor/bundle" or "public/build"
        if "/" in fragment or "\\" in fragment:
            if fragment.replace("\\", "/") in str(path).replace("\\", "/"):
                return True
        elif fragment in dir_parts:
            return True

    if path.suffix.lower() in IGNORE_EXTENSIONS:
        return True
    if path.name.endswith(".min.js") or path.name.endswith(".min.css"):
        return True
    if path.suffix == ".egg-info" or ".egg-info" in path.parts:
        return True
    if path.name.endswith(".d.ts"):
        return True
    if path.suffix == ".js" and any(
        p in path.name for p in (".chunk.", ".bundle.", ".min.")
    ):
        return True
    if _matches_ignore_pattern(path):
        return True
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _make_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Core scan function
# ---------------------------------------------------------------------------
def scan_content(
    content: str,
    file_path: str,
    commit_hash: str | None = None,
    commit_date: str | None = None,
) -> tuple[list[Finding], dict[str, str]]:
    """
    Scan a string for secrets.
    Returns (findings, raw_values) where raw_values maps finding_id → raw secret.
    Raw values are NEVER stored inside Finding objects.
    """
    findings: list[Finding] = []
    raw_values: dict[str, str] = {}
    seen_ids: set[str] = set()

    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):

        # ── Regex-pattern matching ──────────────────────────────────────────
        for pat in PATTERNS:
            for match in pat.pattern.finditer(line):
                value = match.group(pat.value_group)

                # Context-keyword gate for noisy patterns (Twilio, Heroku, generic)
                if pat.requires_context and pat.context_keywords:
                    if not any(kw.lower() in line.lower() for kw in pat.context_keywords):
                        continue

                # Allowlist check for generic password patterns
                if pat.value_group != 0:
                    if value.lower() in GENERIC_DUMMY_VALUES:
                        continue
                    # Skip strings that are too repetitive (e.g. "aaaaaaaa")
                    if len(set(value.lower())) < 4:
                        continue

                secret_id = _make_id(value)
                if secret_id in seen_ids:
                    continue
                seen_ids.add(secret_id)

                # ── AWS: try to pair key ID with its secret key ─────────────
                if pat.secret_type == SecretType.AWS_ACCESS_KEY:
                    ctx_start = max(0, line_no - 6)
                    ctx_end = min(len(lines), line_no + 5)
                    context_block = "\n".join(lines[ctx_start:ctx_end])
                    secret_match = _AWS_SECRET_KEY_RE.search(context_block)
                    raw_values[secret_id] = (
                        value + ":" + secret_match.group(1)
                        if secret_match
                        else value
                    )
                # ── Twilio: try to pair SID with its auth token ──────────────
                elif pat.secret_type == SecretType.TWILIO:
                    ctx_start = max(0, line_no - 6)
                    ctx_end = min(len(lines), line_no + 5)
                    context_block = "\n".join(lines[ctx_start:ctx_end])
                    token_match = _TWILIO_AUTH_TOKEN_RE.search(context_block)
                    raw_values[secret_id] = (
                        value + ":" + token_match.group(1)
                        if token_match
                        else value
                    )
                else:
                    raw_values[secret_id] = value

                findings.append(Finding(
                    id=secret_id,
                    secret_type=pat.secret_type,
                    severity=pat.default_severity,
                    file_path=file_path,
                    line_number=line_no,
                    commit_hash=commit_hash,
                    commit_date=commit_date,
                    masked_value=_mask(value),
                ))

        # ── Shannon entropy fallback ────────────────────────────────────────
        for token in re.findall(r'[A-Za-z0-9+/=_\-]{20,}', line):
            if not is_high_entropy_secret(token):
                continue
            secret_id = _make_id(token)
            if secret_id in seen_ids:
                continue
            # Skip tokens already caught by a named pattern
            if any(pat.pattern.search(token) for pat in PATTERNS):
                continue
            seen_ids.add(secret_id)
            raw_values[secret_id] = token
            findings.append(Finding(
                id=secret_id,
                secret_type=SecretType.HIGH_ENTROPY,
                severity=Severity.INFO,
                file_path=file_path,
                line_number=line_no,
                commit_hash=commit_hash,
                commit_date=commit_date,
                masked_value=_mask(token),
            ))

    return findings, raw_values


# ---------------------------------------------------------------------------
# File / directory scanners
# ---------------------------------------------------------------------------
def scan_file(file_path: Path) -> tuple[list[Finding], dict[str, str]]:
    """
    Scan a single file on disk.
    Uses the absolute path for skip checking — intended for explicit single-file
    scans where the user deliberately targets a file.
    """
    if _should_skip(file_path):
        return [], {}
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return [], {}
    return scan_content(content, str(file_path))


def scan_directory(directory: Path) -> tuple[list[Finding], dict[str, str], int]:
    """
    Recursively scan all files under *directory*.

    Fragment-matching is done on paths RELATIVE to *directory* so that system
    directories in the absolute path (e.g. /tmp on Linux, C:\\Users on Windows)
    never trigger the ignore list. Only project-internal dirs like tmp/,
    .env/, node_modules/ etc. are skipped.

    Returns (findings, raw_values, files_scanned).
    """
    load_ignore_patterns_for_root(directory)
    findings: list[Finding] = []
    raw_values: dict[str, str] = {}
    files_scanned = 0

    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        # Use the project-relative path for fragment checking so /tmp, /home,
        # C:\Users etc. in the absolute path never falsely trigger the ignore list.
        rel_path = file_path.relative_to(directory)
        if _should_skip(rel_path):
            continue
        files_scanned += 1
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            f, r = scan_content(content, str(file_path))
        except Exception:
            continue
        findings.extend(f)
        raw_values.update(r)

    return findings, raw_values, files_scanned