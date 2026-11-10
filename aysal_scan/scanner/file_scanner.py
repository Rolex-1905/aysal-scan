"""File / directory / text scanning.

Key behaviours
--------------
* ``scan_content`` is the single detection entry point used by every scan mode.
* Directory walking prunes skipped directories instead of enumerating them
  (a 60,000-file ``node_modules`` costs ~0 instead of seconds), never follows
  symlinks, skips binaries and oversized files, and reports what it skipped.
* ``AysalScanignore`` uses real gitignore semantics (via ``pathspec``).
* Raw secret values are returned separately (``raw_values``) and never stored
  on ``Finding`` objects.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pathspec

from aysal_scan.models import Finding, SecretType, Severity
from aysal_scan.scanner.entropy import is_high_entropy_secret, shannon_entropy
from aysal_scan.scanner.patterns import (
    get_all_patterns,
    is_placeholder_value,
    looks_like_code_reference,
)

IGNORE_FILE_NAME = "AysalScanignore"
DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# ---------------------------------------------------------------------------
# What we skip by default
# ---------------------------------------------------------------------------

SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo", ".whl",
    ".lock", ".map", ".sqlite", ".db", ".pfx", ".p12", ".jks",
})

# Lock files are skipped by *file name* (checked separately from directories).
SKIP_FILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "poetry.lock", "Pipfile.lock", "Cargo.lock",
    "go.sum", "bun.lockb", "gradle.lockfile",
})

# Directory *names* skipped wherever they appear. Deliberately excludes names
# that commonly hold real secrets (logs, bin, env, tmp, out, output, site).
SKIP_DIR_NAMES: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".eggs",
    ".venv", "venv", "virtualenv", "site-packages", "dist", "build", ".cache",
    ".idea", ".vscode", ".terraform", ".next", ".nuxt", ".gradle", ".parcel-cache",
    ".turbo", ".angular", ".dart_tool", "Pods", "vendor", "coverage", "htmlcov",
})

# Multi-segment directory paths, matched as contiguous path *components*.
SKIP_DIR_SEQUENCES: tuple[tuple[str, ...], ...] = (
    ("tests", "fixtures"), ("public", "build"), ("docs", "_build"),
)

_MINIFIED_MARKERS = (".min.", ".chunk.", ".bundle.")


# ---------------------------------------------------------------------------
# Ignore file handling (gitignore semantics via pathspec)
# ---------------------------------------------------------------------------

_tls = threading.local()
_ignore_options = {"explicit": None, "disabled": False}


def configure_ignore(explicit: Optional[Path] = None, disabled: bool = False) -> None:
    """Choose which ignore file is honoured.

    explicit: use this file instead of discovering AysalScanignore in the scanned tree.
    disabled: ignore every AysalScanignore. Use this for UNTRUSTED repositories: a
              hostile repo can ship an AysalScanignore containing ``*`` to hide secrets.
    """
    _ignore_options["explicit"] = Path(explicit) if explicit else None
    _ignore_options["disabled"] = disabled


def _build_spec(lines: list[str]):
    spec_cls = getattr(pathspec, "GitIgnoreSpec", None)
    if spec_cls is not None:
        return spec_cls.from_lines(lines)
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _find_ignore_file(root: Path) -> Optional[Path]:
    start = root if root.is_dir() else root.parent
    for candidate_dir in [start, *start.parents]:
        candidate = candidate_dir / IGNORE_FILE_NAME
        if candidate.is_file():
            return candidate
        if (candidate_dir / ".git").exists():
            break  # repo boundary: do not look above the repository root
    return None


def load_ignore_patterns_for_root(root: Path) -> None:
    """Load ignore rules for ``root`` into thread-local state (replaces any previous state)."""
    _tls.spec = None
    _tls.prefix = ""
    if _ignore_options["disabled"]:
        return
    root = Path(root).resolve()
    ignore_path = _ignore_options["explicit"] or _find_ignore_file(root)
    if ignore_path is None:
        return
    try:
        lines = ignore_path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError):
        return
    _tls.spec = _build_spec(lines)
    base = ignore_path.resolve().parent
    try:
        rel = root.relative_to(base)
        _tls.prefix = "" if str(rel) == "." else rel.as_posix().rstrip("/") + "/"
    except ValueError:
        _tls.prefix = ""


def _ignored_by_spec(rel_posix: str, is_dir: bool = False) -> bool:
    spec = getattr(_tls, "spec", None)
    if spec is None:
        return False
    path = getattr(_tls, "prefix", "") + rel_posix
    return bool(spec.match_file(path + ("/" if is_dir else "")))


# ---------------------------------------------------------------------------
# Skip decisions
# ---------------------------------------------------------------------------

def _has_sequence(parts: tuple[str, ...], seq: tuple[str, ...]) -> bool:
    n = len(seq)
    return any(parts[i:i + n] == seq for i in range(len(parts) - n + 1))


def _dir_name_skipped(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.endswith(".egg-info")


def _should_skip_dir(rel_dir: Path, abs_dir: Optional[Path] = None) -> bool:
    """Used by the directory walker to prune whole subtrees."""
    if _dir_name_skipped(rel_dir.name):
        return True
    if any(_has_sequence(rel_dir.parts, seq) for seq in SKIP_DIR_SEQUENCES):
        return True
    if abs_dir is not None and (abs_dir / "pyvenv.cfg").is_file():
        return True  # any virtualenv, whatever it is called
    return _ignored_by_spec(rel_dir.as_posix(), is_dir=True)


def _should_skip(path: Path) -> bool:
    """Decide whether a repo-/root-relative *file* path is skipped."""
    parts = path.parts
    dir_parts = parts[:-1]
    name = path.name

    if any(_dir_name_skipped(p) for p in dir_parts):
        return True
    if any(_has_sequence(dir_parts, seq) for seq in SKIP_DIR_SEQUENCES):
        return True
    if name in SKIP_FILE_NAMES:
        return True
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    lowered = name.lower()
    if lowered.endswith((".min.js", ".min.css", ".d.ts")):
        return True
    if lowered.endswith((".js", ".css")) and any(m in lowered for m in _MINIFIED_MARKERS):
        return True
    return _ignored_by_spec(path.as_posix())


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

_ID_SALT = os.environ.get("AYSAL_SCAN_ID_SALT")


def _secret_id(value: str) -> str:
    """Stable finding id. Plain SHA-256 by default (compatible with v1 baselines);
    HMAC-SHA256 when AYSAL_SCAN_ID_SALT is set so ids in shared reports cannot be
    brute-forced offline for weak secrets."""
    data = value.encode("utf-8", errors="ignore")
    if _ID_SALT:
        return hmac.new(_ID_SALT.encode(), data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _mask(value: str) -> str:
    """Reveal at most ~25% of a value (8 chars of a long token, 4 of a short one)."""
    n = len(value)
    if n <= 8:
        return "****"
    if n <= 16:
        return value[:2] + "*" * (n - 4) + value[-2:]
    return value[:4] + "*" * (n - 8) + value[-4:]


_EXAMPLE_MARKERS = (".example", ".sample", ".template", ".dist", "-example", "_example",
                    ".tmpl", ".tpl", ".default")


def _context_adjust(file_path: str, severity: Severity) -> tuple[Severity, list[str]]:
    """Example/template files are a classic source of false alarms: lower severity one level."""
    name = Path(file_path).name.lower()
    if name.startswith(("example", "sample")) or any(m in name for m in _EXAMPLE_MARKERS):
        return severity.lowered(), ["example-file"]
    return severity, []


# ---------------------------------------------------------------------------
# Companion-secret pairing
# ---------------------------------------------------------------------------

_AWS_SECRET_KEY_RE = re.compile(
    r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[:=]\s*["\']?'
    r'([A-Za-z0-9/+=]{40})["\']?'
)
_TWILIO_AUTH_TOKEN_RE = re.compile(
    r'(?:TWILIO_AUTH_TOKEN|auth_token|authToken)\s*[:=]\s*["\']?'
    r'([a-fA-F0-9]{32})["\']?'
)
_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_NAME_PREFIX_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}=(.+)$")
_BASE64_BODY_RE = re.compile(r"[A-Za-z0-9+/=]{32,}")


_BASE64_LINE_RE = re.compile(r"[A-Za-z0-9+/=]+")
_PGP_ARMOR_HEADER_RE = re.compile(r"[A-Za-z-]+: .*")


def _pem_block(lines: list[str], start: int) -> Optional[tuple[int, str]]:
    """Return (end_line_index, normalized_body) for a private-key block starting at ``start``.

    Returns None when there is no real key material (e.g. code or docs that merely mention the
    header). The body must be *consecutive base64-looking lines* directly after the header; the
    first line of ordinary text ends it, so surrounding source code is never mistaken for a key.
    Single-line, JSON-escaped (``\\n``) keys are handled separately.
    """
    header_line = lines[start]
    m = re.search(r"-----BEGIN [^-]*-----(.*)$", header_line)
    tail = m.group(1) if m else ""

    # Single-line form: "-----BEGIN PRIVATE KEY-----\\nMIIE...\\n-----END PRIVATE KEY-----\\n"
    if "\\n" in tail or "-----END" in tail:
        body = re.sub(r"-----END[^-]*-----.*$", "", tail)
        body = body.replace("\\n", "").replace("\\r", "")
        body = re.sub(r"\s+", "", body)
        if _BASE64_LINE_RE.fullmatch(body) and len(body) >= 32:
            return start, body

    parts: list[str] = []
    end = start
    longest = 0
    for j in range(start + 1, min(len(lines), start + 400)):
        line = lines[j].strip()
        if line.startswith("-----END"):
            end = j
            break
        if line == "" or _PGP_ARMOR_HEADER_RE.fullmatch(line):
            end = j
            continue
        if _BASE64_LINE_RE.fullmatch(line):
            parts.append(line)
            longest = max(longest, len(line))
            end = j
            continue
        break  # ordinary text: the key body (if any) has ended

    body = "".join(parts)
    if len(body) < 32 or longest < 20:
        return None
    return end, body


def _extract_gcp_json(content: str, match_start: int) -> Optional[tuple[dict, int, int]]:
    """Find the JSON object containing a service-account marker. Returns (obj, start, end offsets)."""
    decoder = json.JSONDecoder()
    candidates = [m.start() for m in re.finditer(r"\{", content[:match_start + 1])][-25:]
    for idx in reversed(candidates):
        try:
            obj, end = decoder.raw_decode(content, idx)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("type") == "service_account" and end >= match_start:
            return obj, idx, end
    return None


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def scan_content(
    content: str,
    file_path: str,
    line_map: Optional[list[int]] = None,
    commit_hash: Optional[str] = None,
    commit_date: Optional[str] = None,
) -> tuple[list[Finding], dict[str, str]]:
    """Scan text and return ``(findings, raw_values)``.

    ``raw_values`` maps finding id -> raw secret (kept out of ``Finding`` on purpose).
    ``line_map`` optionally maps line index -> real file line number (used when scanning
    only the added lines of a git diff, whose positions differ from the file's).
    ``commit_hash`` / ``commit_date`` are copied onto every finding (history scans).
    """
    findings: list[Finding] = []
    raw_values: dict[str, str] = {}
    seen_ids: set[str] = set()

    lines = [ln.rstrip("\r") for ln in content.split("\n")]
    suppressed: set[int] = set()           # line indices consumed by a PEM block / GCP JSON
    paired_secrets: set[str] = set()       # secret halves already attached to an AWS key / Twilio SID
    patterns = get_all_patterns()

    def real_line(idx: int) -> int:
        if line_map is not None and idx < len(line_map):
            return line_map[idx]
        return idx + 1

    def add(finding: Finding, raw: str) -> None:
        findings.append(finding)
        raw_values[finding.id] = raw
        seen_ids.add(finding.id)

    # Character offset of the start of every line (for JSON extraction)
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln) + 1)

    for idx, line in enumerate(lines):
        matched_spans: list[tuple[int, int]] = []

        for pat in patterns:
            for match in pat.pattern.finditer(line):
                matched_spans.append(match.span())
                value = match.group(pat.value_group)
                severity = pat.default_severity
                tags: list[str] = []

                if idx in suppressed and pat.secret_type in (
                    SecretType.PRIVATE_KEY, SecretType.GCP_SERVICE_ACCOUNT
                ):
                    continue

                if pat.requires_context and not any(
                    kw.lower() in line.lower() for kw in pat.context_keywords
                ):
                    continue

                if pat.check_dummy and (
                    is_placeholder_value(value) or looks_like_code_reference(value)
                ):
                    continue
                if pat.min_entropy and shannon_entropy(value) < pat.min_entropy:
                    continue
                if pat.validator is not None and not pat.validator(value):
                    continue
                if pat.adjust_severity is not None:
                    severity = pat.adjust_severity(value, severity)

                masked = None
                raw = value

                # ---- private keys: fingerprint the whole block, not the header ----
                if pat.secret_type == SecretType.PRIVATE_KEY:
                    block = _pem_block(lines, idx)
                    if block is None:
                        continue  # header mentioned in code/docs, no key material
                    end_idx, body = block
                    suppressed.update(range(idx, end_idx + 1))
                    raw = body
                    n_lines = end_idx - idx + 1
                    masked = f"{value} [{n_lines} line{'s' if n_lines != 1 else ''}]"

                # ---- GCP service account: parse the JSON object ----
                elif pat.secret_type == SecretType.GCP_SERVICE_ACCOUNT:
                    parsed = _extract_gcp_json(content, offsets[idx] + match.start())
                    if parsed is None:
                        continue  # fragment without a complete JSON object
                    obj, j_start, j_end = parsed
                    private_key = str(obj.get("private_key", ""))
                    gcp_tags: list[str] = []
                    if "PRIVATE KEY" not in private_key:
                        # A service-account identity without key material is not a credential.
                        severity = Severity.INFO
                        gcp_tags = ["no-private-key"]
                    first = content.count("\n", 0, j_start)
                    last = content.count("\n", 0, j_end)
                    suppressed.update(range(first, last + 1))
                    identity = f"{obj.get('client_email', '')}|{obj.get('private_key_id', '')}"
                    raw = json.dumps({
                        "project_id": obj.get("project_id", ""),
                        "client_email": obj.get("client_email", ""),
                        "private_key_id": obj.get("private_key_id", ""),
                    })
                    secret_id = _secret_id("gcp-sa:" + (identity if identity != "|" else private_key))
                    if secret_id in seen_ids:
                        continue
                    key_id = str(obj.get("private_key_id", "")) or "unknown"
                    add(
                        Finding(
                            id=secret_id, secret_type=pat.secret_type, severity=severity,
                            file_path=file_path, line_number=real_line(idx),
                            masked_value=f"service account key id {_mask(key_id)}",
                            rule_id=pat.rule_id, tags=gcp_tags,
                            commit_hash=commit_hash, commit_date=commit_date,
                        ),
                        raw,
                    )
                    continue

                secret_id = _secret_id(raw)
                if secret_id in seen_ids:
                    continue

                severity, ctx_tags = _context_adjust(file_path, severity)
                tags.extend(ctx_tags)

                # ---- AWS: pair key id with a nearby secret access key ----
                if pat.secret_type == SecretType.AWS_ACCESS_KEY and value.startswith("AKIA"):
                    window = lines[max(0, idx - 5): idx + 6]
                    m = _AWS_SECRET_KEY_RE.search("\n".join(window))
                    if m:
                        raw = f"{value}:{m.group(1)}"
                        paired_secrets.add(m.group(1))
                elif pat.secret_type == SecretType.TWILIO:
                    window = lines[max(0, idx - 5): idx + 6]
                    m = _TWILIO_AUTH_TOKEN_RE.search("\n".join(window))
                    if m:
                        raw = f"{value}:{m.group(1)}"
                        paired_secrets.add(m.group(1))

                add(
                    Finding(
                        id=secret_id, secret_type=pat.secret_type, severity=severity,
                        file_path=file_path, line_number=real_line(idx),
                        masked_value=masked or _mask(value), rule_id=pat.rule_id, tags=tags,
                        commit_hash=commit_hash, commit_date=commit_date,
                    ),
                    raw,
                )

        # ---- Entropy fallback for secrets no named rule recognised ----
        if idx in suppressed:
            continue
        for tok in _ENTROPY_TOKEN_RE.finditer(line):
            if any(tok.start() < e and tok.end() > s for s, e in matched_spans):
                continue
            token = tok.group()
            prefixed = _NAME_PREFIX_RE.match(token)
            if prefixed and len(prefixed.group(1)) >= 20:
                token = prefixed.group(1)   # hash the value, not "NAME=value"
            if token.count("/") >= 4 or token.startswith("/"):
                continue                    # file path / URL fragment
            if not any(ch.isdigit() for ch in token):
                continue                    # identifiers and prose are letters-only
            if not is_high_entropy_secret(token):
                continue
            secret_id = _secret_id(token)
            if secret_id in seen_ids:
                continue
            sev, ctx_tags = _context_adjust(file_path, Severity.INFO)
            add(
                Finding(
                    id=secret_id, secret_type=SecretType.HIGH_ENTROPY, severity=sev,
                    file_path=file_path, line_number=real_line(idx),
                    masked_value=_mask(token), rule_id="high-entropy-string", tags=ctx_tags,
                    commit_hash=commit_hash, commit_date=commit_date,
                ),
                token,
            )

    if paired_secrets:
        # The secret half of an AWS/Twilio credential is reported once, with its key/SID.
        drop = {
            f.id for f in findings
            if f.secret_type == SecretType.HIGH_ENTROPY and raw_values.get(f.id) in paired_secrets
        }
        findings = [f for f in findings if f.id not in drop]
        for fid in drop:
            raw_values.pop(fid, None)

    return findings, raw_values


# ---------------------------------------------------------------------------
# Files and directories
# ---------------------------------------------------------------------------

@dataclass
class ScanStats:
    files_scanned: int = 0
    skipped_large: int = 0
    skipped_binary: int = 0
    skipped_symlinks: int = 0
    unreadable: int = 0

    @property
    def files_skipped(self) -> int:
        return self.skipped_large + self.skipped_binary + self.skipped_symlinks + self.unreadable

    def warnings(self) -> list[str]:
        out = []
        if self.skipped_large:
            out.append(f"{self.skipped_large} file(s) skipped: larger than the size limit")
        if self.skipped_binary:
            out.append(f"{self.skipped_binary} binary file(s) skipped")
        if self.skipped_symlinks:
            out.append(f"{self.skipped_symlinks} symlink(s) not followed")
        if self.unreadable:
            out.append(f"{self.unreadable} file(s) could not be read (permissions/IO error)")
        return out


def _read_text(path: Path, max_size: int, stats: ScanStats) -> Optional[str]:
    try:
        size = path.stat().st_size
        if size > max_size:
            stats.skipped_large += 1
            return None
        with open(path, "rb") as fh:
            head = fh.read(8192)
            if b"\x00" in head:
                stats.skipped_binary += 1
                return None
            data = head + fh.read()
        return data.decode("utf-8", errors="ignore")
    except OSError:
        stats.unreadable += 1
        return None


def scan_file(file_path: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
    """Scan one explicitly-named file. Directory/extension skip rules are not applied
    (the caller asked for this file), but binary and oversized files are still refused."""
    file_path = Path(file_path)
    stats = ScanStats()
    text = _read_text(file_path, max_file_size, stats)
    if text is None:
        return [], {}
    return scan_content(text, str(file_path))


def scan_directory_ex(directory: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
    """Scan a directory tree. Returns (findings, raw_values, ScanStats)."""
    directory = Path(directory)
    load_ignore_patterns_for_root(directory)
    stats = ScanStats()
    findings: list[Finding] = []
    raw_values: dict[str, str] = {}

    for root, dirs, files in os.walk(directory, followlinks=False):
        root_path = Path(root)
        rel_root = root_path.relative_to(directory)
        dirs[:] = sorted(
            d for d in dirs if not _should_skip_dir(rel_root / d, root_path / d)
        )
        for fname in sorted(files):
            fpath = root_path / fname
            if fpath.is_symlink():
                stats.skipped_symlinks += 1
                continue
            if _should_skip(rel_root / fname):
                continue
            text = _read_text(fpath, max_file_size, stats)
            if text is None:
                continue
            stats.files_scanned += 1
            f, r = scan_content(text, str(fpath))
            findings.extend(f)
            raw_values.update(r)
    return findings, raw_values, stats


def scan_directory(directory: Path):
    """Backward-compatible wrapper: returns (findings, raw_values, files_scanned)."""
    findings, raw_values, stats = scan_directory_ex(directory)
    return findings, raw_values, stats.files_scanned
