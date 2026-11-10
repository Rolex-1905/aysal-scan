"""Optional ``aysal-scan.toml`` configuration: defaults plus custom detection rules.

Example::

    min_severity = "MEDIUM"
    fail_on = "HIGH"
    no_blast_radius = false
    max_file_size_mb = 5
    allow_list = ["<finding id>", "<finding id>"]

    [[rules]]
    id = "acme-internal-token"
    description = "ACME internal API token"
    regex = 'acme_[a-z0-9]{32}'
    severity = "HIGH"          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    secret_group = 0           # capture group holding the secret (0 = whole match)
    keywords = ["acme"]        # optional: the line must contain one of these words
    entropy = 3.0              # optional: minimum Shannon entropy of the secret
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any, Optional

from aysal_scan.models import SecretType, Severity
from aysal_scan.scanner.patterns import SecretPattern

CONFIG_FILE_NAMES = ("aysal-scan.toml", ".aysal-scan.toml")

_KNOWN_KEYS = {
    "min_severity", "fail_on", "no_blast_radius", "max_file_size_mb", "allow_list", "rules",
}


class ConfigError(ValueError):
    """The configuration file is invalid."""


def find_config(start: Optional[Path] = None) -> Optional[Path]:
    """Look for a config file in ``start`` (default: the current directory) only."""
    base = Path(start) if start else Path.cwd()
    for name in CONFIG_FILE_NAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc

    unknown = set(data) - _KNOWN_KEYS
    if unknown:
        raise ConfigError(f"Unknown config key(s) in {path}: {', '.join(sorted(unknown))}")
    try:
        if "min_severity" in data:
            Severity.parse(str(data["min_severity"]))
        if "fail_on" in data and str(data["fail_on"]).upper() != "NONE":
            Severity.parse(str(data["fail_on"]))
    except ValueError as exc:
        raise ConfigError(f"Invalid config value in {path}: {exc}") from exc
    if "allow_list" in data and not isinstance(data["allow_list"], list):
        raise ConfigError("allow_list must be a list of finding ids")
    return data


def compile_rules(rules: list[dict[str, Any]]) -> list[SecretPattern]:
    """Turn ``[[rules]]`` tables into detection patterns."""
    out: list[SecretPattern] = []
    seen: set[str] = set()
    for i, rule in enumerate(rules, start=1):
        rid = str(rule.get("id", "")).strip()
        if not rid:
            raise ConfigError(f"rules[{i}] is missing an 'id'")
        if rid in seen:
            raise ConfigError(f"Duplicate rule id: {rid}")
        seen.add(rid)
        regex = rule.get("regex")
        if not regex:
            raise ConfigError(f"Rule '{rid}' is missing a 'regex'")
        try:
            compiled = re.compile(regex)
        except re.error as exc:
            raise ConfigError(f"Rule '{rid}' has an invalid regex: {exc}") from exc
        group = int(rule.get("secret_group", 0))
        if group > compiled.groups:
            raise ConfigError(f"Rule '{rid}': secret_group {group} but the regex has {compiled.groups} group(s)")
        try:
            severity = Severity.parse(str(rule.get("severity", "HIGH")))
        except ValueError as exc:
            raise ConfigError(f"Rule '{rid}': {exc}") from exc
        keywords = [str(k) for k in rule.get("keywords", [])]
        out.append(
            SecretPattern(
                secret_type=SecretType.CUSTOM,
                pattern=compiled,
                default_severity=severity,
                requires_context=bool(keywords),
                context_keywords=keywords,
                value_group=group,
                rule_id=rid,
                min_entropy=float(rule.get("entropy", 0.0)),
            )
        )
    return out
