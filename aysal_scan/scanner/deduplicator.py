"""
deduplicator.py — deduplicate findings by secret hash.

Same secret found in N files/commits → 1 Finding whose `locations` list
records every additional occurrence beyond the first.
"""
from __future__ import annotations

from aysal_scan.models import Finding, Location


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate by secret id (sha256 of the raw value).

    The first occurrence becomes the canonical Finding.
    Every subsequent occurrence appends a Location entry so no context is lost.
    """
    index: dict[str, int] = {}   # id → position in `unique`
    unique: list[Finding] = []

    for f in findings:
        if f.id not in index:
            index[f.id] = len(unique)
            unique.append(f)
        else:
            # Record the additional location on the canonical finding
            canonical = unique[index[f.id]]
            canonical.locations.append(
                Location(
                    file_path=f.file_path,
                    line_number=f.line_number,
                    commit_hash=f.commit_hash,
                    commit_date=f.commit_date,
                )
            )

    return unique