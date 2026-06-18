"""Tests for deduplicator — verifies location merging, not just dropping."""
import pytest
from aysal_scan.scanner.deduplicator import deduplicate
from aysal_scan.models import Finding, SecretType, Severity


def _f(secret_id: str, file_path: str, line: int = 1) -> Finding:
    return Finding(
        id=secret_id,
        secret_type=SecretType.AWS_ACCESS_KEY,
        severity=Severity.CRITICAL,
        file_path=file_path,
        line_number=line,
        masked_value="AKIA****XMPL",
    )


def test_empty_list():
    assert deduplicate([]) == []


def test_single_finding_unchanged():
    f = _f("abc", "file.py", 10)
    result = deduplicate([f])
    assert len(result) == 1
    assert result[0].file_path == "file.py"
    assert result[0].locations == []


def test_duplicate_keeps_first_occurrence():
    f1 = _f("abc", "file1.py", 10)
    f2 = _f("abc", "file2.py", 20)
    result = deduplicate([f1, f2])
    assert len(result) == 1
    assert result[0].file_path == "file1.py"
    assert result[0].line_number == 10


def test_duplicate_records_additional_locations():
    f1 = _f("abc", "file1.py", 10)
    f2 = _f("abc", "file2.py", 20)
    f3 = _f("abc", "file3.py", 30)
    result = deduplicate([f1, f2, f3])
    assert len(result) == 1
    assert len(result[0].locations) == 2
    paths = {loc.file_path for loc in result[0].locations}
    assert paths == {"file2.py", "file3.py"}


def test_location_line_numbers_preserved():
    f1 = _f("abc", "a.py", 5)
    f2 = _f("abc", "b.py", 99)
    result = deduplicate([f1, f2])
    assert result[0].locations[0].line_number == 99


def test_different_secrets_all_kept():
    f1 = _f("aaa", "file1.py", 1)
    f2 = _f("bbb", "file2.py", 2)
    f3 = _f("ccc", "file3.py", 3)
    result = deduplicate([f1, f2, f3])
    assert len(result) == 3


def test_mixed_duplicates_and_uniques():
    f1 = _f("aaa", "a.py", 1)
    f2 = _f("bbb", "b.py", 2)
    f3 = _f("aaa", "c.py", 3)  # duplicate of f1
    f4 = _f("ccc", "d.py", 4)
    result = deduplicate([f1, f2, f3, f4])
    assert len(result) == 3
    aaa_finding = next(r for r in result if r.id == "aaa")
    assert len(aaa_finding.locations) == 1
    assert aaa_finding.locations[0].file_path == "c.py"


def test_order_preserved():
    findings = [_f(str(i), f"file{i}.py") for i in range(5)]
    result = deduplicate(findings)
    assert [r.id for r in result] == [str(i) for i in range(5)]