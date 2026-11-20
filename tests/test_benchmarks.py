"""The benchmark harness itself must be trustworthy: labels, scoring and determinism."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmarks"))
import corpus  # noqa: E402
import corpus_realistic  # noqa: E402
import run  # noqa: E402


@pytest.mark.parametrize("module", [corpus, corpus_realistic])
def test_every_labelled_file_exists_and_labels_are_disjoint(module, tmp_path):
    labels = module.build(tmp_path / "c", seed=7)
    assert labels["positives"] and labels["decoys"]
    assert not set(labels["positives"]) & set(labels["decoys"])
    for rel in labels["positives"] + labels["decoys"]:
        assert (tmp_path / "c" / rel).is_file()


def test_synthetic_corpus_is_deterministic(tmp_path):
    a = corpus.build(tmp_path / "a", seed=1)
    b = corpus.build(tmp_path / "b", seed=1)
    assert a == b
    for rel in a["positives"]:
        assert (tmp_path / "a" / rel).read_text() == (tmp_path / "b" / rel).read_text()


def test_github_token_checksum_is_correct_and_deterministic():
    import random
    import zlib

    tok = corpus_realistic.github_classic_token(random.Random(3))
    body, checksum = tok[4:34], tok[34:]
    assert tok.startswith("ghp_") and len(tok) == 40
    assert checksum == corpus_realistic._base62(zlib.crc32(body.encode()))
    assert tok == corpus_realistic.github_classic_token(random.Random(3))


@pytest.mark.skipif(not corpus_realistic.HAVE_CRYPTO, reason="needs cryptography")
def test_realistic_keys_are_real_pem_and_decoys_contain_only_public_material(tmp_path):
    labels = corpus_realistic.build(tmp_path / "c")
    pem = (tmp_path / "c" / "positives" / "pem_rsa_pkcs8" / "rsa_pkcs8.pem").read_text()
    assert pem.startswith("-----BEGIN PRIVATE KEY-----")
    from cryptography.hazmat.primitives import serialization
    serialization.load_pem_private_key(pem.encode(), password=None)   # parses => a real key
    decoy_text = "".join((tmp_path / "c" / r).read_text() for r in labels["decoys"])
    assert "PRIVATE KEY" not in decoy_text


def test_scoring_math():
    labels = {"positives": ["p1", "p2", "p3", "p4"], "decoys": ["d1", "d2"]}
    r = run.score({"p1", "p2", "p3", "d1", "labels.json"}, labels)
    assert (r["tp"], r["fn"], r["fp"]) == (3, 1, 1)
    assert r["precision"] == pytest.approx(0.75) and r["recall"] == pytest.approx(0.75)
    assert r["missed"] == ["p4"] and r["false_alarms"] == ["d1"]


def test_scoring_handles_empty_detections():
    r = run.score(set(), {"positives": ["p"], "decoys": ["d"]})
    assert r["recall"] == 0 and r["precision"] == 1.0 and r["f1"] == 0
