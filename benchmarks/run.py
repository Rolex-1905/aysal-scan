"""Run one or more scanners over the labelled corpus and report precision / recall.

Usage:
    python benchmarks/run.py --aysal aysal-scan                # a v2 binary
    python benchmarks/run.py --aysal /path/to/v1/aysal-scan    # compare an older version
    python benchmarks/run.py --aysal aysal-scan --gitleaks gitleaks --trufflehog trufflehog

Scoring is FILE-LEVEL: a file counts as detected if the tool reports at least one finding in
it. A positive file with a finding is a true positive, without one a false negative; a decoy
file with a finding is a false positive.

The gitleaks / trufflehog adapters parse their JSON output as documented upstream but have NOT
been exercised by the author's CI: verify them against your installed versions before citing
any comparison.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import corpus  # noqa: E402


def _aysal(binary: str, root: Path) -> set[str]:
    p = subprocess.run(
        [binary, "scan", str(root), "--no-blast-radius", "--min-severity", "MEDIUM",
         "--report", "json", "--no-fail"],
        capture_output=True, text=True,
    )
    data = json.loads(p.stdout)
    return {Path(f["file_path"]).relative_to(root.resolve()).as_posix()
            if Path(f["file_path"]).is_absolute() else f["file_path"] for f in data["findings"]}


def _gitleaks(binary: str, root: Path) -> set[str]:
    out = Path(tempfile.mkdtemp()) / "gl.json"
    subprocess.run([binary, "dir", str(root), "--report-format", "json", "--report-path", str(out),
                    "--no-banner", "--exit-code", "0"], capture_output=True, text=True)
    findings = json.loads(out.read_text() or "[]") if out.exists() else []
    return {Path(f["File"]).resolve().relative_to(root.resolve()).as_posix() for f in findings}


def _trufflehog(binary: str, root: Path) -> set[str]:
    p = subprocess.run([binary, "filesystem", str(root), "--json", "--no-verification", "--no-update"],
                       capture_output=True, text=True)
    files = set()
    for line in p.stdout.splitlines():
        try:
            item = json.loads(line)
            file = item["SourceMetadata"]["Data"]["Filesystem"]["file"]
            files.add(Path(file).resolve().relative_to(root.resolve()).as_posix())
        except (ValueError, KeyError):
            continue
    return files


def score(detected: set[str], labels: dict) -> dict:
    # labels.json itself is never a candidate
    detected = {d for d in detected if d != "labels.json"}
    pos, dec = set(labels["positives"]), set(labels["decoys"])
    tp, fn = len(pos & detected), len(pos - detected)
    fp = len(dec & detected)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "precision": precision, "recall": recall, "f1": f1,
            "missed": sorted(pos - detected), "false_alarms": sorted(dec & detected)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--aysal", action="append", default=[], help="path to an aysal-scan executable (repeatable)")
    ap.add_argument("--gitleaks")
    ap.add_argument("--trufflehog")
    ap.add_argument("--seed", type=int, default=1905)
    ap.add_argument("--json", help="write full results here")
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="aysal-bench-")) / "corpus"
    labels = corpus.build(root, args.seed)
    print(f"corpus: {len(labels['positives'])} positive files, {len(labels['decoys'])} decoy files (seed {args.seed})\n")

    runs = [(f"aysal-scan [{b}]", lambda b=b: _aysal(b, root)) for b in args.aysal]
    if args.gitleaks:
        runs.append(("gitleaks", lambda: _gitleaks(args.gitleaks, root)))
    if args.trufflehog:
        runs.append(("trufflehog", lambda: _trufflehog(args.trufflehog, root)))

    results = {}
    print(f"{'tool':44} {'TP':>3} {'FN':>3} {'FP':>3} {'precision':>10} {'recall':>8} {'F1':>6}")
    for name, fn in runs:
        r = score(fn(), labels)
        results[name] = r
        print(f"{name:44} {r['tp']:3} {r['fn']:3} {r['fp']:3} {r['precision']:10.2f} {r['recall']:8.2f} {r['f1']:6.2f}")
    for name, r in results.items():
        if r["missed"] or r["false_alarms"]:
            print(f"\n{name}\n  missed       : {', '.join(r['missed']) or '-'}\n  false alarms : {', '.join(r['false_alarms']) or '-'}")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
