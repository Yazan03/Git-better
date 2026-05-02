#!/usr/bin/env python3
"""
SAST Benchmark Runner
=====================
Evaluates Git Better against Semgrep and Bandit on a labeled vulnerability
corpus and reports Precision, Recall, F1, False-Positive Rate, and scan time.

Usage
-----
    # Run all tools (Semgrep and Bandit are skipped if not installed)
    python benchmark/run_benchmark.py

    # Select tools explicitly
    python benchmark/run_benchmark.py --tools gitbetter,semgrep,bandit

    # Save results to CSV and JSON for import into Excel / LaTeX
    python benchmark/run_benchmark.py --csv results.csv --json-out results.json

    # Show per-finding detail for one tool
    python benchmark/run_benchmark.py --detail gitbetter

Install optional tools
----------------------
    pip install semgrep bandit
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

BENCHMARK_DIR = Path(__file__).parent.resolve()
CORPUS_DIR    = BENCHMARK_DIR / "corpus"
GT_FILE       = BENCHMARK_DIR / "ground_truth.json"
SCANNER       = BENCHMARK_DIR.parent / "scripts" / "vuln_scanner.py"


# ── Ground truth ──────────────────────────────────────────────────────────────

def load_ground_truth() -> list[dict]:
    with open(GT_FILE, encoding="utf-8") as f:
        return json.load(f)["tests"]


# ── Path normalisation ────────────────────────────────────────────────────────

def _normalise(raw_path: str) -> str:
    """
    Return the portion of a file path starting from 'corpus/', so that
    absolute paths from different tools all compare equal to the relative
    paths stored in ground_truth.json.

    e.g. '/home/user/.../benchmark/corpus/python/foo.py' → 'corpus/python/foo.py'
    """
    p = Path(raw_path)
    parts = p.parts
    try:
        idx = next(i for i, part in enumerate(parts) if part == "corpus")
        return str(Path(*parts[idx:]))
    except StopIteration:
        return p.name   # fallback: just the filename


# ── Tool runners ──────────────────────────────────────────────────────────────

def _is_installed(tool: str) -> bool:
    try:
        subprocess.run([tool, "--version"], capture_output=True, check=True, timeout=10)
        return True
    except Exception:
        return False


def run_gitbetter() -> tuple[dict[str, set[int]], float]:
    """Run git-better on the corpus; return ({norm_path: {lines}}, elapsed_sec)."""
    out_file = BENCHMARK_DIR / "_tmp_gitbetter.json"
    cmd = [
        sys.executable, str(SCANNER),
        "--path",   str(CORPUS_DIR),
        "--output", str(out_file),
        "--no-sca",
        "--jobs", "4",
    ]
    t0 = time.perf_counter()
    subprocess.run(cmd, capture_output=True, check=False)
    elapsed = time.perf_counter() - t0

    findings: dict[str, set[int]] = defaultdict(set)
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
        for f in data.get("findings", []):
            findings[_normalise(f["file"])].add(f["line"])
    except Exception:
        pass
    finally:
        out_file.unlink(missing_ok=True)

    return dict(findings), elapsed


def run_semgrep() -> tuple[dict[str, set[int]] | None, float]:
    """Run Semgrep with --config auto; return None if not installed."""
    if not _is_installed("semgrep"):
        return None, 0.0

    out_file = BENCHMARK_DIR / "_tmp_semgrep.json"
    cmd = [
        "semgrep", "--config", "auto",
        "--json", "--output", str(out_file),
        "--quiet",
        str(CORPUS_DIR),
    ]
    t0 = time.perf_counter()
    try:
        subprocess.run(cmd, capture_output=True, check=False, timeout=180)
    except subprocess.TimeoutExpired:
        print("  [semgrep] timed out after 180 s")
        return {}, 180.0
    elapsed = time.perf_counter() - t0

    findings: dict[str, set[int]] = defaultdict(set)
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
        for r in data.get("results", []):
            findings[_normalise(r["path"])].add(r.get("start", {}).get("line", 0))
    except Exception:
        pass
    finally:
        out_file.unlink(missing_ok=True)

    return dict(findings), elapsed


def run_bandit() -> tuple[dict[str, set[int]] | None, float]:
    """Run Bandit on Python files only; return None if not installed."""
    if not _is_installed("bandit"):
        return None, 0.0

    out_file = BENCHMARK_DIR / "_tmp_bandit.json"
    cmd = [
        "bandit", "-r", str(CORPUS_DIR / "python"),
        "-f", "json", "-o", str(out_file),
        "-q",
    ]
    t0 = time.perf_counter()
    subprocess.run(cmd, capture_output=True, check=False)
    elapsed = time.perf_counter() - t0

    findings: dict[str, set[int]] = defaultdict(set)
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
        for r in data.get("results", []):
            findings[_normalise(r["filename"])].add(r["line_number"])
    except Exception:
        pass
    finally:
        out_file.unlink(missing_ok=True)

    return dict(findings), elapsed


# ── Evaluation ────────────────────────────────────────────────────────────────

def _has_finding(tool_findings: dict[str, set[int]], test_file: str) -> bool:
    """Return True if the tool reported any finding in test_file."""
    norm = _normalise(test_file)
    # Try exact normalised match first, then filename-only fallback
    if norm in tool_findings and tool_findings[norm]:
        return True
    basename = Path(test_file).name
    for key, lines in tool_findings.items():
        if Path(key).name == basename and lines:
            return True
    return False


def evaluate(
    tool_findings: dict[str, set[int]],
    tests: list[dict],
    lang_filter: str | None = None,
) -> dict:
    """
    File-level evaluation (standard for SAST benchmarks, ref. OWASP Benchmark).

    A tool "detects" a vulnerable file if it reports at least one finding.
    Any finding in a safe file counts as a false positive.
    """
    TP = FP = FN = TN = 0
    per_cat:  dict[str, dict] = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    per_lang: dict[str, dict] = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    details:  list[dict]      = []

    for t in tests:
        if lang_filter and t["language"] != lang_filter:
            continue

        found = _has_finding(tool_findings, t["file"])
        cat   = t["category"]
        lang  = t["language"]

        if t["vulnerable"]:
            if found:
                TP += 1; per_cat[cat]["TP"] += 1; per_lang[lang]["TP"] += 1
                details.append({"id": t["id"], "result": "TP"})
            else:
                FN += 1; per_cat[cat]["FN"] += 1; per_lang[lang]["FN"] += 1
                details.append({"id": t["id"], "result": "FN"})
        else:
            if found:
                FP += 1; per_cat[cat]["FP"] += 1; per_lang[lang]["FP"] += 1
                details.append({"id": t["id"], "result": "FP"})
            else:
                TN += 1; per_cat[cat]["TN"] += 1; per_lang[lang]["TN"] += 1
                details.append({"id": t["id"], "result": "TN"})

    def _metrics(tp, fp, fn, tn):
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr}

    m = _metrics(TP, FP, FN, TN)
    return {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        **m,
        "per_category": {
            cat: {**counts, **_metrics(counts["TP"], counts["FP"], counts["FN"], counts["TN"])}
            for cat, counts in per_cat.items()
        },
        "per_language": {
            lang: {**counts, **_metrics(counts["TP"], counts["FP"], counts["FN"], counts["TN"])}
            for lang, counts in per_lang.items()
        },
        "details": details,
    }


# ── Pretty-print helpers ──────────────────────────────────────────────────────

def _pct(v: float) -> str:
    return f"{v:.1%}"


def print_results(results: dict[str, dict], elapsed: dict[str, float]) -> None:
    tools = list(results)
    W = 16

    print("\n" + "═" * 76)
    print("  Git Better SAST Benchmark — Results")
    print("═" * 76)

    # ── Overall table ──────────────────────────────────────────────────────
    print(f"\n  {'Tool':<{W}} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4}"
          f"  {'Precision':>9} {'Recall':>7} {'F1':>7} {'FPR':>7} {'Time':>7}")
    print("  " + "─" * 74)
    for tool in tools:
        r = results[tool]
        print(f"  {tool:<{W}} {r['TP']:>4} {r['FP']:>4} {r['FN']:>4} {r['TN']:>4}"
              f"  {_pct(r['precision']):>9} {_pct(r['recall']):>7}"
              f" {_pct(r['f1']):>7} {_pct(r['fpr']):>7} {elapsed[tool]:>6.1f}s")

    # ── Per-category F1 ────────────────────────────────────────────────────
    all_cats = sorted({
        cat for r in results.values() for cat in r["per_category"]
    })
    if all_cats:
        print(f"\n  {'Category':<22}", end="")
        for tool in tools:
            print(f"  {tool:<14}", end="")
        print()
        print("  " + "─" * (22 + len(tools) * 16))
        for cat in all_cats:
            print(f"  {cat:<22}", end="")
            for tool in tools:
                f1 = results[tool]["per_category"].get(cat, {}).get("f1", None)
                print(f"  {_pct(f1) if f1 is not None else 'N/A':<14}", end="")
            print()

    # ── Per-language Recall ────────────────────────────────────────────────
    all_langs = sorted({
        lang for r in results.values() for lang in r["per_language"]
    })
    if all_langs:
        print(f"\n  {'Language':<14}", end="")
        for tool in tools:
            print(f"  {tool + ' recall':<18}", end="")
        print()
        print("  " + "─" * (14 + len(tools) * 20))
        for lang in all_langs:
            print(f"  {lang:<14}", end="")
            for tool in tools:
                rec = results[tool]["per_language"].get(lang, {}).get("recall", None)
                print(f"  {_pct(rec) if rec is not None else 'N/A (not supported)':<18}", end="")
            print()

    print("\n" + "═" * 76 + "\n")


def print_detail(tool: str, results: dict[str, dict], tests: list[dict]) -> None:
    if tool not in results:
        print(f"  No results for '{tool}'")
        return
    details = {d["id"]: d["result"] for d in results[tool]["details"]}
    print(f"\n  Per-test detail — {tool}")
    print(f"  {'ID':<25} {'Expected':<10} {'Result':<6}")
    print("  " + "─" * 45)
    for t in tests:
        tid    = t["id"]
        label  = "VULN" if t["vulnerable"] else "SAFE"
        result = details.get(tid, "—")
        flag   = "  ← miss" if result == "FN" else ("  ← FP" if result == "FP" else "")
        print(f"  {tid:<25} {label:<10} {result:<6}{flag}")
    print()


# ── CSV / JSON export ─────────────────────────────────────────────────────────

def save_csv(results: dict[str, dict], elapsed: dict[str, float], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tool", "TP", "FP", "FN", "TN",
                    "precision", "recall", "f1", "fpr", "scan_time_s"])
        for tool, r in results.items():
            w.writerow([tool, r["TP"], r["FP"], r["FN"], r["TN"],
                        f"{r['precision']:.4f}", f"{r['recall']:.4f}",
                        f"{r['f1']:.4f}",        f"{r['fpr']:.4f}",
                        f"{elapsed[tool]:.2f}"])
    print(f"  CSV saved → {path}")


def save_json(results: dict, elapsed: dict, tests: list, path: str) -> None:
    vuln  = sum(1 for t in tests if t["vulnerable"])
    safe  = sum(1 for t in tests if not t["vulnerable"])
    out = {
        "corpus": {"total": len(tests), "vulnerable": vuln, "safe": safe},
        "tools":  {
            tool: {"metrics": r, "scan_time_s": elapsed[tool]}
            for tool, r in results.items()
        },
    }
    Path(path).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"  JSON saved → {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

RUNNERS = {
    "gitbetter": run_gitbetter,
    "semgrep":   run_semgrep,
    "bandit":    run_bandit,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SAST benchmark: git-better vs Semgrep vs Bandit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--tools", default="all",
        help="Comma-separated tools to run: gitbetter,semgrep,bandit  (default: all)",
    )
    parser.add_argument("--csv",      metavar="FILE", help="Export summary to CSV")
    parser.add_argument("--json-out", metavar="FILE", help="Export full results to JSON")
    parser.add_argument(
        "--detail", metavar="TOOL",
        help="Print per-test breakdown for one tool after the summary",
    )
    args = parser.parse_args()

    selected = (
        list(RUNNERS)
        if args.tools.strip().lower() == "all"
        else [t.strip().lower() for t in args.tools.split(",")]
    )

    tests = load_ground_truth()
    vuln  = sum(1 for t in tests if t["vulnerable"])
    safe  = sum(1 for t in tests if not t["vulnerable"])
    print(f"\n  Corpus: {len(tests)} test cases — {vuln} vulnerable, {safe} safe")
    print(f"  Languages: {sorted({t['language'] for t in tests})}")
    print(f"  Categories: {sorted({t['category'] for t in tests})}\n")

    results: dict[str, dict]   = {}
    elapsed: dict[str, float]  = {}

    for tool in selected:
        runner = RUNNERS.get(tool)
        if runner is None:
            print(f"  Unknown tool '{tool}' — skipping")
            continue

        print(f"  [{tool}] scanning …")
        findings, t = runner()

        if findings is None:
            print(f"  [{tool}] not installed — skipping  "
                  f"(install: pip install {tool})\n")
            continue

        elapsed[tool]  = t
        results[tool]  = evaluate(findings, tests)
        r = results[tool]
        print(f"  [{tool}] done in {t:.1f}s  "
              f"TP={r['TP']} FP={r['FP']} FN={r['FN']} TN={r['TN']}\n")

    if not results:
        print("  No tools produced results.")
        return

    print_results(results, elapsed)

    if args.detail:
        print_detail(args.detail, results, tests)

    if args.csv:
        save_csv(results, elapsed, args.csv)
    if args.json_out:
        save_json(results, elapsed, tests, args.json_out)


if __name__ == "__main__":
    main()
