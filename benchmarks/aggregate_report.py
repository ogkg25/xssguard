#!/usr/bin/env python3
"""
Aggregate benchmark report generator.
Produces per-target, per-xss-type, per-context breakdowns and macro-averaged metrics.
Optionally compares against a baseline and highlights regressions.
"""

import argparse
import glob
import json
import os
import sys
from typing import Dict, List, Optional, Any

XSS_TYPE_ORDER = ["reflected", "stored", "dom"]
CONTEXT_ORDER = ["html_body", "html_attribute", "js_string", "json", "url_href"]


def _round3(v: float) -> float:
    return round(v, 3)


def _is_matrix_report(data: Dict) -> bool:
    """Check if JSON looks like a matrix report (from score_matrix.py)."""
    return isinstance(data, dict) and "summary" in data and ("by_xss_type" in data or "matrix" in data)


def _load_report(path: str) -> Optional[Dict]:
    """Load a matrix report JSON. Returns None if invalid."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if _is_matrix_report(data):
            return data
        return None
    except (json.JSONDecodeError, IOError):
        return None


def _get_target_name(path: str, data: Dict) -> str:
    """Derive target name from path or benchmark field."""
    name = data.get("benchmark", "")
    if name:
        return name
    base = os.path.basename(path)
    if base.endswith("_report.json"):
        return base.replace("_report.json", "").replace("_matrix", "").replace("matrix_", "") or base
    return base.replace(".json", "")


def _aggregate_stats(stats_list: List[Dict]) -> Dict:
    """Aggregate multiple stats dicts (sum TP/FP/FN/TN, recompute P/R/F1)."""
    tp = fp = fn = tn = skipped = errors = 0
    for s in stats_list:
        tp += s.get("true_positives", 0)
        fp += s.get("false_positives", 0)
        fn += s.get("false_negatives", 0)
        tn += s.get("true_negatives", 0)
        skipped += s.get("skipped", 0)
        errors += s.get("errors", 0)
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "total_cases": total + skipped,
        "skipped": skipped,
        "errors": errors,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": _round3(precision),
        "recall": _round3(recall),
        "f1_score": _round3(f1),
    }


def _macro_average(by_key: Dict[str, Dict], order: List[str]) -> Dict[str, float]:
    """
    Compute macro-averaged Precision, Recall, F1 across classes.
    Macro = unweighted mean of per-class metrics (classes with no cases contribute 0).
    """
    precisions, recalls, f1s = [], [], []
    for k in order:
        s = by_key.get(k, {})
        total = s.get("total_cases", 0) or 0
        if total > 0:
            precisions.append(s.get("precision", 0.0))
            recalls.append(s.get("recall", 0.0))
            f1s.append(s.get("f1_score", 0.0))
        else:
            precisions.append(0.0)
            recalls.append(0.0)
            f1s.append(0.0)
    n = len(order)
    return {
        "macro_precision": _round3(sum(precisions) / n if n else 0.0),
        "macro_recall": _round3(sum(recalls) / n if n else 0.0),
        "macro_f1": _round3(sum(f1s) / n if n else 0.0),
    }


def _collect_reports(paths: List[str], results_dir: Optional[str]) -> List[tuple]:
    """Collect (path, report) for all valid matrix reports."""
    collected: List[tuple] = []
    if results_dir:
        pattern = os.path.join(results_dir, "**", "*matrix*report*.json")
        for p in glob.glob(pattern):
            r = _load_report(p)
            if r:
                collected.append((p, r))
        pattern2 = os.path.join(results_dir, "**", "*_report.json")
        for p in glob.glob(pattern2):
            if p not in [c[0] for c in collected]:
                r = _load_report(p)
                if r and _is_matrix_report(r):
                    collected.append((p, r))
    for p in paths:
        if p and os.path.isfile(p):
            r = _load_report(p)
            if r:
                collected.append((p, r))
    return collected


def build_aggregate(reports: List[tuple]) -> Dict[str, Any]:
    """Build aggregate report from (path, report) tuples."""
    by_target: Dict[str, Dict] = {}
    all_by_type: Dict[str, List[Dict]] = {t: [] for t in XSS_TYPE_ORDER}
    all_by_context: Dict[str, List[Dict]] = {c: [] for c in CONTEXT_ORDER}

    for path, data in reports:
        target = _get_target_name(path, data)
        summary = data.get("summary", {})
        by_target[target] = {"summary": summary, "path": path}

        for t in XSS_TYPE_ORDER:
            s = data.get("by_xss_type", {}).get(t, {})
            if s.get("total_cases", 0) > 0:
                all_by_type[t].append(s)
        for c in CONTEXT_ORDER:
            s = data.get("by_context", {}).get(c, {})
            if s.get("total_cases", 0) > 0:
                all_by_context[c].append(s)

    agg_by_type = {k: _aggregate_stats(v) if v else _aggregate_stats([]) for k, v in all_by_type.items()}
    agg_by_context = {k: _aggregate_stats(v) if v else _aggregate_stats([]) for k, v in all_by_context.items()}

    macro_type = _macro_average(agg_by_type, XSS_TYPE_ORDER)
    macro_context = _macro_average(agg_by_context, CONTEXT_ORDER)

    overall_summary = _aggregate_stats([r[1].get("summary", {}) for r in reports])

    return {
        "aggregate_report": "1.0",
        "num_targets": len(by_target),
        "targets": list(by_target.keys()),
        "overall_summary": overall_summary,
        "per_target": {t: by_target[t]["summary"] for t in by_target},
        "per_xss_type": agg_by_type,
        "per_context": agg_by_context,
        "macro_by_xss_type": macro_type,
        "macro_by_context": macro_context,
    }


def print_table(report: Dict) -> None:
    """Print human-readable console table."""
    print("\n--- Aggregate Report ---")
    print(f"Targets: {report.get('num_targets', 0)}")
    print(f"Overall: P={report['overall_summary'].get('precision', 0):.3f} "
          f"R={report['overall_summary'].get('recall', 0):.3f} "
          f"F1={report['overall_summary'].get('f1_score', 0):.3f}")

    m = report.get("macro_by_xss_type", {})
    print(f"Macro (by xss_type): P={m.get('macro_precision', 0):.3f} "
          f"R={m.get('macro_recall', 0):.3f} F1={m.get('macro_f1', 0):.3f}")

    m2 = report.get("macro_by_context", {})
    print(f"Macro (by context):  P={m2.get('macro_precision', 0):.3f} "
          f"R={m2.get('macro_recall', 0):.3f} F1={m2.get('macro_f1', 0):.3f}")

    print("\nPer-target F1:")
    for t, s in report.get("per_target", {}).items():
        print(f"  {t}: {s.get('f1_score', 0):.3f}")


def compare_with_baseline(report: Dict, baseline_path: str) -> bool:
    """
    Compare aggregate report against baseline. Returns True if no regressions.
    Uses compare_baseline logic for matrix comparison when baseline is a matrix report.
    """
    if not os.path.exists(baseline_path):
        print(f"Baseline not found: {baseline_path}", file=sys.stderr)
        return False
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            content = f.read()
        decoder = json.JSONDecoder()
        baseline, _ = decoder.raw_decode(content)  # parse first JSON object only
    except (json.JSONDecodeError, IOError) as e:
        print(f"Failed to load baseline: {e}", file=sys.stderr)
        return False
    if not _is_matrix_report(baseline):
        print("Baseline is not a matrix report; skipping comparison.", file=sys.stderr)
        return True

    curr = report.get("overall_summary", {})
    base = baseline.get("summary", {})
    curr_f1 = curr.get("f1_score", 0.0)
    base_f1 = base.get("f1_score", 0.0)
    if curr_f1 + 1e-9 < base_f1:
        print(f"[REGRESSION] Overall F1 dropped: {base_f1:.3f} -> {curr_f1:.3f}")
        return False

    base_by_type = baseline.get("by_xss_type", {})
    agg_by_type = report.get("per_xss_type", {})
    for t in XSS_TYPE_ORDER:
        base_t = base_by_type.get(t, {}).get("f1_score", 0.0)
        agg_t = agg_by_type.get(t, {}).get("f1_score", 0.0)
        if base_t > 0 and agg_t + 1e-9 < base_t:
            print(f"[REGRESSION] {t} F1 dropped: {base_t:.3f} -> {agg_t:.3f}")
            return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate aggregate benchmark report with per-target/type/context breakdowns and macro-averaged metrics."
    )
    parser.add_argument(
        "results",
        nargs="*",
        default=[],
        help="Result JSON files (matrix reports)",
    )
    parser.add_argument(
        "--results-dir",
        metavar="DIR",
        help="Directory to scan for *_report.json and *matrix*report*.json",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write aggregate JSON report to FILE",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        help="Compare against baseline matrix report and flag regressions",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Minimal console output",
    )
    args = parser.parse_args()

    reports = _collect_reports(args.results, args.results_dir)
    if not reports:
        print("No valid matrix reports found.", file=sys.stderr)
        sys.exit(1)

    report = build_aggregate(reports)

    if not args.quiet:
        print_table(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        if not args.quiet:
            print(f"\nReport saved to: {args.output}")

    if args.baseline:
        if not compare_with_baseline(report, args.baseline):
            sys.exit(1)


if __name__ == "__main__":
    main()
