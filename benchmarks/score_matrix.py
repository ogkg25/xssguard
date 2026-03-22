#!/usr/bin/env python3
"""
Score XSS matrix benchmark results.
Produces per-type, per-context, and type x context metrics.
"""

import argparse
import json
import os
from typing import Dict, List, Optional, Tuple

DEFAULT_RESULTS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "results", "matrix_raw_results.json"
)
DEFAULT_REPORT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "results", "matrix_report.json"
)

XSS_TYPE_ORDER = ["reflected", "stored", "dom"]
CONTEXT_ORDER = ["html_body", "html_attribute", "js_string", "json", "url_href"]


def _calc_stats(cases: List[Dict]) -> Dict:
    tp = fp = fn = tn = 0
    skipped = 0
    errors = 0
    for case in cases:
        if case.get("skipped"):
            skipped += 1
            continue
        if case.get("error"):
            errors += 1
            continue
        vulnerable = bool(case.get("vulnerable"))
        found = bool(case.get("found"))
        if vulnerable and found:
            tp += 1
        elif vulnerable and not found:
            fn += 1
        elif not vulnerable and found:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "total_cases": len(cases),
        "skipped": skipped,
        "errors": errors,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
    }


def _bucket_cases(cases: List[Dict], key: str) -> Dict[str, List[Dict]]:
    buckets: Dict[str, List[Dict]] = {}
    for case in cases:
        value = case.get(key, "unknown")
        buckets.setdefault(value, []).append(case)
    return buckets


def _format_cell(stats: Optional[Dict]) -> str:
    if not stats or stats.get("total_cases", 0) == 0:
        return "--"
    return f"{stats.get('f1_score', 0):.3f}"


def print_confusion_matrix(stats: Dict, label: str = "Summary") -> None:
    """Print confusion matrix counts (TP, FP, FN, TN) for a stats dict."""
    tp = stats.get("true_positives", 0)
    fp = stats.get("false_positives", 0)
    fn = stats.get("false_negatives", 0)
    tn = stats.get("true_negatives", 0)
    print(f"\nConfusion matrix ({label}):")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Score XSS matrix benchmark results.")
    parser.add_argument("--input", default=DEFAULT_RESULTS, help="Path to matrix_raw_results.json")
    parser.add_argument("--output", default=DEFAULT_REPORT, help="Path to write matrix_report.json")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as handle:
        raw = json.load(handle)

    cases = raw.get("cases", [])

    by_type = {k: _calc_stats(v) for k, v in _bucket_cases(cases, "xss_type").items()}
    by_context = {k: _calc_stats(v) for k, v in _bucket_cases(cases, "context").items()}

    matrix: Dict[str, Dict[str, Dict]] = {}
    for xss_type in XSS_TYPE_ORDER:
        matrix[xss_type] = {}
        for context in CONTEXT_ORDER:
            subset = [c for c in cases if c.get("xss_type") == xss_type and c.get("context") == context]
            matrix[xss_type][context] = _calc_stats(subset)

    report = {
        "benchmark": raw.get("benchmark", "XSS Matrix"),
        "version": raw.get("version", "unknown"),
        "timestamp": raw.get("timestamp"),
        "verify_enabled": raw.get("verify_enabled", False),
        "summary": _calc_stats(cases),
        "by_xss_type": by_type,
        "by_context": by_context,
        "matrix": matrix,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print("XSS Type x Context Matrix (F1 scores)")
    header = "            " + "  ".join(f"{c:>10}" for c in CONTEXT_ORDER) + "  TOTAL"
    print(header)
    for xss_type in XSS_TYPE_ORDER:
        row = [f"{xss_type:<10}"]
        for context in CONTEXT_ORDER:
            row.append(f"{_format_cell(matrix.get(xss_type, {}).get(context)):>10}")
        row.append(f"{_format_cell(by_type.get(xss_type)):>6}")
        print("  ".join(row))
    total_row = ["TOTAL     "]
    for context in CONTEXT_ORDER:
        total_row.append(f"{_format_cell(by_context.get(context)):>10}")
    total_row.append(f"{_format_cell(report['summary']):>6}")
    print("  ".join(total_row))

    print_confusion_matrix(report["summary"])

    print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()
