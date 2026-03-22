#!/usr/bin/env python3
"""
Score whitebox scanner results against ground truth.
Computes Precision, Recall, and F1 for whitebox XSS findings.
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Set, Tuple

DEFAULT_GROUND_TRUTH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "ground_truth",
    "whitebox_ground_truth.json",
)


def _normalize_path(path: str) -> str:
    """Normalize file path for stable matching across machines."""
    if not path:
        return ""
    norm = path.replace("\\", "/")
    marker = "/benchmarks/"
    idx = norm.find(marker)
    if idx != -1:
        return norm[idx + 1:]
    return norm


def _finding_key(file_path: str, line: int, signature: str) -> str:
    """Create a unique key for a finding."""
    return f"{_normalize_path(file_path)}:{line}:{signature}"


def load_ground_truth(path: str) -> List[Dict]:
    """Load ground truth findings from JSON."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", [])
    if isinstance(findings, list):
        return findings
    return []


def load_scanner_output(path: str) -> List[Dict]:
    """Load whitebox scanner findings from JSON."""
    if not os.path.exists(path):
        print(f"Error: Scanner output file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    if isinstance(data, list):
        return data
    print("Error: Unexpected JSON format (expected {'findings': [...]} or [...])", file=sys.stderr)
    sys.exit(1)


def compute_metrics(
    predicted: List[Dict],
    ground_truth: List[Dict],
) -> Tuple[int, int, int, float, float, float]:
    """
    Compute TP, FP, FN and Precision, Recall, F1.
    Match on (normalized file, line, signature).
    """
    gt_keys: Set[str] = set()
    for f in ground_truth:
        k = _finding_key(
            f.get("file", ""),
            f.get("line", 0),
            f.get("signature", ""),
        )
        gt_keys.add(k)

    pred_keys: Set[str] = set()
    for f in predicted:
        k = _finding_key(
            f.get("file", ""),
            f.get("line", 0),
            f.get("signature", ""),
        )
        pred_keys.add(k)

    tp = len(pred_keys & gt_keys)
    fp = len(pred_keys - gt_keys)
    fn = len(gt_keys - pred_keys)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return tp, fp, fn, precision, recall, f1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Score whitebox XSS scanner results against ground truth.",
    )
    parser.add_argument(
        "results",
        nargs="?",
        default=None,
        help="Path to whitebox scanner JSON output file",
    )
    parser.add_argument(
        "--ground-truth",
        "-g",
        default=DEFAULT_GROUND_TRUTH,
        help="Path to ground truth JSON file (default: benchmarks/ground_truth/whitebox_ground_truth.json)",
    )
    args = parser.parse_args()

    if not args.results:
        parser.print_help()
        sys.exit(0)

    if not os.path.exists(args.ground_truth):
        print(f"Error: Ground truth file not found: {args.ground_truth}", file=sys.stderr)
        sys.exit(1)

    gt_findings = load_ground_truth(args.ground_truth)
    pred_findings = load_scanner_output(args.results)

    tp, fp, fn, precision, recall, f1 = compute_metrics(pred_findings, gt_findings)

    print("\n--- Whitebox Benchmark Results ---")
    print(f"{'Metric':<20} {'Value':>10}")
    print("-" * 32)
    print(f"{'True Positives':<20} {tp:>10}")
    print(f"{'False Positives':<20} {fp:>10}")
    print(f"{'False Negatives':<20} {fn:>10}")
    print(f"{'Precision':<20} {precision:>10.3f}")
    print(f"{'Recall':<20} {recall:>10.3f}")
    print(f"{'F1 Score':<20} {f1:>10.3f}")
    print()


if __name__ == "__main__":
    main()
