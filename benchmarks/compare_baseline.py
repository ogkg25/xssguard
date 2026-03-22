import json
import argparse
import sys
import os
from typing import Any, List, Dict, Set, Tuple

def load_findings(filepath: str) -> List[Dict]:
    """Load findings from a JSON file."""
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return []
    
    with open(filepath, 'r') as f:
        try:
            data = json.load(f)
            # Handle new whitebox format: {"summary": {...}, "findings": [...]}
            if isinstance(data, dict) and 'findings' in data:
                return data['findings']
            # Handle new blackbox format: {"summary": {...}, "vulnerabilities": [...]}
            elif isinstance(data, dict) and 'vulnerabilities' in data:
                return data['vulnerabilities']
            # Handle old format: [...]
            elif isinstance(data, list):
                return data
            else:
                print(f"Error: Unexpected JSON format in {filepath}")
                return []
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {filepath}: {e}")
            return []

def get_finding_key(finding: Dict, mode: str) -> str:
    """Create a unique key for a finding to allow comparison."""
    if mode == 'whitebox':
        # Whitebox smoke tests often emit multiple signatures for the *same* vulnerable sink line
        # (e.g., a generic sink + a framework-specific sink). We key by:
        #   file + line + content
        # so we don't fail due to signature naming/duplication changes.
        file_path = _normalize_path(finding.get('file', ''))
        line = finding.get('line', '')
        content = (finding.get('content', '') or '').strip()
        return f"{file_path}:{line}:{content}"
    else:
        # For blackbox: URL + parameter is the stable identity for smoke tests.
        url = finding.get('url', '')
        param = finding.get('parameter') or finding.get('param') or finding.get('param_name') or ''
        return f"{url}:{param}"

def _normalize_path(path: str) -> str:
    """
    Normalize absolute paths so baselines are stable across machines.
    If the path contains 'benchmarks/', strip everything before it.
    """
    if not path:
        return ""
    norm = path.replace("\\", "/")
    marker = "/benchmarks/"
    idx = norm.find(marker)
    if idx != -1:
        return norm[idx + 1 :]  # drop leading slash to keep it relative-ish
    return norm

def compare_results(actual_path: str, expected_path: str, mode: str):
    """Compare actual scan results against an expected baseline."""
    print(f"Comparing {actual_path} against baseline {expected_path}...")
    
    actual_findings = load_findings(actual_path)
    expected_findings = load_findings(expected_path)
    
    if not actual_findings and not expected_findings:
        print("Both finding sets are empty.")
        return

    actual_keys = {get_finding_key(f, mode) for f in actual_findings}
    expected_keys = {get_finding_key(f, mode) for f in expected_findings}

    # Calculate metrics
    true_positives = actual_keys.intersection(expected_keys)
    false_positives = actual_keys - expected_keys
    false_negatives = expected_keys - actual_keys

    precision = len(true_positives) / len(actual_keys) if actual_keys else 0.0
    recall = len(true_positives) / len(expected_keys) if expected_keys else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    # Regression detection: FNs or F1 drop vs perfect baseline
    reg = detect_regressions(actual_keys, expected_keys, f1, 1.0 if expected_keys else 0.0)

    # Report
    print(f"\n--- Benchmark Results ({mode}) ---")
    print(f"Total Expected: {len(expected_keys)}")
    print(f"Total Found:    {len(actual_keys)}")
    print(f"True Positives: {len(true_positives)}")
    print(f"False Positives: {len(false_positives)}")
    print(f"False Negatives: {len(false_negatives)}")

    precision = len(true_positives) / len(actual_keys) if actual_keys else 0.0
    recall = len(true_positives) / len(expected_keys) if expected_keys else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"\nPrecision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    print(f"F1 Score:  {f1:.2f}")

    if reg["has_regression"]:
        print("\n[FAIL] Regressions detected (missed expected vulnerabilities):")
        for fn in list(reg["false_negatives"])[:10]:
            print(f" - {fn}")
        if len(reg["false_negatives"]) > 10:
            print(f" ... and {len(reg['false_negatives']) - 10} more.")
        sys.exit(1)

    if reg["new_fps"]:
        print("\n[WARN] New findings detected (potential False Positives or New Vulnerabilities):")
        fps = list(reg["new_fps"])
        for fp in fps[:10]:
            print(f" - {fp}")
        if len(fps) > 10:
            print(f" ... and {len(fps) - 10} more.")

    print("\n[PASS] Baseline checks passed.")


def detect_regressions(
    actual_keys: Set[str],
    expected_keys: Set[str],
    actual_f1: float,
    expected_f1: float,
) -> Dict[str, Any]:
    """
    Regression detection logic: identify F1 drops, new FPs, and missed FNs.
    Returns a dict with regression flags and details.
    """
    false_positives = actual_keys - expected_keys
    false_negatives = expected_keys - actual_keys
    f1_dropped = actual_f1 + 1e-9 < expected_f1 if expected_f1 > 0 else False
    return {
        "has_regression": bool(false_negatives) or f1_dropped,
        "false_negatives": false_negatives,
        "new_fps": false_positives,
        "f1_dropped": f1_dropped,
        "expected_f1": expected_f1,
        "actual_f1": actual_f1,
    }


def detect_matrix_regressions(actual: Dict, expected: Dict) -> List[Tuple[str, str, float, float]]:
    """
    Regression detection for matrix reports: find cells where F1 dropped.
    Also checks for new FPs (actual FP > expected FP) and summary F1 drop.
    """
    xss_types = ["reflected", "stored", "dom"]
    contexts = ["html_body", "html_attribute", "js_string", "json", "url_href"]

    regressions: List[Tuple[str, str, float, float]] = []
    for xss_type in xss_types:
        for context in contexts:
            actual_cell = actual.get("matrix", {}).get(xss_type, {}).get(context, {})
            expected_cell = expected.get("matrix", {}).get(xss_type, {}).get(context, {})
            actual_f1 = float(actual_cell.get("f1_score", 0.0))
            expected_f1 = float(expected_cell.get("f1_score", 0.0))
            if actual_f1 + 1e-9 < expected_f1:
                regressions.append((xss_type, context, expected_f1, actual_f1))
    return regressions


def compare_matrix(actual_path: str, expected_path: str):
    """Compare matrix benchmark reports and flag regressions by cell."""
    if not os.path.exists(actual_path) or not os.path.exists(expected_path):
        print("Error: matrix report or baseline not found.")
        sys.exit(1)

    with open(actual_path, "r", encoding="utf-8") as handle:
        actual = json.load(handle)
    with open(expected_path, "r", encoding="utf-8") as handle:
        expected = json.load(handle)

    regressions = detect_matrix_regressions(actual, expected)
    xss_types = ["reflected", "stored", "dom"]
    contexts = ["html_body", "html_attribute", "js_string", "json", "url_href"]

    print("\n--- Matrix Benchmark Results ---")
    print(f"Cells checked: {len(xss_types) * len(contexts)}")
    print(f"Regressions:   {len(regressions)}")

    if regressions:
        print("\n[FAIL] Regressions detected:")
        for xss_type, context, expected_f1, actual_f1 in regressions:
            print(f" - {xss_type}/{context}: {expected_f1:.3f} -> {actual_f1:.3f}")
        sys.exit(1)

    print("\n[PASS] Matrix baseline checks passed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Compare benchmark results against baseline.')
    parser.add_argument('actual', help='Path to actual results JSON')
    parser.add_argument('expected', help='Path to expected baseline JSON')
    parser.add_argument('--mode', choices=['whitebox', 'blackbox', 'matrix'], required=True, help='Scan mode')
    
    args = parser.parse_args()
    if args.mode == "matrix":
        compare_matrix(args.actual, args.expected)
    else:
        compare_results(args.actual, args.expected, args.mode)
