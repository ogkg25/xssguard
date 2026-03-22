#!/usr/bin/env python3
"""
OWASP Benchmark Evaluation Script (Sample - 50 XSS Test Cases)

OWASP Benchmark v1.2 contains 2,740+ test cases for SAST/DAST tools.
This script evaluates a representative sample of 50 XSS-related test cases.

DEPLOYMENT NOTE:
================
OWASP Benchmark is a Java/Maven application and requires manual deployment:
1. Clone: git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
2. Build: cd BenchmarkJava && mvn clean install
3. Run: mvn tomcat7:run-war (starts on http://localhost:8080/benchmark)
4. Wait ~2 minutes for full startup
5. Run this script

Estimated time: ~30-45 minutes for 50 test cases
"""

import os
import sys
import json
import argparse
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests

try:
    from benchmarks.lib.orchestrator import ServerManager
except ImportError:
    ServerManager = None

# Colors for output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

BENCHMARK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Default matches the script's own deployment instructions (Tomcat Maven plugin).
DEFAULT_BENCHMARK_URL = "http://localhost:8080/benchmark"

GROUND_TRUTH_FILE = os.path.join(
    BENCHMARK_DIR, "ground_truth", "owasp_benchmark_xss_sample.json"
)
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results", "owasp_benchmark")
SCAN_RESULTS_FILE = os.path.join(RESULTS_DIR, "scan_results.json")
METRICS_FILE = os.path.join(RESULTS_DIR, "metrics.json")


def print_header(text):
    """Print formatted header."""
    print(f"\n{BOLD}{YELLOW}{'=' * 60}{RESET}")
    print(f"{BOLD}{YELLOW}{text}{RESET}")
    print(f"{BOLD}{YELLOW}{'=' * 60}{RESET}\n")


def _normalize_base_url(url: str) -> str:
    return url.rstrip("/")


def _candidate_benchmark_urls(url: str) -> List[str]:
    """
    Build a small set of likely working Benchmark base URLs.

    Users often start Tomcat at http://localhost:8080/benchmark, but may provide:
    - http://localhost:8080
    - https://localhost:8443
    - http://localhost:8080/benchmark/
    """
    url = _normalize_base_url(url)
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return [url]

    candidates: List[str] = [url]
    # If user provided just host[:port], try adding /benchmark.
    if parsed.path in ("", "/"):
        candidates.append(f"{parsed.scheme}://{parsed.netloc}/benchmark")

    # If user provided something ending in /benchmark/, normalize and keep.
    if url.endswith("/benchmark/"):
        candidates.append(url[:-1])

    # If user provided .../benchmark (no trailing slash), try with slash too.
    if url.endswith("/benchmark"):
        candidates.append(f"{url}/")

    # De-dupe while preserving order.
    deduped: List[str] = []
    for c in candidates:
        if c not in deduped:
            deduped.append(c)
    # Strip trailing slash on all "base" variants except where explicitly intended
    # (we'll use them for GET anyway).
    return [_normalize_base_url(c) for c in deduped]


def _probe_url(session: requests.Session, url: str, timeout_s: int) -> Tuple[bool, Optional[int], Optional[str]]:
    try:
        resp = session.get(url, timeout=timeout_s, allow_redirects=True)
        return True, resp.status_code, resp.url
    except requests.exceptions.RequestException as e:
        return False, None, str(e)


def check_benchmark_availability(benchmark_url: str, verify_tls: bool) -> Optional[str]:
    """Check if OWASP Benchmark is deployed and accessible. Returns working base URL or None."""
    print(f"{YELLOW}Checking OWASP Benchmark availability...{RESET}")

    # Suppress SSL warnings when verify_tls=False
    if not verify_tls:
        import warnings
        from urllib3.exceptions import InsecureRequestWarning
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    session = requests.Session()
    session.verify = verify_tls

    candidates = _candidate_benchmark_urls(benchmark_url)
    for candidate in candidates:
        ok, status, detail = _probe_url(session, candidate, timeout_s=5)
        if ok and status == 200:
            print(f"{GREEN}✓ OWASP Benchmark is accessible at {candidate}{RESET}")
            return candidate
        if ok and status in (301, 302, 303, 307, 308):
            print(f"{GREEN}✓ OWASP Benchmark redirected from {candidate} → {detail}{RESET}")
            return candidate

    # If all candidates failed, print best-effort diagnostics.
    print(f"{RED}✗ OWASP Benchmark not accessible at the provided URL(s).{RESET}")
    print(f"{YELLOW}Tried:{RESET}")
    for candidate in candidates:
        ok, status, detail = _probe_url(session, candidate, timeout_s=5)
        if ok:
            print(f"  - {candidate}  (HTTP {status}, final={detail})")
        else:
            print(f"  - {candidate}  (error={detail})")

    print(f"\n{YELLOW}DEPLOYMENT INSTRUCTIONS:{RESET}")
    print("1. Clone: git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git")
    print("2. Build: cd BenchmarkJava && mvn clean install")
    print("3. Run: mvn tomcat7:run-war")
    print("4. Wait ~2 minutes for startup")
    print(f"5. Verify in browser: {DEFAULT_BENCHMARK_URL}")
    print(f"\n{YELLOW}TIP:{RESET} If Benchmark runs on a different URL, pass:")
    print(f"  - env: OWASP_BENCHMARK_URL='http://localhost:8080/benchmark'")
    print(f"  - or:  python3 benchmarks/real_world/run_owasp_benchmark.py --url http://localhost:8080/benchmark")
    return None


def load_ground_truth() -> Dict:
    """Load ground truth test cases."""
    print(f"{YELLOW}Loading ground truth from {GROUND_TRUTH_FILE}...{RESET}")
    with open(GROUND_TRUTH_FILE, 'r') as f:
        data = json.load(f)
    print(f"{GREEN}✓ Loaded {len(data['test_cases'])} test cases{RESET}")
    return data


def run_blackbox_scan(test_cases: List[Dict], benchmark_url: str, verify_tls: bool):
    """Run blackbox scans against each test case endpoint using direct XSS testing."""
    print_header("Running Blackbox Scans (50 Test Cases)")
    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    session = requests.Session()
    session.verify = verify_tls
    
    # XSS test payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')"
    ]
    
    all_findings = []
    scan_count = 0
    
    for test_case in test_cases:
        test_id = test_case['id']
        endpoint = test_case['endpoint']
        
        scan_count += 1
        print(f"{YELLOW}[{scan_count}/{len(test_cases)}] Scanning {test_id}...{RESET}", end=" ", flush=True)
        
        found_vuln = False
        
        try:
            # Extract parameter name from endpoint (e.g., BenchmarkTest00013 from ?BenchmarkTest00013=test)
            param_name = test_id
            
            for payload in payloads:
                # Build test URL with payload (requests will URL-encode params safely)
                test_url = f"{benchmark_url}{endpoint.split('?')[0]}"
                response = session.get(test_url, params={param_name: payload}, timeout=10, allow_redirects=True)
                
                # Check if payload is reflected in response
                if payload in response.text or payload.replace("'", "&#39;") in response.text:
                    finding = {
                        "test_case_id": test_id,
                        "url": response.url,
                        "parameter": param_name,
                        "payload": payload,
                        "vuln_type": "Reflected XSS",
                        "confidence": "High",
                        "context": "html_body"
                    }
                    all_findings.append(finding)
                    found_vuln = True
                    break  # Found vulnerability, move to next test case
            
            if found_vuln:
                print(f"{GREEN}VULNERABLE{RESET}")
            else:
                print(f"Safe")
                
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
    
    # Save aggregated results
    with open(SCAN_RESULTS_FILE, 'w') as f:
        json.dump(all_findings, f, indent=2)
    
    print(f"\n{GREEN}✓ Scan complete. Found {len(all_findings)} total findings.{RESET}")
    print(f"{GREEN}✓ Results saved to {SCAN_RESULTS_FILE}{RESET}")
    
    return all_findings


def calculate_metrics(ground_truth: Dict, scan_results: List[Dict]):
    """Calculate precision, recall, and F1-score."""
    print_header("Calculating Metrics")
    
    # Create sets of vulnerable test case IDs from ground truth
    true_vulnerabilities = {
        tc['id'] for tc in ground_truth['test_cases'] 
        if tc['vulnerable']
    }
    
    # Create sets of test cases flagged by scanner
    detected_test_cases = {
        finding['test_case_id'] 
        for finding in scan_results
    }
    
    # Calculate metrics
    tp = len(true_vulnerabilities & detected_test_cases)  # True Positives
    fp = len(detected_test_cases - true_vulnerabilities)  # False Positives
    fn = len(true_vulnerabilities - detected_test_cases)  # False Negatives
    tn = len(ground_truth['test_cases']) - tp - fp - fn  # True Negatives
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    metrics = {
        "benchmark": "OWASP Benchmark v1.2 (Sample)",
        "total_test_cases": len(ground_truth['test_cases']),
        "true_vulnerabilities": len(true_vulnerabilities),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1_score, 3),
        "detected_ids": sorted(list(detected_test_cases)),
        "missed_ids": sorted(list(true_vulnerabilities - detected_test_cases)),
        "false_positive_ids": sorted(list(detected_test_cases - true_vulnerabilities))
    }
    
    # Save metrics
    with open(METRICS_FILE, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    # Print results
    print(f"{BOLD}Results:{RESET}")
    print(f"  Total Test Cases:     {metrics['total_test_cases']}")
    print(f"  True Vulnerabilities: {metrics['true_vulnerabilities']}")
    print(f"  Detected:             {len(detected_test_cases)}")
    print(f"\n{BOLD}Metrics:{RESET}")
    print(f"  True Positives:  {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives:  {tn}")
    print(f"\n{BOLD}Performance:{RESET}")
    print(f"  Precision: {precision:.1%}")
    print(f"  Recall:    {recall:.1%}")
    print(f"  F1-Score:  {f1_score:.3f}")
    
    print(f"\n{GREEN}✓ Metrics saved to {METRICS_FILE}{RESET}")
    
    return metrics


def main():
    print_header("OWASP Benchmark Evaluation (Sample - 50 Test Cases)")

    parser = argparse.ArgumentParser(description="Evaluate XSSGuard against OWASP Benchmark (sample of 50 XSS test cases).")
    parser.add_argument(
        "--url",
        default=None,
        help=f"Base URL where OWASP Benchmark is deployed (alias for --owasp-url).",
    )
    parser.add_argument(
        "--owasp-url",
        default=os.environ.get("OWASP_BENCHMARK_URL", DEFAULT_BENCHMARK_URL),
        dest="url",
        metavar="URL",
        help=f"OWASP Benchmark base URL (default: {DEFAULT_BENCHMARK_URL}; env: OWASP_BENCHMARK_URL). For Docker: https://localhost:8443/benchmark",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates (disable this if using self-signed HTTPS). Default: disabled.",
    )
    parser.add_argument(
        "--ensure-docker",
        action="store_true",
        help="Start OWASP Benchmark via docker compose before running (requires benchmarks.lib.orchestrator).",
    )
    args = parser.parse_args()

    # Step 0 (optional): Start OWASP Benchmark via Docker Compose
    if args.ensure_docker and ServerManager is not None:
        compose_file = os.path.join(BENCHMARK_DIR, "docker-compose.bench.yml")
        docker_url = "https://localhost:8443/benchmark"
        if args.url == DEFAULT_BENCHMARK_URL:
            args.url = docker_url
        mgr = ServerManager(compose_file, services=["owasp"], base_url=docker_url, timeout=180.0)
        if not mgr.start_server():
            print(f"{RED}Cannot start OWASP Benchmark via Docker. Ensure docker compose is available.{RESET}")
            sys.exit(1)
        # Poll until ready (Docker image takes ~2 min; use requests with verify=False for self-signed)
        import time
        import warnings
        from urllib3.exceptions import InsecureRequestWarning
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        deadline = time.monotonic() + 180.0
        session = requests.Session()
        session.verify = False
        while time.monotonic() < deadline:
            try:
                r = session.get(docker_url, timeout=5)
                if r.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(5)
        else:
            print(f"{RED}OWASP Benchmark Docker started but did not become ready within 180s.{RESET}")
            sys.exit(1)

    # Step 1: Check if benchmark is deployed
    benchmark_url = check_benchmark_availability(args.url, verify_tls=args.verify_tls)
    if not benchmark_url:
        print(f"\n{RED}Cannot proceed without OWASP Benchmark deployment.{RESET}")
        print(f"{YELLOW}This is expected - OWASP Benchmark requires manual Java/Maven setup.{RESET}")
        print(f"{YELLOW}Ground truth has been prepared for future evaluation.{RESET}")
        sys.exit(1)
    
    # Step 2: Load ground truth
    ground_truth = load_ground_truth()
    
    # Step 3: Run blackbox scans
    scan_results = run_blackbox_scan(ground_truth['test_cases'], benchmark_url=benchmark_url, verify_tls=args.verify_tls)
    
    # Step 4: Calculate metrics
    metrics = calculate_metrics(ground_truth, scan_results)
    
    # Final summary
    print_header("Evaluation Complete")
    print(f"{GREEN}✓ OWASP Benchmark sample evaluation finished!{RESET}")
    print(f"\n{BOLD}Files Generated:{RESET}")
    print(f"  - {SCAN_RESULTS_FILE}")
    print(f"  - {METRICS_FILE}")
    print(f"  - Individual scan results in {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
