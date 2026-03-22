#!/usr/bin/env python3
"""
Run the DVWA matrix benchmark against a running DVWA instance.

Requires: DVWA running (e.g., via Docker), optional session cookie for auth.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.matrix_runner import TargetAdapter, run_matrix_cases, score_and_report

BENCHMARK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH_FILE = os.path.join(BENCHMARK_DIR, "ground_truth", "dvwa_matrix_ground_truth.json")
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results", "real_world")
RAW_RESULTS_FILE = os.path.join(RESULTS_DIR, "dvwa_matrix_raw_results.json")
REPORT_FILE = os.path.join(RESULTS_DIR, "dvwa_matrix_report.json")
BASELINE_FILE = os.path.join(BENCHMARK_DIR, "baselines", "dvwa_matrix.json")


class DvwaAdapter(TargetAdapter):
    """Adapter for DVWA matrix benchmark. Expects DVWA already running (e.g., in Docker)."""

    def __init__(
        self,
        dvwa_url: str = "http://localhost:8081",
        cookie_file: str | None = None,
        cookie_env_var: str = "DVWA_COOKIE",
    ) -> None:
        self.dvwa_url = dvwa_url.rstrip("/")
        self.cookie_file = cookie_file
        self.cookie_env_var = cookie_env_var
        self.base_cookie: str | None = None

    def setup(self) -> None:
        """Load session cookie from file or env var."""
        if self.cookie_file and os.path.exists(self.cookie_file):
            with open(self.cookie_file, "r", encoding="utf-8") as f:
                self.base_cookie = f.read().strip()
            return
        if self.cookie_env_var and os.environ.get(self.cookie_env_var):
            self.base_cookie = os.environ[self.cookie_env_var].strip()
            return
        print("Warning: No DVWA session cookie found. Some endpoints may require auth.")
        print("  Tip: python benchmarks/real_world/get_dvwa_cookie.py")
        print("  Or set DVWA_COOKIE env var.")
        self.base_cookie = None

    def check_ready(self, base_url: str) -> bool:
        """Verify DVWA is accessible at base_url."""
        try:
            import urllib.request

            req = urllib.request.Request(
                f"{base_url.rstrip('/')}/",
                headers={"User-Agent": "DVWA-Matrix-Benchmark"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status in (200, 302)
        except Exception:
            try:
                req = urllib.request.Request(
                    f"{base_url.rstrip('/')}/login.php",
                    headers={"User-Agent": "DVWA-Matrix-Benchmark"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status in (200, 302)
            except Exception:
                return False

    def teardown(self) -> None:
        """No-op; Docker container stays running."""
        pass

    def build_url(self, base_url: str, case: dict) -> str:
        """Construct full URL from case (endpoint, param, vector)."""
        url = f"{base_url.rstrip('/')}{case['endpoint']}"
        if case.get("vector") == "query":
            param = case.get("param", "q")
            url += f"?{param}=test"
        return url

    def get_cookie(self, case: dict) -> str | None:
        """Return cookie string with security level for this case."""
        if not self.base_cookie:
            return None
        level = case.get("security_level", "low")
        return f"{self.base_cookie}; security={level}"

    def get_extra_flags(self, case: dict) -> list[str]:
        """Return extra xssguard flags for stored/DOM cases."""
        xss_type = case.get("xss_type")
        if xss_type == "stored":
            scope_path = case.get("endpoint", "/vulnerabilities/xss_s/")
            return ["--crawl", "--depth", "1", "--scope", scope_path]
        elif xss_type == "dom":
            # DOM XSS: disable crawl since we're testing specific URLs
            # Our new DOM detection works by analyzing the page source for sinks
            return ["--no-crawl", "--request-delay", "0"]
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DVWA matrix benchmark.")
    parser.add_argument(
        "--dvwa-url",
        default="http://localhost:8081",
        help="DVWA base URL (default: http://localhost:8081)",
    )
    parser.add_argument(
        "--cookie-file",
        default=os.path.join(os.path.dirname(__file__), ".dvwa_cookie"),
        help="Path to file containing DVWA session cookie",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Enable headless verification for DOM cases",
    )
    parser.add_argument(
        "--xss-type",
        help="Filter by XSS type (reflected/stored/dom)",
    )
    parser.add_argument(
        "--context",
        help="Filter by context (html_body/html_attribute/etc.)",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Copy report to baselines/dvwa_matrix.json",
    )
    args = parser.parse_args()

    dvwa_url = args.dvwa_url.rstrip("/")
    adapter = DvwaAdapter(
        dvwa_url=dvwa_url,
        cookie_file=args.cookie_file,
    )

    try:
        raw_results = run_matrix_cases(
            adapter,
            GROUND_TRUTH_FILE,
            RESULTS_DIR,
            dvwa_url,
            verify=args.verify,
            xss_type=args.xss_type,
            context=args.context,
        )
    except RuntimeError:
        print(f"Error: DVWA not accessible at {dvwa_url}")
        print("Tip: Start DVWA with: docker-compose -f benchmarks/docker-compose.bench.yml up -d dvwa")
        print("Tip: Get auth cookie with: python benchmarks/real_world/get_dvwa_cookie.py")
        sys.exit(1)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RAW_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(raw_results, f, indent=2)
    print(f"Raw results saved to: {RAW_RESULTS_FILE}")

    if not score_and_report(RAW_RESULTS_FILE, REPORT_FILE):
        print("Warning: scoring failed; raw results were still written.")
        sys.exit(1)

    if args.generate:
        import shutil

        shutil.copy(REPORT_FILE, BASELINE_FILE)
        print(f"Baseline copied to: {BASELINE_FILE}")


if __name__ == "__main__":
    main()
