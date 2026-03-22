#!/usr/bin/env python3
"""
Run the Juice Shop matrix benchmark against a running OWASP Juice Shop instance.

Requires: Juice Shop running (e.g., via Docker), optional token for auth.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lib.matrix_runner import TargetAdapter, run_matrix_cases, score_and_report

BENCHMARK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROUND_TRUTH_FILE = os.path.join(BENCHMARK_DIR, "ground_truth", "juiceshop_matrix_ground_truth.json")
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results", "real_world")
RAW_RESULTS_FILE = os.path.join(RESULTS_DIR, "juiceshop_matrix_raw_results.json")
REPORT_FILE = os.path.join(RESULTS_DIR, "juiceshop_matrix_report.json")
BASELINE_FILE = os.path.join(BENCHMARK_DIR, "baselines", "juiceshop_matrix.json")


class JuiceShopAdapter(TargetAdapter):
    """Adapter for Juice Shop matrix benchmark. Expects Juice Shop already running (e.g., in Docker)."""

    def __init__(
        self,
        juiceshop_url: str = "http://localhost:3000",
        token_file: str | None = None,
        token_env_var: str = "JUICESHOP_TOKEN",
    ) -> None:
        self.juiceshop_url = juiceshop_url.rstrip("/")
        self.token_file = token_file
        self.token_env_var = token_env_var
        self.token: str | None = None

    def setup(self) -> None:
        """Load JWT token from file or env var."""
        if self.token_file and os.path.exists(self.token_file):
            with open(self.token_file, "r", encoding="utf-8") as f:
                raw = f.read().strip()
                self.token = raw if raw.startswith("token=") else f"token={raw}"
            return
        if self.token_env_var and os.environ.get(self.token_env_var):
            raw = os.environ[self.token_env_var].strip()
            self.token = raw if raw.startswith("token=") else f"token={raw}"
            return
        print("Warning: No Juice Shop token found. Some endpoints may require auth.")
        print("  Tip: Log in to Juice Shop and copy the 'token' cookie value")
        print("  Or set JUICESHOP_TOKEN env var.")
        self.token = None

    def check_ready(self, base_url: str) -> bool:
        """Verify Juice Shop is accessible at base_url via admin version endpoint."""
        try:
            import urllib.request

            url = f"{base_url.rstrip('/')}/rest/admin/application-version"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "JuiceShop-Matrix-Benchmark"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def teardown(self) -> None:
        """No-op; Docker container stays running."""
        pass

    def build_url(self, base_url: str, case: dict) -> str:
        """Construct full URL from case (endpoint, param, vector)."""
        url = f"{base_url.rstrip('/')}{case['endpoint']}"
        vector = case.get("vector", "query")
        if vector == "query":
            param = case.get("param", "q")
            url += f"?{param}=test"
        # form and header: URL is endpoint only; form/header injection handled by xssguard
        return url

    def get_cookie(self, case: dict) -> str | None:
        """Return token cookie if present."""
        return self.token

    def get_extra_flags(self, case: dict) -> list[str]:
        """Return extra xssguard flags for stored form-like cases or DOM with verify."""
        xss_type = case.get("xss_type")
        vector = case.get("vector", "")

        # Stored form-like cases: use crawl and scope
        if xss_type == "stored" and vector == "form":
            scope_path = case.get("endpoint", "/#/contact")
            return ["--crawl", "--depth", "1", "--scope", scope_path]

        # DOM cases with verify enabled: runner already passes --verify when requires_browser
        # No additional flags needed here; verify is global CLI flag
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Juice Shop matrix benchmark.")
    parser.add_argument(
        "--juiceshop-url",
        default="http://localhost:3000",
        help="Juice Shop base URL (default: http://localhost:3000)",
    )
    parser.add_argument(
        "--token-file",
        default=os.path.join(os.path.dirname(__file__), ".juiceshop_token"),
        help="Path to file containing Juice Shop token cookie value",
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
        help="Copy report to baselines/juiceshop_matrix.json",
    )
    args = parser.parse_args()

    juiceshop_url = args.juiceshop_url.rstrip("/")
    adapter = JuiceShopAdapter(
        juiceshop_url=juiceshop_url,
        token_file=args.token_file,
    )

    try:
        raw_results = run_matrix_cases(
            adapter,
            GROUND_TRUTH_FILE,
            RESULTS_DIR,
            juiceshop_url,
            verify=args.verify,
            xss_type=args.xss_type,
            context=args.context,
        )
    except RuntimeError:
        print(f"Error: Juice Shop not accessible at {juiceshop_url}")
        print("Tip: Start Juice Shop with: docker run -d -p 3000:3000 bkimminich/juice-shop")
        print("Tip: Log in via UI and copy the 'token' cookie into benchmarks/real_world/.juiceshop_token")
        print("     Or set JUICESHOP_TOKEN env var to the raw JWT value.")
        sys.exit(1)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(RAW_RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(raw_results, f, indent=2)
    print(f"Raw results saved to: {RAW_RESULTS_FILE}")

    if not score_and_report(RAW_RESULTS_FILE, REPORT_FILE):
        print("Warning: scoring failed; raw results were still written.")
        sys.exit(1)

    print(f"Scored report saved to: {REPORT_FILE}")

    if args.generate:
        import shutil

        shutil.copy(REPORT_FILE, BASELINE_FILE)
        print(f"Baseline copied to: {BASELINE_FILE}")


if __name__ == "__main__":
    main()
