#!/usr/bin/env python3
"""
Run the XSS matrix benchmark against the synthetic matrix server.
"""

import argparse
import datetime
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
SMOKE_DIR = os.path.join(BENCHMARK_DIR, "smoke_targets")
GROUND_TRUTH_FILE = os.path.join(BENCHMARK_DIR, "ground_truth", "matrix_ground_truth.json")
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results")
RAW_RESULTS_FILE = os.path.join(RESULTS_DIR, "matrix_raw_results.json")
REPORT_FILE = os.path.join(RESULTS_DIR, "matrix_report.json")
MATRIX_SERVER_PORT = 5556
XSSGUARD_CMD = os.environ.get("XSSGUARD_CMD")

from lib.matrix_runner import TargetAdapter, run_matrix_cases, score_and_report

GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def _ts() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _phase_start(name: str) -> float:
    t = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] Phase [{name}] started{RESET}")
    return t


def _phase_end(name: str, start: float) -> None:
    elapsed = time.perf_counter() - start
    print(f"{GREEN}[{_ts()}] Phase [{name}] completed in {elapsed:.2f}s{RESET}")


def check_xssguard_installed() -> bool:
    """Check if xssguard is installed and available."""
    global XSSGUARD_CMD
    if not XSSGUARD_CMD:
        XSSGUARD_CMD = "xssguard" if shutil.which("xssguard") else f"{sys.executable} -m xssguard.cli"
    try:
        subprocess.run(f"{XSSGUARD_CMD} --help", shell=True, capture_output=True, check=True, text=True)
        return True
    except subprocess.CalledProcessError:
        print(f"Error: unable to run XSSGuard CLI via: {XSSGUARD_CMD}")
        print("Tip: set XSSGUARD_CMD='python -m xssguard.cli' or install with: pip install -e .")
        return False


def _is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _tail_file(path: str, max_lines: int = 80) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        return "".join(lines[-max_lines:])
    except Exception:
        return ""


class SmokeAdapter(TargetAdapter):
    """Adapter for the synthetic matrix server (Flask on port 5556)."""

    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._started_by_us: bool = False

    def setup(self) -> None:
        """Start the matrix server on port 5556, or reuse if already running."""
        if _is_port_open(MATRIX_SERVER_PORT):
            print(f"Matrix server already running on port {MATRIX_SERVER_PORT}; reusing it.")
            self._process = None
            self._started_by_us = False
            return

        server_script = os.path.join(SMOKE_DIR, "matrix_server.py")
        server_log = os.path.join(RESULTS_DIR, "matrix_server.log")
        os.makedirs(RESULTS_DIR, exist_ok=True)
        log_handle = open(server_log, "w", encoding="utf-8")

        self._process = subprocess.Popen(
            [sys.executable, server_script],
            stdout=log_handle,
            stderr=log_handle,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )

        for _ in range(50):
            if _is_port_open(MATRIX_SERVER_PORT):
                self._started_by_us = True
                return
            time.sleep(0.1)

        try:
            self._process.kill()
        finally:
            log_handle.close()

        self._process = None
        self._started_by_us = False
        log_tail = _tail_file(server_log)
        if log_tail:
            print("\n--- matrix_server.log (tail) ---")
            print(log_tail.rstrip())
            print("--- end log ---\n")
        else:
            print(f"Matrix server failed to start; no logs captured at: {server_log}")

    def teardown(self) -> None:
        """Stop the matrix server process if we started it."""
        if not self._started_by_us or not self._process:
            return
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
            else:
                self._process.terminate()
            self._process.wait(timeout=3)
        except Exception:
            self._process.kill()
        self._process = None
        self._started_by_us = False

    def check_ready(self, base_url: str) -> bool:
        """Check if port 5556 is open."""
        return _is_port_open(MATRIX_SERVER_PORT)

    def build_url(self, base_url: str, case: dict) -> str:
        """Build URL from base_url + endpoint, with query param if vector=='query'."""
        endpoint = case["endpoint"]
        if case.get("vector") == "query":
            param = case.get("param", "q")
            return f"{base_url}{endpoint}?{param}=test"
        return f"{base_url}{endpoint}"

    def get_cookie(self, case: dict) -> str | None:
        """No auth needed for smoke server."""
        return None

    def get_extra_flags(self, case: dict) -> list:
        """No special flags needed."""
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="Run XSS matrix benchmark.")
    parser.add_argument("--xss-type", dest="xss_type", help="Filter by XSS type (reflected/stored/dom)")
    parser.add_argument("--context", dest="context", help="Filter by context (html_body/html_attribute/js_string/json/url_href)")
    parser.add_argument("--verify", action="store_true", help="Enable headless verification for DOM cases")
    parser.add_argument(
        "--no-score",
        action="store_true",
        help="Only write matrix_raw_results.json (do not generate matrix_report.json).",
    )
    args = parser.parse_args()

    if not check_xssguard_installed():
        sys.exit(1)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    base_url = f"http://127.0.0.1:{MATRIX_SERVER_PORT}"

    suite_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] Matrix benchmark suite started{RESET}")

    # Phase 1: run matrix cases (setup + scan + teardown)
    t1 = _phase_start("matrix cases")
    adapter = SmokeAdapter()
    results = run_matrix_cases(
        adapter,
        GROUND_TRUTH_FILE,
        RESULTS_DIR,
        base_url,
        verify=args.verify,
        xss_type=args.xss_type,
        context=args.context,
        xssguard_cmd=XSSGUARD_CMD,
    )
    _phase_end("matrix cases", t1)

    # Phase 2: write raw results
    t2 = _phase_start("write raw results")
    with open(RAW_RESULTS_FILE, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    _phase_end("write raw results", t2)
    print(f"  -> saved to: {RAW_RESULTS_FILE}")

    # Phase 3: scoring
    if not args.no_score:
        t3 = _phase_start("scoring")
        if not score_and_report(RAW_RESULTS_FILE, REPORT_FILE):
            print("Warning: scoring failed; raw results were still written.")
        _phase_end("scoring", t3)

    total_elapsed = time.perf_counter() - suite_start
    print(f"\n{GREEN}[{_ts()}] Matrix benchmark suite finished — total elapsed: {total_elapsed:.2f}s{RESET}")


if __name__ == "__main__":
    main()
