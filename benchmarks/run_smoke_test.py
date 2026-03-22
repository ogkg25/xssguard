#!/usr/bin/env python3
import subprocess
import os
import sys
import argparse
import datetime
import time
import shutil
import socket
import signal

# Configuration
BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
SYNTHETIC_DIR = os.path.join(BENCHMARK_DIR, "smoke_targets")
BASELINE_WHITEBOX = os.path.join(BENCHMARK_DIR, "baselines", "whitebox.json")
BASELINE_BLACKBOX = os.path.join(BENCHMARK_DIR, "baselines", "blackbox.json")
BASELINE_MATRIX = os.path.join(BENCHMARK_DIR, "baselines", "matrix.json")
BASELINE_DVWA_MATRIX = os.path.join(BENCHMARK_DIR, "baselines", "dvwa_matrix.json")
BASELINE_JUICESHOP_MATRIX = os.path.join(BENCHMARK_DIR, "baselines", "juiceshop_matrix.json")
VULNERABLE_SERVER_PORT = 5555
XSSGUARD_CMD = os.environ.get("XSSGUARD_CMD")  # optional override

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'


def _ts() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_command(cmd, output_file=None, allowed_exit_codes=None):
    """Run a shell command and optionally capture output to a file."""
    if allowed_exit_codes is None:
        allowed_exit_codes = [0]

    print(f"{YELLOW}[{_ts()}] Running: {cmd}{RESET}")
    cmd_start = time.perf_counter()
    try:
        result = subprocess.run(cmd, shell=True, check=False, text=True, capture_output=True)
        elapsed = time.perf_counter() - cmd_start

        if result.returncode in allowed_exit_codes:
            print(f"{GREEN}[{_ts()}] Success in {elapsed:.2f}s.{RESET}")
            return True
        else:
            print(f"{RED}[{_ts()}] Error (exit {result.returncode}) after {elapsed:.2f}s:{RESET}")
            print(f"STDOUT:\n{result.stdout}")
            print(f"STDERR:\n{result.stderr}")
            return False

    except Exception as e:
        elapsed = time.perf_counter() - cmd_start
        print(f"{RED}[{_ts()}] Exception after {elapsed:.2f}s:{RESET}")
        print(str(e))
        return False

def check_xssguard_installed():
    """Check if xssguard is installed and available."""
    global XSSGUARD_CMD
    # Prefer the installed entrypoint if present; otherwise fall back to module execution.
    if not XSSGUARD_CMD:
        XSSGUARD_CMD = "xssguard" if shutil.which("xssguard") else f"{sys.executable} -m xssguard.cli"
    try:
        subprocess.run(f"{XSSGUARD_CMD} --help", shell=True, capture_output=True, check=True, text=True)
        return True
    except subprocess.CalledProcessError:
        print(f"{RED}Error: unable to run XSSGuard CLI via: {XSSGUARD_CMD}{RESET}")
        print(f"{YELLOW}Tip: set XSSGUARD_CMD='python -m xssguard.cli' or install with: pip install -e .{RESET}")
        return False

def is_port_open(port, host='127.0.0.1'):
    """Check if a port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def start_vulnerable_server():
    """Start the vulnerable test server in background."""
    print(f"{YELLOW}Starting vulnerable test server on port {VULNERABLE_SERVER_PORT}...{RESET}")
    
    server_script = os.path.join(SYNTHETIC_DIR, "vulnerable_server.py")
    
    # Start server in background
    process = subprocess.Popen(
        [sys.executable, server_script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid if hasattr(os, 'setsid') else None
    )
    
    # Wait for server to be ready (max 5 seconds)
    for i in range(50):
        if is_port_open(VULNERABLE_SERVER_PORT):
            print(f"{GREEN}Server ready!{RESET}")
            return process
        time.sleep(0.1)
    
    print(f"{RED}Server failed to start!{RESET}")
    process.kill()
    return None

def stop_vulnerable_server(process):
    """Stop the vulnerable test server."""
    if process:
        print(f"{YELLOW}Stopping server...{RESET}")
        try:
            if hasattr(os, 'killpg'):
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=3)
        except:
            process.kill()
        print(f"{GREEN}Server stopped.{RESET}")

def run_whitebox(generate=False):
    """Run the whitebox benchmark."""
    phase_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] --- Starting Whitebox Benchmark ---{RESET}")
    
    output_target = BASELINE_WHITEBOX if generate else "current_whitebox.json"
    
    # Command to scan the smoke target directory
    # -f specifies the output file
    # --output json specifies JSON format
    cmd = f"{XSSGUARD_CMD} whitebox {SYNTHETIC_DIR} --output json -f {output_target}"
    
    # xssguard returns 1 if vulnerabilities are found, which is expected here
    if run_command(cmd, allowed_exit_codes=[0, 1]):
        if generate:
            print(f"{GREEN}Baseline generated at: {BASELINE_WHITEBOX}{RESET}")
        else:
            # Compare
            compare_script = os.path.join(BENCHMARK_DIR, "compare_baseline.py")
            compare_cmd = f"python3 {compare_script} {output_target} {BASELINE_WHITEBOX} --mode whitebox"
            subprocess.run(compare_cmd, shell=True)

            # Clean up
            if os.path.exists(output_target):
                os.remove(output_target)

    elapsed = time.perf_counter() - phase_start
    print(f"{GREEN}[{_ts()}] --- Whitebox Benchmark finished in {elapsed:.2f}s ---{RESET}")

def run_blackbox(generate=False):
    """Run the blackbox benchmark against the smoke-test vulnerable server."""
    phase_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] --- Starting Blackbox Benchmark (Smoke Test) ---{RESET}")
    
    # Start the vulnerable server
    server_process = start_vulnerable_server()
    if not server_process:
        print(f"{RED}Failed to start vulnerable server. Skipping blackbox test.{RESET}")
        return
    
    try:
        target_url = f"http://127.0.0.1:{VULNERABLE_SERVER_PORT}"
        output_target = BASELINE_BLACKBOX if generate else "current_blackbox.json"
        
        # Smoke test command: crawl the vulnerable server
        cmd = f"{XSSGUARD_CMD} blackbox {target_url} --crawl --depth 2 --output json -f {output_target}"
        
        # xssguard returns 1 if vulnerabilities are found, which is expected here
        if run_command(cmd, allowed_exit_codes=[0, 1]):
            if generate:
                print(f"{GREEN}Baseline generated at: {BASELINE_BLACKBOX}{RESET}")
            else:
                # Compare
                compare_script = os.path.join(BENCHMARK_DIR, "compare_baseline.py")
                compare_cmd = f"python3 {compare_script} {output_target} {BASELINE_BLACKBOX} --mode blackbox"
                subprocess.run(compare_cmd, shell=True)
                
                # Clean up
                if os.path.exists(output_target):
                    os.remove(output_target)
    finally:
        stop_vulnerable_server(server_process)
        elapsed = time.perf_counter() - phase_start
        print(f"{GREEN}[{_ts()}] --- Blackbox Benchmark finished in {elapsed:.2f}s ---{RESET}")


def run_matrix(generate=False):
    """Run the matrix benchmark and optionally update baseline."""
    phase_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] --- Starting Matrix Benchmark ---{RESET}")

    matrix_runner = os.path.join(BENCHMARK_DIR, "run_matrix_benchmark.py")
    score_script = os.path.join(BENCHMARK_DIR, "score_matrix.py")
    compare_script = os.path.join(BENCHMARK_DIR, "compare_baseline.py")
    raw_results = os.path.join(BENCHMARK_DIR, "results", "matrix_raw_results.json")
    report_path = os.path.join(BENCHMARK_DIR, "results", "matrix_report.json")

    # Run benchmark
    # This is a Python runner script, not the xssguard CLI itself.
    # Treat non-zero exit as a real failure (e.g., server couldn't start).
    if not run_command(f"{sys.executable} {matrix_runner}", allowed_exit_codes=[0]):
        return

    # Score
    if not run_command(f"{sys.executable} {score_script} --input {raw_results} --output {report_path}"):
        return

    if generate:
        try:
            import shutil
            shutil.copyfile(report_path, BASELINE_MATRIX)
            print(f"{GREEN}Baseline generated at: {BASELINE_MATRIX}{RESET}")
        except Exception as e:
            print(f"{RED}Failed to write baseline: {e}{RESET}")
    else:
        compare_cmd = f"{sys.executable} {compare_script} {report_path} {BASELINE_MATRIX} --mode matrix"
        subprocess.run(compare_cmd, shell=True)

    elapsed = time.perf_counter() - phase_start
    print(f"{GREEN}[{_ts()}] --- Matrix Benchmark finished in {elapsed:.2f}s ---{RESET}")


def run_dvwa_matrix(generate=False):
    """Run the DVWA matrix benchmark and optionally update baseline."""
    phase_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] --- Starting DVWA Matrix Benchmark ---{RESET}")

    dvwa_runner = os.path.join(BENCHMARK_DIR, "real_world", "run_dvwa_matrix.py")
    compare_script = os.path.join(BENCHMARK_DIR, "compare_baseline.py")
    report_path = os.path.join(BENCHMARK_DIR, "results", "real_world", "dvwa_matrix_report.json")
    baseline = BASELINE_DVWA_MATRIX

    # Run benchmark
    generate_flag = "--generate" if generate else ""
    if not run_command(f"{sys.executable} {dvwa_runner} {generate_flag}", allowed_exit_codes=[0]):
        return

    if not generate:
        compare_cmd = f"{sys.executable} {compare_script} {report_path} {baseline} --mode matrix"
        subprocess.run(compare_cmd, shell=True)

    elapsed = time.perf_counter() - phase_start
    print(f"{GREEN}[{_ts()}] --- DVWA Matrix Benchmark finished in {elapsed:.2f}s ---{RESET}")


def run_juiceshop_matrix(generate=False):
    """Run the Juice Shop matrix benchmark and optionally update baseline."""
    phase_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] --- Starting Juice Shop Matrix Benchmark ---{RESET}")

    juiceshop_runner = os.path.join(BENCHMARK_DIR, "real_world", "run_juiceshop_matrix.py")
    compare_script = os.path.join(BENCHMARK_DIR, "compare_baseline.py")
    report_path = os.path.join(BENCHMARK_DIR, "results", "real_world", "juiceshop_matrix_report.json")
    baseline = BASELINE_JUICESHOP_MATRIX

    # Run benchmark
    generate_flag = "--generate" if generate else ""
    if not run_command(f"{sys.executable} {juiceshop_runner} {generate_flag}", allowed_exit_codes=[0]):
        return

    if not generate:
        compare_cmd = f"{sys.executable} {compare_script} {report_path} {baseline} --mode matrix"
        subprocess.run(compare_cmd, shell=True)

    elapsed = time.perf_counter() - phase_start
    print(f"{GREEN}[{_ts()}] --- Juice Shop Matrix Benchmark finished in {elapsed:.2f}s ---{RESET}")


def main():
    parser = argparse.ArgumentParser(description='Run XSSGuard Smoke Test Benchmarks')
    parser.add_argument('--generate', action='store_true', help='Generate new baselines instead of comparing')
    parser.add_argument('--mode', choices=['all', 'whitebox', 'blackbox', 'matrix', 'dvwa-matrix', 'juiceshop-matrix'], default='all', help='Which benchmarks to run')

    args = parser.parse_args()

    if not check_xssguard_installed():
        sys.exit(1)

    suite_start = time.perf_counter()
    print(f"\n{YELLOW}[{_ts()}] XSSGuard benchmark suite started (mode={args.mode}){RESET}")

    if args.mode in ['all', 'whitebox']:
        run_whitebox(args.generate)

    if args.mode in ['all', 'blackbox']:
        run_blackbox(args.generate)

    if args.mode in ['all', 'matrix']:
        run_matrix(args.generate)

    if args.mode in ['all', 'dvwa-matrix']:
        run_dvwa_matrix(args.generate)

    if args.mode in ['all', 'juiceshop-matrix']:
        run_juiceshop_matrix(args.generate)

    total_elapsed = time.perf_counter() - suite_start
    print(f"\n{GREEN}[{_ts()}] XSSGuard benchmark suite finished — total elapsed: {total_elapsed:.2f}s{RESET}")


if __name__ == "__main__":
    main()
