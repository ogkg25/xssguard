"""
Unified CLI for XSSGuard Framework.
Provides access to both white-box and black-box scanners.
"""

import os
import sys
from typing import Optional
from urllib.parse import urlparse

import click
import yaml
from rich.console import Console

from blackbox_scanner.scanner import BlackBoxScanner
from blackbox_scanner.verifier.headless import HeadlessVerifier
from whitebox_scanner.scanner import WhiteBoxScanner
from xssguard.config import Config
from xssguard.logging import configure_logging
from xssguard.reporting import (
    get_reporter,
    summarize_findings,
    summarize_vulnerabilities,
)
from xssguard.sanitizer import HtmlSanitizer

console = Console()

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
CONFIDENCE_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Confirmed": 3}


def _normalize_severity(value: str) -> str:
    return value[:1].upper() + value[1:].lower()


def _normalize_confidence(value: str) -> str:
    if value.lower() == "confirmed":
        return "Confirmed"
    return value[:1].upper() + value[1:].lower()


def _filter_by_min_severity(findings, min_severity: str):
    min_sev = _normalize_severity(min_severity)
    min_rank = SEVERITY_ORDER.get(min_sev, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_rank]


def _filter_by_min_confidence(vulns, min_confidence: str):
    min_conf = _normalize_confidence(min_confidence)
    min_rank = CONFIDENCE_ORDER.get(min_conf, 0)
    return [v for v in vulns if CONFIDENCE_ORDER.get(v.confidence, 0) >= min_rank]


@click.group()
@click.version_option(version="1.0.0", prog_name="XSSGuard")
@click.option("--config", "-c", type=click.Path(exists=True), help="Configuration file")
@click.option(
    "--verbosity",
    type=click.Choice(["quiet", "normal", "verbose"]),
    help="Logging verbosity override",
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], verbosity: Optional[str]):
    """
    XSSGuard - Cross-Site Scripting Detection Framework

    A dual-approach tool for detecting XSS vulnerabilities using
    both static (white-box) and dynamic (black-box) analysis.

    \b
    Examples:
        xssguard whitebox ./src
        xssguard blackbox http://example.com --crawl
        xssguard sanitize --input unsafe.html --output-file safe.html
    """
    cfg = Config.load(config)
    if verbosity:
        cfg.set("global.verbosity", verbosity)
    configure_logging(cfg.get("global.verbosity", "normal"))
    ctx.obj = {"config": cfg, "console": console}


@cli.command("whitebox")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Choice(["console", "json", "html"]), default=None)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Minimum severity to report",
)
@click.option("--output-file", "-f", type=click.Path(), help="Output file path")
@click.option("--fail-on", type=click.Choice(["low", "medium", "high", "critical"]))
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Ignore sanitizers; report all findings at original confidence (no reduction)",
)
@click.pass_context
def whitebox_scan(
    ctx: click.Context,
    target: str,
    output: Optional[str],
    min_severity: Optional[str],
    output_file: Optional[str],
    fail_on: Optional[str],
    strict: bool,
):
    """
    Perform white-box (static) analysis on source code.

    TARGET can be a file path or directory path.
    """
    cfg: Config = ctx.obj["config"]
    console.print(f"[bold blue][*][/bold blue] Starting white-box scan of: {target}")

    scanner_config = dict(cfg.get_section("whitebox") or {})
    scanner_config["strict"] = strict
    scanner = WhiteBoxScanner(config=scanner_config)

    if os.path.isfile(target):
        findings = scanner.scan_file(target)
    else:
        findings = scanner.scan_project(target)

    min_severity = min_severity or cfg.get("whitebox.min_severity", "medium")
    findings = _filter_by_min_severity(findings, min_severity)

    output_format = output or cfg.get("global.output_format", "console")
    if output_format == "console" and output_file:
        raise click.UsageError("Console output does not support --output-file.")
    summary = summarize_findings(findings)
    reporter = get_reporter(output_format, console=console)
    reporter.write_whitebox(findings, summary, output_file)

    filtered_findings = _filter_by_min_severity(findings, fail_on) if fail_on else findings
    sys.exit(1 if filtered_findings else 0)


@cli.command("blackbox")
@click.argument("url")
@click.option("--crawl/--no-crawl", default=None, help="Enable crawling")
@click.option("--depth", "-d", type=int, default=None, help="Crawl depth")
@click.option("--max-pages", type=int, default=None, help="Maximum pages to crawl")
@click.option("--scope", type=str, default=None, help="Restrict crawling to URLs matching this path prefix (e.g., '/vulnerabilities/xss_r/')")
@click.option("--output", "-o", type=click.Choice(["console", "json", "html"]), default=None)
@click.option("--verify/--no-verify", default=None, help="Verify with headless browser")
@click.option("--output-file", "-f", type=click.Path(), help="Output file path")
@click.option("--fail-on", type=click.Choice(["low", "medium", "high", "confirmed"]))
@click.option("--cookie", type=str, help="Session cookie for authentication (e.g., 'PHPSESSID=abc123')")
@click.option("--request-delay", type=float, default=None, help="Delay between requests in seconds (default: 0.1)")
@click.pass_context
def blackbox_scan(
    ctx: click.Context,
    url: str,
    crawl: Optional[bool],
    depth: Optional[int],
    max_pages: Optional[int],
    scope: Optional[str],
    output: Optional[str],
    verify: Optional[bool],
    output_file: Optional[str],
    fail_on: Optional[str],
    cookie: Optional[str],
    request_delay: Optional[float],
):
    """
    Perform black-box (dynamic) analysis on a web application.
    """
    cfg: Config = ctx.obj["config"]
    console.print(f"[bold blue][*][/bold blue] Starting black-box scan of: {url}")

    scanner_config = cfg.get_section("blackbox")
    crawl_cfg = scanner_config.get("crawl", {})
    payload_cfg = scanner_config.get("payloads", {})

    effective_config = dict(scanner_config)
    effective_config.update(
        {
            "max_depth": depth if depth is not None else crawl_cfg.get("max_depth", 2),
            "max_pages": max_pages if max_pages is not None else crawl_cfg.get("max_pages", 100),
            "same_domain_only": crawl_cfg.get("same_domain_only", True),
            "max_per_param": payload_cfg.get("max_per_param", 10),
            "scope_path": scope if scope is not None else crawl_cfg.get("scope_path", None),
            "request_delay": request_delay if request_delay is not None else scanner_config.get("request_delay", 0.1),
        }
    )

    scanner = BlackBoxScanner(config=effective_config)
    
    # Set authentication cookie if provided
    if cookie:
        scanner.set_cookie(cookie)

    crawl_enabled = crawl if crawl is not None else crawl_cfg.get("enabled", False)
    if crawl_enabled:
        console.print(
            f"[bold blue][*][/bold blue] Crawling enabled (depth: {effective_config['max_depth']})"
        )
        if scope:
            console.print(
                f"[bold blue][*][/bold blue] Scope restriction: {scope}"
            )
        vulnerabilities = scanner.crawl_and_scan(url)
    else:
        vulnerabilities = scanner.scan_url(url)

    verify_enabled = verify if verify is not None else scanner_config.get("verification", {}).get(
        "headless", False
    )
    if verify_enabled and vulnerabilities:
        console.print("[bold blue][*][/bold blue] Verifying with headless browser...")
        verification_cfg = scanner_config.get("verification", {})
        verifier = HeadlessVerifier(
            timeout=effective_config.get("timeout", 10),
            browser=verification_cfg.get("browser", "chromium"),
            wait_time_ms=verification_cfg.get("wait_time", 1000),
        )
        verified_vulns = []
        # Build Playwright cookies from the scanner's requests session for authenticated targets.
        # We attach them for the hostname of the URL being verified.
        def _playwright_cookies_for(url: str):
            hostname = urlparse(url).hostname or ""
            return [
                {"name": c.name, "value": c.value, "domain": hostname, "path": "/"}
                for c in scanner.session.cookies
            ]

        with console.status("[bold green]Verifying vulnerabilities..."):
            for vuln in vulnerabilities:
                verify_url = None
                if isinstance(getattr(vuln, "request_details", None), dict):
                    verify_url = vuln.request_details.get("verify_url")
                if not verify_url:
                    verify_url = scanner._inject_url_param(vuln.url, vuln.parameter, vuln.payload)

                result = verifier.verify_xss(verify_url, cookies=_playwright_cookies_for(verify_url))
                if result.get("executed"):
                    vuln.confidence = "Confirmed"
                    verified_vulns.append(vuln)
        vulnerabilities = verified_vulns

    output_format = output or cfg.get("global.output_format", "console")
    if output_format == "console" and output_file:
        raise click.UsageError("Console output does not support --output-file.")
    summary = summarize_vulnerabilities(vulnerabilities)
    reporter = get_reporter(output_format, console=console)
    reporter.write_blackbox(vulnerabilities, summary, output_file)

    filtered_findings = _filter_by_min_confidence(vulnerabilities, fail_on) if fail_on else vulnerabilities
    sys.exit(1 if filtered_findings else 0)


@cli.command("benchmark")
@click.option(
    "--target",
    type=click.Choice(["synthetic", "dvwa", "juiceshop", "all"]),
    default="synthetic",
    help="Benchmark target (synthetic, dvwa, juiceshop, all)",
)
@click.option(
    "--mode",
    type=click.Choice(["whitebox", "blackbox", "both"]),
    default="both",
    help="Scanner mode (whitebox, blackbox, both)",
)
@click.option("--verify/--no-verify", default=True, help="Enable headless verification")
@click.option("--baseline", type=click.Path(exists=True), default=None, help="Path to baseline file for comparison")
@click.pass_context
def benchmark_cmd(
    ctx: click.Context,
    target: str,
    mode: str,
    verify: bool,
    baseline: Optional[str],
):
    """
    Run benchmark suite with configurable target and scanner mode.
    """
    cfg: Config = ctx.obj["config"]
    console.print(f"[bold blue][*][/bold blue] Running benchmark (target={target}, mode={mode})...")
    if baseline:
        console.print(f"[bold blue][*][/bold blue] Baseline: {baseline}")
    if not verify:
        console.print("[dim]Verification disabled.[/dim]")


@cli.command("sanitize")
@click.option("--input", "-i", "input_path", type=click.Path(exists=True))
@click.option("--stdin", is_flag=True, help="Read HTML from stdin")
@click.option("--output-file", "-o", type=click.Path(), help="Output file path")
@click.option("--policy", type=click.Path(exists=True), help="Sanitization policy YAML")
@click.pass_context
def sanitize_html(
    ctx: click.Context,
    input_path: Optional[str],
    stdin: bool,
    output_file: Optional[str],
    policy: Optional[str],
):
    """
    Sanitize HTML content to prevent XSS.
    """
    cfg: Config = ctx.obj["config"]
    if not input_path and not stdin:
        raise click.UsageError("Provide --input or --stdin.")

    if input_path:
        with open(input_path, "r", encoding="utf-8") as handle:
            html = handle.read()
    else:
        html = sys.stdin.read()

    policy_data = cfg.get_section("sanitizer").get("policy", {})
    if policy:
        with open(policy, "r", encoding="utf-8") as handle:
            loaded_policy = yaml.safe_load(handle) or {}
        policy_data = loaded_policy

    sanitizer = HtmlSanitizer(policy=policy_data)
    result = sanitizer.sanitize(html)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write(result.clean_html)
        console.print(f"[bold green][+][/bold green] Sanitized output written to: {output_file}")
    else:
        print(result.clean_html)

    if result.changed:
        console.print("[bold yellow][!][/bold yellow] Sanitizer removed unsafe content.")


if __name__ == "__main__":
    cli()
