"""
Reporting utilities for XSSGuard.
"""

import json
from dataclasses import dataclass, field
from typing import Optional, Sequence

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from xssguard.core.models import Finding, Vulnerability


@dataclass
class ReportSummary:
    total: int
    counts: dict = field(default_factory=dict)


def summarize_findings(findings: Sequence[Finding]) -> ReportSummary:
    counts: dict = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return ReportSummary(total=len(findings), counts=counts)


def summarize_vulnerabilities(vulns: Sequence[Vulnerability]) -> ReportSummary:
    counts: dict = {}
    for vuln in vulns:
        counts[vuln.confidence] = counts.get(vuln.confidence, 0) + 1
    return ReportSummary(total=len(vulns), counts=counts)


class Reporter:
    def write_whitebox(
        self,
        findings: Sequence[Finding],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        raise NotImplementedError

    def write_blackbox(
        self,
        vulns: Sequence[Vulnerability],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        raise NotImplementedError


class ConsoleReporter(Reporter):
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def write_whitebox(
        self,
        findings: Sequence[Finding],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        if output_file:
            raise ValueError("Console reporter does not support output files.")
        if not findings:
            self.console.print("[bold green][+][/bold green] No vulnerabilities found!")
            return
        self.console.print(
            f"\n[bold red][!][/bold red] Found {summary.total} potential vulnerabilities:\n"
        )
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim")
        table.add_column("Confidence", style="dim")
        table.add_column("File:Line", style="cyan")
        table.add_column("Pattern")
        table.add_column("Description", max_width=50)
        for finding in findings:
            severity_color = {
                "Critical": "bold red",
                "High": "red",
                "Medium": "yellow",
                "Low": "white",
            }.get(finding.severity, "white")
            confidence_color = {
                "High": "green",
                "Medium": "yellow",
                "Low": "white",
            }.get(finding.confidence, "white")
            table.add_row(
                f"[{severity_color}]{finding.severity}[/{severity_color}]",
                f"[{confidence_color}]{finding.confidence}[/{confidence_color}]",
                f"{finding.file}:{finding.line}",
                finding.signature,
                finding.description,
            )
        self.console.print(table)
        self.console.print("\n[bold]Summary:[/bold]")
        self.console.print(f"  Total findings: {summary.total}")
        for sev, count in sorted(summary.counts.items()):
            self.console.print(f"  {sev}: {count}")

    def write_blackbox(
        self,
        vulns: Sequence[Vulnerability],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        if output_file:
            raise ValueError("Console reporter does not support output files.")
        if not vulns:
            self.console.print("[bold green][+][/bold green] No vulnerabilities found!")
            return
        self.console.print(f"\n[bold red][!][/bold red] Found {summary.total} vulnerabilities:\n")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Confidence", style="dim")
        table.add_column("Type")
        table.add_column("URL", max_width=40)
        table.add_column("Parameter")
        table.add_column("Context")
        for vuln in vulns:
            confidence_color = {
                "Confirmed": "bold green",
                "High": "green",
                "Medium": "yellow",
                "Low": "white",
            }.get(vuln.confidence, "white")
            table.add_row(
                f"[{confidence_color}]{vuln.confidence}[/{confidence_color}]",
                vuln.vuln_type,
                vuln.url[:40] + "..." if len(vuln.url) > 40 else vuln.url,
                vuln.parameter,
                vuln.context,
            )
        self.console.print(table)
        self.console.print(f"\n[bold]Summary:[/bold] {summary.total} vulnerabilities found")


class JsonReporter(Reporter):
    def _write(self, payload: dict, output_file: Optional[str]) -> None:
        result = json.dumps(payload, indent=2)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as file:
                file.write(result)
        else:
            print(result)

    def write_whitebox(
        self,
        findings: Sequence[Finding],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        output_data = [
            {
                "file": f.file,
                "line": f.line,
                "content": f.content,
                "signature": f.signature,
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation,
                "confidence": f.confidence,
            }
            for f in findings
        ]
        self._write(
            {"summary": {"total": summary.total, "counts": summary.counts}, "findings": output_data},
            output_file,
        )

    def write_blackbox(
        self,
        vulns: Sequence[Vulnerability],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        output_data = [
            {
                "url": v.url,
                "parameter": v.parameter,
                "payload": v.payload,
                "type": v.vuln_type,
                "confidence": v.confidence,
                "context": v.context,
            }
            for v in vulns
        ]
        self._write(
            {"summary": {"total": summary.total, "counts": summary.counts}, "vulnerabilities": output_data},
            output_file,
        )


class HtmlReporter(Reporter):
    _whitebox_template = Template(
        """
<!DOCTYPE html>
<html>
<head>
  <title>{{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    th { background-color: #4CAF50; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .critical { color: #d32f2f; font-weight: bold; }
    .high { color: #f44336; }
    .medium { color: #ff9800; }
    .low { color: #666; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <p>Total findings: {{ summary.total }}</p>
  <table>
    <tr>
      <th>Severity</th>
      <th>Confidence</th>
      <th>File</th>
      <th>Line</th>
      <th>Pattern</th>
      <th>Description</th>
      <th>Remediation</th>
    </tr>
    {% for f in findings %}
    <tr>
      <td class="{{ f.severity|lower }}">{{ f.severity }}</td>
      <td>{{ f.confidence }}</td>
      <td>{{ f.file }}</td>
      <td>{{ f.line }}</td>
      <td>{{ f.signature }}</td>
      <td>{{ f.description }}</td>
      <td>{{ f.remediation }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""
    )

    _blackbox_template = Template(
        """
<!DOCTYPE html>
<html>
<head>
  <title>{{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    th { background-color: #4CAF50; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .confirmed { color: #4CAF50; font-weight: bold; }
    .high { color: #f44336; }
    .medium { color: #ff9800; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <p>Total vulnerabilities: {{ summary.total }}</p>
  <table>
    <tr>
      <th>Confidence</th>
      <th>Type</th>
      <th>URL</th>
      <th>Parameter</th>
      <th>Payload</th>
      <th>Context</th>
    </tr>
    {% for v in vulnerabilities %}
    <tr>
      <td class="{{ v.confidence|lower }}">{{ v.confidence }}</td>
      <td>{{ v.vuln_type }}</td>
      <td style="word-break: break-all;">{{ v.url }}</td>
      <td>{{ v.parameter }}</td>
      <td><code>{{ v.payload[:100] }}</code></td>
      <td>{{ v.context }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""
    )

    def _write(self, content: str, output_file: Optional[str]) -> None:
        if output_file:
            with open(output_file, "w", encoding="utf-8") as file:
                file.write(content)
        else:
            print(content)

    def write_whitebox(
        self,
        findings: Sequence[Finding],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        content = self._whitebox_template.render(
            title="White-Box Scan Results",
            summary=summary,
            findings=findings,
        )
        self._write(content, output_file)

    def write_blackbox(
        self,
        vulns: Sequence[Vulnerability],
        summary: ReportSummary,
        output_file: Optional[str],
    ) -> None:
        content = self._blackbox_template.render(
            title="Black-Box Scan Results",
            summary=summary,
            vulnerabilities=vulns,
        )
        self._write(content, output_file)


def get_reporter(output_format: str, console: Optional[Console] = None) -> Reporter:
    normalized = output_format.lower()
    if normalized == "json":
        return JsonReporter()
    if normalized == "html":
        return HtmlReporter()
    return ConsoleReporter(console=console)
