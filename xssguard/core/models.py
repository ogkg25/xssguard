"""
Core data models for XSSGuard.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Finding:
    """Represents a potential vulnerability finding.

    confidence: Expected values are "Low", "Medium", "High".
    """

    file: str
    line: int
    content: str
    signature: str
    severity: str = "Medium"
    description: str = ""
    remediation: str = ""
    confidence: str = "Medium"


@dataclass
class Vulnerability:
    """Represents a detected XSS vulnerability."""

    url: str
    parameter: str
    payload: str
    vuln_type: str
    confidence: str
    context: str = ""
    request_details: Dict = field(default_factory=dict)
    response_snippet: str = ""


@dataclass
class InputVector:
    """Represents a potential injection point."""

    url: str
    method: str
    param_name: str
    param_type: str  # 'query', 'form', 'path'
    # For form vectors, the page where the form was discovered (used to refetch tokens / verify persistence)
    page_url: Optional[str] = None
    # For form vectors, the resolved action URL (usually same as url, but kept for clarity/matching)
    form_action: Optional[str] = None
    # Index of the form on the page (stable enough for benchmarks; used to re-identify the form)
    form_index: Optional[int] = None