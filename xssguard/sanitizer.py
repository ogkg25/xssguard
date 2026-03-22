"""
HTML sanitization utilities for XSS prevention.
"""

from dataclasses import dataclass
from typing import Dict, Optional

import bleach


DEFAULT_POLICY = {
    "tags": [
        "b",
        "i",
        "u",
        "em",
        "strong",
        "p",
        "br",
        "ul",
        "ol",
        "li",
        "a",
        "code",
        "pre",
    ],
    "attributes": {
        "a": ["href", "title", "rel", "target"],
    },
    "protocols": ["http", "https", "mailto"],
    "strip": True,
    "strip_comments": True,
}


@dataclass
class SanitizationResult:
    """Result of sanitization."""

    clean_html: str
    changed: bool


def _merge_policy(base: Dict, override: Optional[Dict]) -> Dict:
    if not override:
        return base
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_policy(merged[key], value)
        else:
            merged[key] = value
    return merged


class HtmlSanitizer:
    """Sanitize HTML using an allowlist policy."""

    def __init__(self, policy: Optional[Dict] = None):
        merged = _merge_policy(DEFAULT_POLICY, policy)
        self._cleaner = bleach.Cleaner(
            tags=merged.get("tags", []),
            attributes=merged.get("attributes", {}),
            protocols=merged.get("protocols", []),
            strip=bool(merged.get("strip", True)),
            strip_comments=bool(merged.get("strip_comments", True)),
        )

    def sanitize(self, html: str) -> SanitizationResult:
        clean_html = self._cleaner.clean(html)
        return SanitizationResult(clean_html=clean_html, changed=clean_html != html)
