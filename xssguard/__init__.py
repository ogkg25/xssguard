"""
XSSGuard - Cross-Site Scripting Detection Framework

A comprehensive dual-approach framework that combines white-box (static) and 
black-box (dynamic) analysis for XSS vulnerability detection.
"""

__version__ = "1.0.0"
__author__ = "Krushna Gaurkar"
__license__ = "MIT"

def __getattr__(name: str):
    """
    Lazy attribute access to avoid importing heavy / circular modules at package import time.

    In particular, importing `xssguard.core.*` should not pull in the CLI (which imports scanners).
    """
    if name == "cli":
        from .cli import cli  # local import to avoid circular import during package init

        return cli
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["cli"]
