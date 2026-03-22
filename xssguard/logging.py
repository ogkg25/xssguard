"""
Logging helpers for XSSGuard.
"""

import logging
from typing import Optional


VERBOSITY_LEVELS = {
    "quiet": logging.ERROR,
    "normal": logging.INFO,
    "verbose": logging.DEBUG,
}


def configure_logging(verbosity: Optional[str] = None) -> None:
    """Configure application-wide logging."""
    level = VERBOSITY_LEVELS.get((verbosity or "normal").lower(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
