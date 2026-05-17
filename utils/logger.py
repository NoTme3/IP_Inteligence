"""Structured logging with rich console output."""

from __future__ import annotations

import logging
import sys

from rich.logging import RichHandler


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure and return the application-wide logger.

    Parameters
    ----------
    level:
        Logging level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).

    Returns
    -------
    logging.Logger
        The root ``ip_intel`` logger.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Root ip_intel logger
    logger = logging.getLogger("ip_intel")
    logger.setLevel(numeric_level)

    # Prevent duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    # Rich console handler — pretty, coloured output
    console_handler = RichHandler(
        level=numeric_level,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
        show_time=True,
        show_path=False,
        markup=True,
    )
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("ipwhois").setLevel(logging.WARNING)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``ip_intel`` namespace."""
    return logging.getLogger(f"ip_intel.{name}")
