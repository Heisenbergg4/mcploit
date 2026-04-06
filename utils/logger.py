"""Logging setup for MCPloit."""

import logging
from rich.logging import RichHandler


def setup_logger(name: str = "mcploit", level: int = logging.INFO) -> logging.Logger:
    """Configure and return a logger with Rich handler."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = RichHandler(
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    logger.setLevel(level)
    return logger


log = setup_logger()
