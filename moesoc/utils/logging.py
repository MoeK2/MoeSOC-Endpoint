"""Application diagnostics logging (separate from Windows security telemetry).

Diagnostic logs must never contain raw event XML, credentials or full command
lines. Log counts, record IDs and error categories instead.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
MAX_LOG_BYTES = 1_000_000
LOG_BACKUP_COUNT = 5

_configured = False


def configure_logging(
    log_dir: Path,
    level: int = logging.INFO,
    console: bool = False,
    filename: str = "moesoc.log",
) -> None:
    """Configure the ``moesoc`` logger with a rotating file handler. Idempotent.

    Each process writes its own file: ``moesoc.log`` (console), ``sensor.log``,
    ``tray.log``.
    """
    global _configured
    if _configured:
        return

    logger = logging.getLogger("moesoc")
    logger.setLevel(level)
    formatter = logging.Formatter(LOG_FORMAT)

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / filename,
            maxBytes=MAX_LOG_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # Logging must never stop the application from starting.
        console = True

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        logger.addHandler(stream)

    _configured = True
