from __future__ import annotations

import logging


_logger = logging.getLogger("masktunnel")


def set_log_level(level: int) -> None:
    """Set python-side log level.

    Go-side logging is currently controlled by the Go application.
    This helper only adjusts the default Python logger used by the wrappers.
    """
    _logger.setLevel(level)
