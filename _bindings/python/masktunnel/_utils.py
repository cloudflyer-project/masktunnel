"""Utility functions for masktunnel.

This module provides utility functions and re-exports from _base for backward compatibility.
"""

from __future__ import annotations

import logging

# Import from _base instead of masktunnellib
from ._base import _stop_log_listener, set_log_level

_logger = logging.getLogger("masktunnel")

# Re-export for backward compatibility
__all__ = ["set_log_level", "_stop_log_listener", "_logger"]
