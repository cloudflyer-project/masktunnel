"""masktunnel: HTTP MITM proxy with browser fingerprint simulation."""

__version__ = "1.1.4"

from ._server import Server
from ._base import get_fingerprint_report, set_log_level

__all__ = ["Server", "get_fingerprint_report", "set_log_level"]
