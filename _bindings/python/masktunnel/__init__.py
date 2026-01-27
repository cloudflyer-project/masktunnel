"""masktunnel: Python bindings for MaskTunnel (Go).

This package provides a Python-friendly API on top of the generated native bindings.
"""

__version__ = "1.0.17"

from ._server import Server, ServerOptions
from ._utils import set_log_level

__all__ = ["Server", "set_log_level"]
