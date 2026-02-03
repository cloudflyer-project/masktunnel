"""Base classes and utilities for masktunnel.

This module contains shared functionality used by Server class.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Union

_BACKEND: str

from masktunnel_ffi import cancel_log_waiters as _ffi_cancel_log_waiters
from masktunnel_ffi import parse_duration as _ffi_parse_duration
from masktunnel_ffi import seconds as _ffi_seconds
from masktunnel_ffi import wait_for_log_entries as _ffi_wait_for_log_entries

_BACKEND = "ffi"

_logger = logging.getLogger(__name__)

# Type aliases
DurationLike = Union[int, float, timedelta, str]


def _to_duration(value: Optional[DurationLike]) -> Any:
    """Convert seconds/str/timedelta to Go time.Duration via bindings.
    
    - None -> 0
    - int/float -> seconds (supports fractions)
    - timedelta -> total seconds
    - str -> parsed by Go (e.g., "1.5s", "300ms")
    
    Returns an int since Go's time.Duration is int64.
    """
    if value is None:
        return 0
    if isinstance(value, timedelta):
        seconds = value.total_seconds()
        return int(seconds * int(_ffi_seconds()))
    if isinstance(value, (int, float)):
        return int(value * int(_ffi_seconds()))
    if isinstance(value, str):
        try:
            return int(_ffi_parse_duration(value))
        except Exception as exc:
            raise ValueError(f"Invalid duration string: {value}") from exc
    raise TypeError(f"Unsupported duration type: {type(value)!r}")


class _NoopLogger:
    def __call__(self, *args: Any, **kwargs: Any) -> None:
        return None


class _DummyManagedLogger:
    def __init__(self, py_logger: logging.Logger, logger_id: str):
        self.py_logger = py_logger
        self.logger_id = logger_id
        self.go_logger = _NoopLogger()

    def cleanup(self) -> None:
        return None


def _json_key(snake: str) -> str:
    return snake


class _FFIServerOption:
    def __init__(self) -> None:
        self._cfg: Dict[str, Any] = {}

    def WithLogger(self, logger: Any) -> None:
        logger_id: Optional[str] = None
        if isinstance(logger, str):
            logger_id = logger
        else:
            logger_id = getattr(logger, "logger_id", None)
        if logger_id:
            self._cfg[_json_key("logger_id")] = str(logger_id)

    def WithAddr(self, v: str) -> None:
        self._cfg[_json_key("addr")] = v

    def WithPort(self, v: int) -> None:
        self._cfg[_json_key("port")] = str(v)

    def WithUserAgent(self, v: str) -> None:
        self._cfg[_json_key("user_agent")] = v

    def WithPayload(self, v: str) -> None:
        self._cfg[_json_key("payload")] = v

    def WithUpstreamProxy(self, v: str) -> None:
        self._cfg[_json_key("upstream_proxy")] = v

    def WithUsername(self, v: str) -> None:
        self._cfg[_json_key("username")] = v

    def WithPassword(self, v: str) -> None:
        self._cfg[_json_key("password")] = v

    def WithVerbose(self, v: bool) -> None:
        self._cfg[_json_key("verbose")] = 1 if v else 0

    def to_cfg(self) -> Dict[str, Any]:
        return dict(self._cfg)


class _FFIRawServer:
    def __init__(self, cfg: Dict[str, Any]):
        from masktunnel_ffi import Server as FFIServer

        self._srv = FFIServer(cfg)

    def Start(self) -> None:
        self._srv.start()

    def StartBackground(self) -> None:
        self._srv.start_background()

    def Stop(self) -> None:
        self._srv.stop()

    def Close(self) -> None:
        self._srv.close()

    def Addr(self) -> str:
        return self._srv.addr()

    def ResetSessions(self) -> int:
        return self._srv.reset_sessions()

    def SetUpstreamProxy(self, proxy: str) -> None:
        self._srv.set_upstream_proxy(proxy)

    def GetCAPEM(self) -> bytes:
        return self._srv.get_ca_pem()


class _FFIBackend:
    def DefaultServerOption(self) -> Any:
        return _FFIServerOption()

    def NewMaskTunnelServer(self, opt: Any) -> Any:
        return _FFIRawServer(opt.to_cfg())

    def NewLoggerWithID(self, _logger_id: str) -> Any:
        return str(_logger_id)

    def NewLogger(self, _cb: Any) -> Any:
        return f"logger_{id(_cb)}"

    def WaitForLogEntries(self, ms: int) -> list[Any]:
        try:
            entries = _ffi_wait_for_log_entries(int(ms))  # type: ignore[misc]
            if not entries:
                return []
            out: List[Any] = []
            for e in entries:
                if isinstance(e, dict):
                    out.append({
                        "LoggerID": e.get("LoggerID") or e.get("logger_id") or "",
                        "Message": e.get("Message") or e.get("message") or "",
                        "Time": e.get("Time") or e.get("time") or 0,
                    })
            return out
        except Exception:
            time.sleep(max(int(ms), 1) / 1000.0)
            return []

    def CancelLogWaiters(self) -> None:
        try:
            _ffi_cancel_log_waiters()  # type: ignore[misc]
        except Exception:
            return None

    def Second(self) -> int:
        return int(_ffi_seconds())  # type: ignore[misc]

    def ParseDuration(self, s: str) -> int:
        return int(_ffi_parse_duration(s))  # type: ignore[misc]


backend = _FFIBackend()


# Shared Go->Python log dispatcher
_def_level_map = {
    "trace": logging.DEBUG,
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.CRITICAL,
    "panic": logging.CRITICAL,
}


def _emit_go_log(py_logger: logging.Logger, line: str) -> None:
    """Process a Go log line and emit it to the Python logger."""
    try:
        obj = json.loads(line)
    except Exception:
        py_logger.info(line)
        return

    if not isinstance(obj, dict):
        py_logger.info(str(obj))
        return

    level = str(obj.get("level", "")).lower()
    message = obj.get("message") or obj.get("msg") or ""
    if message is None:
        message = ""
    message = str(message)

    extras: Dict[str, Any] = {}
    for k, v in obj.items():
        if k in ("level", "time", "message", "msg"):
            continue
        extras[k] = v

    if extras:
        parts: List[str] = []
        for k in sorted(extras.keys()):
            v = extras.get(k)
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                try:
                    v_str = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
                except Exception:
                    v_str = str(v)
            else:
                v_str = str(v)
            parts.append(f"{k}={v_str}")
        if parts:
            suffix = " ".join(parts)
            message = f"{message} {suffix}".strip()

    py_logger.log(_def_level_map.get(level, logging.INFO), message, extra={"go": extras})


# Global registry for logger instances
_logger_registry: Dict[str, logging.Logger] = {}

# Event-driven log monitoring system
_log_listeners: List[Callable[[List], None]] = []
_listener_thread: Optional[threading.Thread] = None
_listener_active: bool = False


def _start_log_listener() -> None:
    """Start background thread to drain Go log buffer and forward to Python loggers."""
    global _listener_thread, _listener_active
    if _listener_active and _listener_thread and _listener_thread.is_alive():
        return
    _listener_active = True

    def _run() -> None:
        # Drain loop: wait for entries with timeout to allow graceful shutdown
        while _listener_active:
            entries = backend.WaitForLogEntries(2000)

            if not entries:
                continue

            # Iterate returned entries; handle both attr and dict styles
            for entry in entries:
                try:
                    logger_id = getattr(entry, "LoggerID", None)
                    if logger_id is None and isinstance(entry, dict):
                        logger_id = entry.get("LoggerID")

                    message = getattr(entry, "Message", None)
                    if message is None and isinstance(entry, dict):
                        message = entry.get("Message")

                    if not message:
                        continue

                    py_logger = _logger_registry.get(str(logger_id)) or _logger
                    _emit_go_log(py_logger, str(message))
                except Exception:
                    # Never let logging path crash the listener
                    continue

    _listener_thread = threading.Thread(target=_run, name="masktunnel-go-log-listener", daemon=True)
    _listener_thread.start()


def _stop_log_listener() -> None:
    """Stop the background log listener thread."""
    global _listener_active
    _listener_active = False
    try:
        backend.CancelLogWaiters()
    except Exception:
        pass


class BufferZerologLogger:
    """Buffer-based logger system for Go bindings."""
    
    def __init__(self, py_logger: logging.Logger, logger_id: str):
        self.py_logger = py_logger
        self.logger_id = logger_id
        # Ensure background listener is running
        _start_log_listener()

        # Prefer Go logger with explicit ID so we can map entries back
        try:
            # Newer binding that tags entries with our provided ID
            self.go_logger = backend.NewLoggerWithID(self.logger_id)
        except Exception:
            # Fallback to older API; if present, still try callback path
            try:
                def log_callback(line: str) -> None:
                    _emit_go_log(py_logger, line)

                self.go_logger = backend.NewLogger(log_callback)
            except Exception:
                # As a last resort, create a default Go logger
                self.go_logger = backend.NewLoggerWithID(self.logger_id)  # may still raise; surface to caller
        _logger_registry[logger_id] = py_logger
    
    def cleanup(self):
        """Clean up logger resources."""
        if self.logger_id in _logger_registry:
            del _logger_registry[self.logger_id]


def set_log_level(level: Union[int, str]) -> None:
    """Set the global log level for masktunnel."""
    if isinstance(level, str):
        level = getattr(logging, level.upper())
    _logger.setLevel(level)
