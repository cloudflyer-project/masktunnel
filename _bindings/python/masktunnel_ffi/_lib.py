from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from cffi import FFI


_ffi = FFI()

_ffi.cdef(
    """
    typedef struct masktunnel_buf {
        uint8_t* data;
        int64_t len;
    } masktunnel_buf;

    void masktunnel_free(void* p);
    void masktunnel_buf_free(masktunnel_buf b);

    char* masktunnel_version(void);
    int64_t masktunnel_seconds(void);
    char* masktunnel_parse_duration(const char* s, int64_t* out);

    char* masktunnel_wait_for_log_entries(int64_t timeoutMs, masktunnel_buf* out);
    void masktunnel_cancel_log_waiters(void);

    uint64_t masktunnel_server_create(const char* opts_json);
    char* masktunnel_server_start(uint64_t h);
    char* masktunnel_server_start_background(uint64_t h);
    char* masktunnel_server_stop(uint64_t h);
    char* masktunnel_server_close(uint64_t h);
    char* masktunnel_server_addr(uint64_t h);
    char* masktunnel_server_reset_sessions(uint64_t h, int* out);
    char* masktunnel_server_set_upstream_proxy(uint64_t h, const char* proxy);
    char* masktunnel_server_get_ca_pem(uint64_t h, masktunnel_buf* out);
    """
)


def _detect_lib_name() -> str:
    if sys.platform.startswith("linux"):
        return "libmasktunnel.so"
    if sys.platform == "darwin":
        return "libmasktunnel.dylib"
    if os.name == "nt":
        return "masktunnel.dll"
    return "libmasktunnel_ffi.so"


def _load_library() -> Any:
    override = os.environ.get("MASKTUNNEL_FFI_LIB")
    if override:
        return _ffi.dlopen(override)

    libname = _detect_lib_name()

    # 1) next to this file
    here = Path(__file__).resolve().parent
    cand = here / libname
    if cand.exists():
        return _ffi.dlopen(str(cand))

    # 2) in masktunnel package (sibling directory)
    pkg_root = here.parent
    cand2 = pkg_root / "masktunnel" / libname
    if cand2.exists():
        return _ffi.dlopen(str(cand2))

    # 3) package root (wheel may place under data)
    cand3 = pkg_root / libname
    if cand3.exists():
        return _ffi.dlopen(str(cand3))

    # 4) fallback to loader search path
    return _ffi.dlopen(libname)


_lib = _load_library()


class MaskTunnelError(RuntimeError):
    pass


def _raise_if_err(err_ptr) -> None:
    if err_ptr == _ffi.NULL:
        return
    try:
        msg = _ffi.string(err_ptr).decode("utf-8", errors="replace")
    finally:
        _lib.masktunnel_free(err_ptr)
    raise MaskTunnelError(msg)


def _take_string(ptr) -> str:
    if ptr == _ffi.NULL:
        return ""
    try:
        return _ffi.string(ptr).decode("utf-8", errors="replace")
    finally:
        _lib.masktunnel_free(ptr)


def _take_buf(b) -> bytes:
    if b.data == _ffi.NULL or b.len == 0:
        return b""
    try:
        return bytes(_ffi.buffer(b.data, int(b.len)))
    finally:
        _lib.masktunnel_buf_free(b)


def version() -> str:
    return _take_string(_lib.masktunnel_version())


def seconds() -> int:
    return int(_lib.masktunnel_seconds())


def parse_duration(s: str) -> int:
    out = _ffi.new("int64_t*")
    err = _lib.masktunnel_parse_duration(s.encode("utf-8"), out)
    _raise_if_err(err)
    return int(out[0])


def wait_for_log_entries(timeout_ms: int) -> list[dict[str, Any]]:
    out = _ffi.new("masktunnel_buf*")
    err = _lib.masktunnel_wait_for_log_entries(int(timeout_ms), out)
    _raise_if_err(err)
    raw = _take_buf(out[0])
    if not raw:
        return []
    try:
        val = json.loads(raw.decode("utf-8", errors="replace"))
        if isinstance(val, list):
            return list(val)
        return []
    except Exception:
        return []


def cancel_log_waiters() -> None:
    _lib.masktunnel_cancel_log_waiters()


class Server:
    def __init__(self, cfg: dict[str, Any]):
        payload = json.dumps(cfg, separators=(",", ":")).encode("utf-8")
        h = _lib.masktunnel_server_create(payload)
        if h == 0:
            raise MaskTunnelError("failed to create server")
        self._h = int(h)

    def start(self) -> None:
        err = _lib.masktunnel_server_start(self._h)
        _raise_if_err(err)

    def start_background(self) -> None:
        err = _lib.masktunnel_server_start_background(self._h)
        _raise_if_err(err)

    def stop(self) -> None:
        err = _lib.masktunnel_server_stop(self._h)
        _raise_if_err(err)

    def close(self) -> None:
        if getattr(self, "_h", 0):
            err = _lib.masktunnel_server_close(self._h)
            self._h = 0
            _raise_if_err(err)

    def addr(self) -> str:
        ptr = _lib.masktunnel_server_addr(self._h)
        return _take_string(ptr)

    def reset_sessions(self) -> int:
        out = _ffi.new("int*")
        err = _lib.masktunnel_server_reset_sessions(self._h, out)
        _raise_if_err(err)
        return int(out[0])

    def set_upstream_proxy(self, proxy: str) -> None:
        err = _lib.masktunnel_server_set_upstream_proxy(self._h, proxy.encode("utf-8"))
        _raise_if_err(err)

    def get_ca_pem(self) -> bytes:
        out = _ffi.new("masktunnel_buf*")
        err = _lib.masktunnel_server_get_ca_pem(self._h, out)
        _raise_if_err(err)
        return _take_buf(out[0])
