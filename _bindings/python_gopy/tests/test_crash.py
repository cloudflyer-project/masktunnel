from __future__ import annotations

import socket
import threading
import time
from typing import Any, List

import pytest


class InvalidInputs:
    @staticmethod
    def invalid_strings() -> List[Any]:
        return [
            None,
            123,
            [],
            {},
            b"bytes",
            "\x00" * 1000,
            "a" * 200000,
            "\ud800",
            "",
        ]

    @staticmethod
    def invalid_ints() -> List[Any]:
        return [
            "not-an-int",
            [],
            {},
            None,
            3.14,
            -1,
            0,
            2**31,
            float("inf"),
            float("nan"),
        ]


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def _wait_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except Exception:
            time.sleep(0.02)
    return False


def _safe_stop_close(server) -> None:
    try:
        server.stop()
    except Exception:
        pass
    try:
        server.close()
    except Exception:
        pass


@pytest.mark.crash
def test_server_init_invalid_options_does_not_segfault():
    from masktunnel._server import Server, ServerOptions

    # Invalid types should raise Python exceptions or be coerced safely,
    # but must not crash the interpreter.
    bad_opts = [
        ServerOptions(port=123),
        ServerOptions(addr=123),
        ServerOptions(username=None),
        ServerOptions(password=None),
        ServerOptions(payload=None),
        ServerOptions(user_agent=None),
        ServerOptions(upstream_proxy=None),
        ServerOptions(verbose="1"),
    ]

    for opt in bad_opts:
        server = None
        try:
            server = Server(options=opt)
        except Exception:
            continue
        finally:
            if server is not None:
                _safe_stop_close(server)


@pytest.mark.crash
def test_server_init_options_invalid_strings_no_crash():
    from masktunnel._server import Server, ServerOptions

    invalid = InvalidInputs.invalid_strings()
    fields = [
        "addr",
        "port",
        "user_agent",
        "payload",
        "upstream_proxy",
        "username",
        "password",
    ]

    for field in fields:
        for v in invalid:
            server = None
            try:
                kwargs = {field: v}
                opt = ServerOptions(**kwargs)  # type: ignore[arg-type]
                server = Server(options=opt)
                try:
                    server.get_ca_pem()
                except Exception:
                    pass
                try:
                    server.reset_sessions()
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                if server is not None:
                    _safe_stop_close(server)


@pytest.mark.crash
def test_server_init_options_invalid_verbose_no_crash():
    from masktunnel._server import Server, ServerOptions

    for v in InvalidInputs.invalid_ints():
        server = None
        try:
            opt = ServerOptions(verbose=v)  # type: ignore[arg-type]
            server = Server(options=opt)
        except Exception:
            pass
        finally:
            if server is not None:
                _safe_stop_close(server)


@pytest.mark.crash
def test_set_upstream_proxy_invalid_inputs_no_crash():
    from masktunnel import Server

    invalid = [
        None,
        123,
        [],
        {},
        b"bytes",
        "\x00" * 50,
        "http://127.0.0.1:1",
        "",
        "http://",
        "socks5://127.0.0.1:1080",
        "http://user:pass@127.0.0.1:3128",
        "http://127.0.0.1:999999",
        "http://[::1]:3128",
        "http://127.0.0.1:notaport",
        "https://127.0.0.1:443",
    ]

    s = Server()
    try:
        for v in invalid:
            try:
                s.set_upstream_proxy(v)  # type: ignore[arg-type]
            except Exception:
                pass
    finally:
        _safe_stop_close(s)


@pytest.mark.crash
def test_set_upstream_proxy_repeated_no_crash():
    from masktunnel import Server

    s = Server()
    try:
        for _ in range(200):
            try:
                s.set_upstream_proxy("http://127.0.0.1:1")
            except Exception:
                pass
    finally:
        _safe_stop_close(s)


@pytest.mark.crash
def test_reset_sessions_repeated_no_crash():
    from masktunnel import Server

    s = Server()
    try:
        for _ in range(2000):
            try:
                s.reset_sessions()
            except Exception:
                pass
    finally:
        _safe_stop_close(s)


@pytest.mark.crash
def test_stop_close_idempotent_no_crash():
    from masktunnel import Server

    s = Server()
    try:
        for _ in range(50):
            try:
                s.stop()
            except Exception:
                pass
        for _ in range(50):
            try:
                s.close()
            except Exception:
                pass
        for _ in range(50):
            try:
                s.stop()
            except Exception:
                pass
    finally:
        _safe_stop_close(s)


@pytest.mark.crash
def test_start_stop_basic_lifecycle_no_crash():
    from masktunnel._server import Server, ServerOptions

    port = _get_free_port()
    server = Server(options=ServerOptions(addr="127.0.0.1", port=str(port)))

    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()

    _wait_tcp("127.0.0.1", port, timeout=3.0)
    _safe_stop_close(server)
    thread.join(timeout=5.0)
    assert not thread.is_alive()


@pytest.mark.crash
def test_start_on_port_in_use_no_crash():
    from masktunnel._server import Server, ServerOptions

    host = "127.0.0.1"
    port = _get_free_port()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((host, port))
    listener.listen(1)

    server = Server(options=ServerOptions(addr=host, port=str(port)))
    err_holder: list[BaseException] = []

    def _run() -> None:
        try:
            server.start()
        except BaseException as e:
            err_holder.append(e)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout=3.0)
    listener.close()

    _safe_stop_close(server)
    thread.join(timeout=3.0)
    assert not thread.is_alive()
    assert err_holder or True


@pytest.mark.crash
def test_many_servers_create_and_close_no_crash():
    from masktunnel import Server

    servers = []
    try:
        for _ in range(50):
            s = Server()
            servers.append(s)
            try:
                s.get_ca_pem()
            except Exception:
                pass
    finally:
        for s in servers:
            _safe_stop_close(s)
