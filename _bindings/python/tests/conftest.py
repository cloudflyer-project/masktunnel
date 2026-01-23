"""Pytest configuration for masktunnel tests."""

from __future__ import annotations

import json
import os
import random
import socket
import ssl
import subprocess
import threading
import time
import base64
import gzip
import hashlib
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Generator, Optional

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--integration-tests",
        action="store_true",
        default=False,
        help="run integration tests",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "integration_tests: mark test as integration test")
    config.addinivalue_line("markers", "crash: mark crash/stress tests")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--integration-tests"):
        return

    skip_mark = pytest.mark.skip(reason="need --integration-tests option to run")
    for item in items:
        if "integration_tests" in item.keywords:
            item.add_marker(skip_mark)


def _get_free_port(ipv6: bool = False, min_port: int = 10000, max_port: int = 65535) -> int:
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    for _ in range(2000):
        port = random.randint(min_port, max_port)
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("::1" if ipv6 else "127.0.0.1", port))
                return port
            except OSError:
                continue
    raise OSError("No free ports available")


def _wait_tcp(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except Exception as e:
            last_err = e
            time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for tcp {host}:{port}: {last_err}")


class _OriginHandler(BaseHTTPRequestHandler):
    server_version = "masktunnel-test-origin/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        # Keep tests quiet by default.
        return

    def _is_tls(self) -> bool:
        return isinstance(getattr(self, "connection", None), ssl.SSLSocket)

    def _send_json(self, obj: dict, status: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html: str, status: int = 200) -> None:
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_gzip(self, content: bytes, status: int = 200) -> None:
        gz = gzip.compress(content)
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(gz)))
        self.end_headers()
        self.wfile.write(gz)

    def _parse_qs(self) -> dict:
        parsed = urllib.parse.urlparse(self.path)
        return {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(parsed.query).items()}

    def _send_stream_fixed(self, numbytes: int) -> None:
        data = b"X" * numbytes
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_stream_chunked(self, numbytes: int, delay: float = 0.02) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        remaining = numbytes
        while remaining > 0:
            chunk = b"Y" * min(remaining, 3)
            remaining -= len(chunk)
            self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            time.sleep(delay)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _send_stream_close(self, numbytes: int) -> None:
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"Z" * numbytes)
        self.wfile.flush()

    def _handle_websocket_echo(self) -> None:
        guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        key = self.headers.get("Sec-WebSocket-Key", "")
        upgrade = self.headers.get("Upgrade", "").lower()
        connection = self.headers.get("Connection", "").lower()
        if upgrade != "websocket" or "upgrade" not in connection or not key:
            self.send_error(400)
            return

        accept = base64.b64encode(hashlib.sha1((key + guid).encode("ascii")).digest()).decode("ascii")
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode("ascii")
        self.connection.sendall(resp)

        try:
            header = self.rfile.read(2)
            if len(header) < 2:
                return
            b1, b2 = header[0], header[1]
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            length = b2 & 0x7F
            if length == 126:
                ext = self.rfile.read(2)
                length = int.from_bytes(ext, "big")
            elif length == 127:
                ext = self.rfile.read(8)
                length = int.from_bytes(ext, "big")

            mask_key = self.rfile.read(4) if masked else b""
            payload = self.rfile.read(length) if length else b""
            if masked and mask_key:
                payload = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))

            if opcode == 0x8:
                return

            out = bytes([0x81, len(payload)]) + payload
            self.connection.sendall(out)
        finally:
            self.close_connection = True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/ws"):
            return self._handle_websocket_echo()

        if path.startswith("/gzip"):
            return self._send_gzip(b"this content was gzipped")

        if path.startswith("/stream/fixed"):
            qs = self._parse_qs()
            numbytes = int(qs.get("numbytes", "7") or "7")
            return self._send_stream_fixed(numbytes)

        if path.startswith("/stream/chunked"):
            qs = self._parse_qs()
            numbytes = int(qs.get("numbytes", "7") or "7")
            delay = float(qs.get("delay", "0.02") or "0.02")
            return self._send_stream_chunked(numbytes, delay=delay)

        if path.startswith("/stream/close"):
            qs = self._parse_qs()
            numbytes = int(qs.get("numbytes", "7") or "7")
            return self._send_stream_close(numbytes)

        if self.path.startswith("/redirect/302"):
            self.send_response(302)
            self.send_header("Location", "/redirect/target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.startswith("/redirect/target"):
            return self._send_json(
                {
                    "protocol": "https" if self._is_tls() else "http",
                    "path": self.path,
                    "is_target": True,
                    "user_agent": self.headers.get("User-Agent", ""),
                }
            )

        if self.path.startswith("/html"):
            body = "<html><head><title>masktunnel</title></head><body>Hello</body></html>"
            return self._send_html(body)

        if self.path.startswith("/large-html"):
            body = "<html><head></head><body>" + ("A" * (2 * 1024 * 1024)) + "</body></html>"
            return self._send_html(body)

        if path.startswith("/stream"):
            # Backward-compatible default stream endpoint.
            qs = self._parse_qs()
            numbytes = int(qs.get("numbytes", "7") or "7")
            delay = float(qs.get("delay", "0.02") or "0.02")
            return self._send_stream_chunked(numbytes, delay=delay)

        return self._send_json(
            {
                "protocol": "https" if self._is_tls() else "http",
                "path": self.path,
                "user_agent": self.headers.get("User-Agent", ""),
                "host": self.headers.get("Host", ""),
            }
        )


def _openssl_available() -> bool:
    try:
        subprocess.run(["openssl", "version"], capture_output=True, text=True, check=True)
        return True
    except Exception:
        return False


def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    # Use OpenSSL to avoid extra Python deps.
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-subj",
        "/CN=localhost",
        "-days",
        "1",
    ]
    subprocess.run(cmd, capture_output=True, text=True, check=True)


@pytest.fixture(scope="session")
def http_origin() -> Generator[str, None, None]:
    host = "127.0.0.1"
    port = _get_free_port()

    server = ThreadingHTTPServer((host, port), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_tcp(host, port, timeout=5.0)

    yield f"http://{host}:{port}"

    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def https_origin(tmp_path_factory: pytest.TempPathFactory) -> Generator[str, None, None]:
    if not _openssl_available():
        pytest.skip("OpenSSL is required for local HTTPS origin tests")

    host = "127.0.0.1"
    port = _get_free_port()

    tmp = tmp_path_factory.mktemp("origin_tls")
    cert_path = tmp / "cert.pem"
    key_path = tmp / "key.pem"
    _generate_self_signed_cert(cert_path, key_path)

    server = ThreadingHTTPServer((host, port), _OriginHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _wait_tcp(host, port, timeout=5.0)

    yield f"https://localhost:{port}"

    server.shutdown()
    server.server_close()


@pytest.fixture()
def start_proxy(tmp_path: Path) -> Callable[..., dict]:
    """Factory fixture to start a masktunnel proxy server.

    Returns a dict containing: server, host, port, proxy_url, ca_path.
    """

    def _start(
        *,
        username: str = "",
        password: str = "",
        payload: str = "",
        user_agent: str = "",
        verbose: int = 0,
    ) -> dict:
        from masktunnel import Server
        from masktunnel._server import ServerOptions

        host = "127.0.0.1"
        port = _get_free_port()

        options = ServerOptions(
            addr=host,
            port=str(port),
            username=username,
            password=password,
            payload=payload,
            user_agent=user_agent,
            verbose=verbose,
        )
        server = Server(options=options)

        # Persist CA for requests verification.
        ca_path = tmp_path / f"masktunnel_ca_{port}.pem"
        ca_pem = server.get_ca_pem()
        ca_path.write_bytes(ca_pem)

        thread = threading.Thread(target=server.start, daemon=True)
        thread.start()
        _wait_tcp(host, port, timeout=8.0)

        return {
            "server": server,
            "host": host,
            "port": port,
            "proxy_url": f"http://{host}:{port}",
            "ca_path": str(ca_path),
        }

    return _start
