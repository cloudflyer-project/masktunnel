from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import urllib.parse
from typing import Optional, Tuple

import pytest


def _raw_http_request(
    host: str,
    port: int,
    request_bytes: bytes,
    *,
    timeout: float = 5.0,
) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(request_bytes)
        sock.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


def _split_http_response(raw: bytes) -> Tuple[str, dict, bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = (lines[0] if lines else b"").decode("iso-8859-1", errors="replace")
    headers: dict = {}
    for line in lines[1:]:
        if not line:
            continue
        k, sep, v = line.partition(b":")
        if not sep:
            continue
        headers[k.decode("iso-8859-1", errors="replace").strip().lower()] = v.decode(
            "iso-8859-1", errors="replace"
        ).strip()
    return status_line, headers, body


def _try_unchunk(body: bytes) -> Optional[bytes]:
    out = bytearray()
    i = 0
    n = len(body)
    try:
        while True:
            j = body.find(b"\r\n", i)
            if j < 0:
                return None
            size_line = body[i:j].decode("ascii").strip()
            if not size_line:
                return None
            size = int(size_line.split(";", 1)[0], 16)
            i = j + 2
            if size == 0:
                return bytes(out)
            if i + size > n:
                return None
            out.extend(body[i : i + size])
            i += size
            if body[i : i + 2] != b"\r\n":
                return None
            i += 2
    except Exception:
        return None


def _looks_chunked(body: bytes) -> bool:
    # Heuristic: starts with hex chunk-size line and ends with terminating chunk.
    if not body:
        return False
    if b"\r\n" not in body:
        return False
    first_line = body.split(b"\r\n", 1)[0].strip()
    if not first_line:
        return False
    # chunk-size is hex digits, optionally with extensions after ';'
    size_part = first_line.split(b";", 1)[0]
    if not all(c in b"0123456789abcdefABCDEF" for c in size_part):
        return False
    return body.rstrip().endswith(b"0\r\n\r\n")


def _normalize_body(headers: dict, body: bytes) -> bytes:
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te or _looks_chunked(body):
        dechunked = _try_unchunk(body)
        if dechunked is not None:
            return dechunked
    return body


def _basic_auth_value(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _proxy_get(
    proxy_host: str,
    proxy_port: int,
    url: str,
    *,
    user_agent: str = "",
    proxy_auth: str = "",
    timeout: float = 10.0,
) -> Tuple[str, dict, bytes]:
    host_header = url.split("://", 1)[1].split("/", 1)[0]
    lines = [
        f"GET {url} HTTP/1.1",
        f"Host: {host_header}",
        "Connection: close",
    ]
    if user_agent:
        lines.append(f"User-Agent: {user_agent}")
    if proxy_auth:
        lines.append(f"Proxy-Authorization: {proxy_auth}")
    raw_req = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
    raw_resp = _raw_http_request(proxy_host, proxy_port, raw_req, timeout=timeout)
    return _split_http_response(raw_resp)


def _proxy_post_direct(
    proxy_host: str,
    proxy_port: int,
    path: str,
    body: bytes = b"",
    *,
    timeout: float = 10.0,
) -> Tuple[str, dict, bytes]:
    lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {proxy_host}:{proxy_port}",
        "Connection: close",
        f"Content-Length: {len(body)}",
    ]
    raw_req = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
    raw_resp = _raw_http_request(proxy_host, proxy_port, raw_req, timeout=timeout)
    return _split_http_response(raw_resp)


def _mitm_https_get(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    ca_path: str,
    path: str,
    *,
    user_agent: str = "",
    timeout: float = 15.0,
) -> Tuple[str, dict, bytes]:
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        connect_req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("utf-8")
        sock.sendall(connect_req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = sock.recv(4096)
            if not data:
                break
            buf += data
        status_line, _headers, _rest = _split_http_response(buf)
        assert " 200 " in status_line

        ctx = ssl.create_default_context(cafile=ca_path)
        with ctx.wrap_socket(sock, server_hostname=target_host) as tls_sock:
            req_lines = [
                f"GET {path} HTTP/1.1",
                f"Host: {target_host}:{target_port}",
                "Connection: close",
            ]
            if user_agent:
                req_lines.append(f"User-Agent: {user_agent}")
            tls_sock.sendall(("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8"))
            chunks: list[bytes] = []
            while True:
                data = tls_sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
            return _split_http_response(b"".join(chunks))


def _ws_masked_text_frame(payload: bytes) -> bytes:
    if len(payload) > 125:
        raise ValueError("payload too large")
    mask_key = os.urandom(4)
    masked = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))
    return bytes([0x81, 0x80 | len(payload)]) + mask_key + masked


def _ws_read_frame(sock: socket.socket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    h = sock.recv(2)
    if len(h) < 2:
        raise RuntimeError("incomplete ws frame header")
    b1, b2 = h[0], h[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    ln = b2 & 0x7F
    if ln == 126:
        ext = sock.recv(2)
        ln = int.from_bytes(ext, "big")
    elif ln == 127:
        ext = sock.recv(8)
        ln = int.from_bytes(ext, "big")
    mask_key = sock.recv(4) if masked else b""
    payload = b""
    while len(payload) < ln:
        chunk = sock.recv(ln - len(payload))
        if not chunk:
            break
        payload += chunk
    if masked and mask_key:
        payload = bytes(payload[i] ^ mask_key[i % 4] for i in range(len(payload)))
    if opcode == 0x8:
        raise RuntimeError("ws closed")
    return payload


def _ws_echo_via_http_proxy(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    path: str,
    message: bytes,
    *,
    timeout: float = 10.0,
) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    target_url = f"http://{target_host}:{target_port}{path}"
    req = (
        f"GET {target_url} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode("ascii")

    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = sock.recv(4096)
            if not data:
                break
            buf += data
        status_line, _headers, _rest = _split_http_response(buf)
        assert " 101 " in status_line

        sock.sendall(_ws_masked_text_frame(message))
        return _ws_read_frame(sock, timeout=timeout)


def _ws_echo_via_connect_tls(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    ca_path: str,
    path: str,
    message: bytes,
    *,
    timeout: float = 15.0,
) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        connect_req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("utf-8")
        sock.sendall(connect_req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = sock.recv(4096)
            if not data:
                break
            buf += data
        status_line, _headers, _rest = _split_http_response(buf)
        assert " 200 " in status_line

        ctx = ssl.create_default_context(cafile=ca_path)
        with ctx.wrap_socket(sock, server_hostname=target_host) as tls_sock:
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n"
            ).encode("ascii")
            tls_sock.sendall(req)
            buf2 = b""
            while b"\r\n\r\n" not in buf2:
                data = tls_sock.recv(4096)
                if not data:
                    break
                buf2 += data
            status_line2, _headers2, _rest2 = _split_http_response(buf2)
            assert " 101 " in status_line2

            tls_sock.sendall(_ws_masked_text_frame(message))
            return _ws_read_frame(tls_sock, timeout=timeout)


def test_imports():
    import masktunnel

    assert hasattr(masktunnel, "__version__")
    assert hasattr(masktunnel, "Server")
    assert hasattr(masktunnel, "set_log_level")


def test_http_proxy_basic(start_proxy, http_origin):
    p = start_proxy()
    try:
        url = http_origin + "/"
        status, _headers, body = _proxy_get(
            p["host"],
            p["port"],
            url,
            user_agent="masktunnel-test-agent",
            timeout=10,
        )
        assert status.startswith("HTTP/1.1 200")
        data = json.loads(body.decode("utf-8"))
        assert data["protocol"] == "http"
        assert data["user_agent"] == "masktunnel-test-agent"
    finally:
        p["server"].stop()
        p["server"].close()


def test_http_proxy_redirect_passthrough(start_proxy, http_origin):
    p = start_proxy()
    try:
        status, headers, _body = _proxy_get(
            p["host"],
            p["port"],
            http_origin + "/redirect/302",
            timeout=10,
        )
        assert status.startswith("HTTP/1.1 302")
        assert headers.get("location") == "/redirect/target"
    finally:
        p["server"].stop()
        p["server"].close()


@pytest.mark.integration_tests
def test_https_mitm_with_ca_verification(start_proxy, https_origin):
    p = start_proxy()
    try:
        # https_origin is like https://localhost:PORT
        target_port = int(https_origin.rsplit(":", 1)[1])
        status, _headers, body = _mitm_https_get(
            p["host"],
            p["port"],
            "localhost",
            target_port,
            p["ca_path"],
            "/",
            user_agent="masktunnel-test-agent",
            timeout=15,
        )
        assert status.startswith("HTTP/1.1 200")
        data = json.loads(body.decode("utf-8"))
        assert data["protocol"] == "https"
        assert data["user_agent"] == "masktunnel-test-agent"
    finally:
        p["server"].stop()
        p["server"].close()


def test_payload_injection_http(start_proxy, http_origin):
    p = start_proxy(payload="window.__masktunnel_injected = true;")
    try:
        status, headers, body = _proxy_get(p["host"], p["port"], http_origin + "/html", timeout=10)
        assert status.startswith("HTTP/1.1 200")
        assert "text/html" in headers.get("content-type", "")
        assert b"window.__masktunnel_injected = true" in body
    finally:
        p["server"].stop()
        p["server"].close()


@pytest.mark.integration_tests
def test_payload_injection_https(start_proxy, https_origin):
    p = start_proxy(payload="window.__masktunnel_injected = true;")
    try:
        target_port = int(https_origin.rsplit(":", 1)[1])
        status, headers, body = _mitm_https_get(
            p["host"],
            p["port"],
            "localhost",
            target_port,
            p["ca_path"],
            "/html",
            timeout=15,
        )
        assert status.startswith("HTTP/1.1 200")
        assert "text/html" in headers.get("content-type", "")
        assert b"window.__masktunnel_injected = true" in body
    finally:
        p["server"].stop()
        p["server"].close()


def test_streaming_http_response(start_proxy, http_origin):
    p = start_proxy()
    try:
        status, headers, body = _proxy_get(
            p["host"],
            p["port"],
            http_origin + "/stream?numbytes=9&delay=0.01",
            timeout=10,
        )
        assert status.startswith("HTTP/1.1 200")
        body2 = _normalize_body(headers, body)
        assert body2 == (b"Y" * 9)
    finally:
        p["server"].stop()
        p["server"].close()


def test_content_encoding_gzip_http(start_proxy, http_origin):
    p = start_proxy()
    try:
        status, headers, body = _proxy_get(p["host"], p["port"], http_origin + "/gzip", timeout=10)
        assert status.startswith("HTTP/1.1 200")
        assert headers.get("content-encoding", "") == ""
        assert _normalize_body(headers, body) == b"this content was gzipped"
    finally:
        p["server"].stop()
        p["server"].close()


@pytest.mark.integration_tests
def test_content_encoding_gzip_https(start_proxy, https_origin):
    p = start_proxy()
    try:
        target_port = int(https_origin.rsplit(":", 1)[1])
        status, headers, body = _mitm_https_get(
            p["host"],
            p["port"],
            "localhost",
            target_port,
            p["ca_path"],
            "/gzip",
            timeout=15,
        )
        assert status.startswith("HTTP/1.1 200")
        assert headers.get("content-encoding", "") == ""
        assert _normalize_body(headers, body) == b"this content was gzipped"
    finally:
        p["server"].stop()
        p["server"].close()


def test_stream_fixed_http(start_proxy, http_origin):
    p = start_proxy()
    try:
        status, headers, body = _proxy_get(
            p["host"],
            p["port"],
            http_origin + "/stream/fixed?numbytes=7",
            timeout=10,
        )
        assert status.startswith("HTTP/1.1 200")
        body2 = _normalize_body(headers, body)
        assert body2 == (b"X" * 7)
    finally:
        p["server"].stop()
        p["server"].close()


def test_stream_chunked_http(start_proxy, http_origin):
    p = start_proxy()
    try:
        status, headers, body = _proxy_get(
            p["host"],
            p["port"],
            http_origin + "/stream/chunked?numbytes=7&delay=0.01",
            timeout=10,
        )
        assert status.startswith("HTTP/1.1 200")
        body2 = _normalize_body(headers, body)
        assert body2 == (b"Y" * 7)
    finally:
        p["server"].stop()
        p["server"].close()


def test_stream_close_http(start_proxy, http_origin):
    p = start_proxy()
    try:
        status, headers, body = _proxy_get(
            p["host"],
            p["port"],
            http_origin + "/stream/close?numbytes=7",
            timeout=10,
        )
        assert status.startswith("HTTP/1.1 200")
        body2 = _normalize_body(headers, body)
        assert body2 == (b"Z" * 7)
    finally:
        p["server"].stop()
        p["server"].close()


def test_websocket_ws_via_proxy(start_proxy, http_origin):
    p = start_proxy()
    try:
        parsed = urllib.parse.urlparse(http_origin)
        target_host = parsed.hostname or "127.0.0.1"
        target_port = int(parsed.port or 80)
        echoed = _ws_echo_via_http_proxy(
            p["host"],
            p["port"],
            target_host,
            target_port,
            "/ws",
            b"hello ws",
            timeout=10,
        )
        assert echoed == b"hello ws"
    finally:
        p["server"].stop()
        p["server"].close()


@pytest.mark.integration_tests
def test_websocket_wss_via_proxy(start_proxy, https_origin):
    p = start_proxy()
    try:
        target_port = int(https_origin.rsplit(":", 1)[1])
        echoed = _ws_echo_via_connect_tls(
            p["host"],
            p["port"],
            "localhost",
            target_port,
            p["ca_path"],
            "/ws",
            b"hello wss",
            timeout=20,
        )
        assert echoed == b"hello wss"
    finally:
        p["server"].stop()
        p["server"].close()


def test_large_html_no_crash(start_proxy, http_origin):
    p = start_proxy(payload="window.__masktunnel_injected = true;")
    try:
        status, _headers, body = _proxy_get(p["host"], p["port"], http_origin + "/large-html", timeout=30)
        assert status.startswith("HTTP/1.1 200")
        assert b"window.__masktunnel_injected = true" in body
        assert len(body) > 1024 * 1024
    finally:
        p["server"].stop()
        p["server"].close()


def test_internal_reset_sessions_api(start_proxy):
    p = start_proxy()
    try:
        status, _headers, body = _proxy_post_direct(p["host"], p["port"], "/__masktunnel__/reset", b"", timeout=10)
        assert status.startswith("HTTP/1.1 200")
        data = json.loads(body.decode("utf-8"))
        assert data.get("success") is True
        assert isinstance(data.get("closed_sessions"), int)
    finally:
        p["server"].stop()
        p["server"].close()


def test_internal_set_proxy_api(start_proxy):
    p = start_proxy()
    try:
        body = b"http://127.0.0.1:1"
        status, _headers, resp_body = _proxy_post_direct(p["host"], p["port"], "/__masktunnel__/proxy", body, timeout=10)
        assert status.startswith("HTTP/1.1 200")
        data = json.loads(resp_body.decode("utf-8"))
        assert data.get("success") is True
        assert data.get("proxy") == "http://127.0.0.1:1"
        assert isinstance(data.get("closed_sessions"), int)
    finally:
        p["server"].stop()
        p["server"].close()


def test_basic_auth_rejects_missing_credentials(start_proxy, http_origin):
    p = start_proxy(username="u", password="p")
    try:
        # Raw proxy request without Proxy-Authorization.
        origin_url = http_origin + "/"
        host_header = http_origin.split("://", 1)[1]
        req = (
            f"GET {origin_url} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")
        raw = _raw_http_request(p["host"], p["port"], req)
        assert raw.startswith(b"HTTP/1.1 407")
    finally:
        p["server"].stop()
        p["server"].close()


def test_basic_auth_allows_valid_credentials(start_proxy, http_origin):
    p = start_proxy(username="u", password="p")
    try:
        origin_url = http_origin + "/"
        host_header = http_origin.split("://", 1)[1]
        auth = _basic_auth_value("u", "p")
        req = (
            f"GET {origin_url} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Proxy-Authorization: {auth}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")
        raw = _raw_http_request(p["host"], p["port"], req)
        assert raw.startswith(b"HTTP/1.1 200")
    finally:
        p["server"].stop()
        p["server"].close()
