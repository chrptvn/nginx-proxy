"""Raw WebSocket client that tunnels through an HTTP proxy (CONNECT)."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _read_until(sock: socket.socket, marker: bytes) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed while reading header")
        buf += chunk
    return buf


def _encode_masked(opcode: int, data: bytes) -> bytes:
    mask = os.urandom(4)
    head = bytes([0x80 | opcode])
    n = len(data)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 65536:
        head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    head += mask
    return head + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _read_frame(sock: socket.socket) -> tuple[int, bytes]:
    head = _recv_exact(sock, 2)
    opcode = head[0] & 0x0F
    length = head[1] & 0x7F
    if length == 126:
        length = int.from_bytes(_recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_recv_exact(sock, 8), "big")
    if head[1] & 0x80:  # server frames are not masked, but be lenient
        sock.recv(4)
    return opcode, _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        buf += chunk
    return buf


def ws_over_proxy(
    proxy_port: int,
    origin_host: str,
    origin_port: int,
    path: str = "/ws",
    tls: bool = False,
    ca_pem: bytes | None = None,
    message: bytes = b"hello-ws",
) -> bytes:
    """Perform the browser handshake through the proxy: CONNECT+TLS for
    ``wss://``, absolute-form GET for plain ``ws://``. Returns the echo."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    try:
        if tls:
            sock.sendall(
                f"CONNECT {origin_host}:{origin_port} HTTP/1.1\r\n"
                f"Host: {origin_host}:{origin_port}\r\n\r\n".encode()
            )
            status = _read_until(sock, b"\r\n\r\n")
            assert b" 200" in status, status
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            if ca_pem:
                ctx.load_verify_locations(ca_pem)
            else:
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=origin_host)
            request_target = path
        else:
            request_target = f"http://{origin_host}:{origin_port}{path}"

        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(
            f"GET {request_target} HTTP/1.1\r\n"
            f"Host: {origin_host}:{origin_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        response = _read_until(sock, b"\r\n\r\n")
        assert b" 101" in response, response

        sock.sendall(_encode_masked(0x1, message))
        opcode, echoed = _read_frame(sock)
        assert opcode == 0x1, opcode
        sock.sendall(_encode_masked(0x8, b""))
        return echoed
    finally:
        try:
            sock.close()
        except OSError:
            pass
