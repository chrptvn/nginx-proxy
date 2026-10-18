"""Test-only origin server: echoes requests, serves big bodies, speaks WS."""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OriginTest/1.0"

    def log_message(self, *args):  # silence
        pass

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        record = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("latin-1"),
        }
        self.server.requests.append(record)

        if self.path.startswith("/ws"):
            self._websocket()
        elif self.path.startswith("/echo"):
            self._json(200, record)
        elif self.path.startswith("/big"):
            size = 1024 * 1024
            if "size=" in self.path:
                size = int(self.path.split("size=")[1].split("&")[0])
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if self.command != "HEAD":
                chunk = b"0123456789abcdef" * 1024  # 16 KiB
                sent = 0
                while sent < size:
                    n = min(len(chunk), size - sent)
                    self.wfile.write(chunk[:n])
                    sent += n
        elif self.path.startswith("/status/"):
            self._json(int(self.path.rsplit("/", 1)[1]), {"status": True})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Origin", "echo")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- minimal RFC6455 echo server ------------------------------------

    def _websocket(self) -> None:
        if (self.headers.get("Upgrade") or "").lower() != "websocket":
            self._json(400, {"error": "expected websocket upgrade"})
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = False
        try:
            while True:
                opcode, data = _read_frame(self.rfile)
                if opcode == 0x8:  # close
                    self.wfile.write(_encode_frame(0x8, b""))
                    self.wfile.flush()
                    break
                if opcode in (0x1, 0x2):  # text/binary echo
                    self.wfile.write(_encode_frame(opcode, data))
                    self.wfile.flush()
        except (ConnectionError, OSError, ValueError):
            pass

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = _handle


def _read_frame(rfile):
    head = rfile.read(2)
    if len(head) < 2:
        raise ConnectionError("short frame")
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = int.from_bytes(rfile.read(2), "big")
    elif length == 127:
        length = int.from_bytes(rfile.read(8), "big")
    mask = rfile.read(4) if masked else None
    data = rfile.read(length)
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


def _encode_frame(opcode: int, data: bytes) -> bytes:
    head = bytes([0x80 | opcode])
    n = len(data)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + n.to_bytes(2, "big")
    else:
        head += bytes([127]) + n.to_bytes(8, "big")
    return head + data


class OriginServer:
    """Threaded HTTP origin that records every request it receives."""

    def __init__(self, tls_ctx: ssl.SSLContext | None = None) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        self.server.daemon_threads = True
        self.server.requests = []
        if tls_ctx is not None:
            self.server.socket = tls_ctx.wrap_socket(self.server.socket, server_side=True)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def url(self) -> str:
        scheme = "https" if isinstance(self.server.socket, ssl.SSLSocket) else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    @property
    def requests(self) -> list[dict]:
        return self.server.requests

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
