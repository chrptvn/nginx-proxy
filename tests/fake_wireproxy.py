"""Standalone fake wireproxy for tests: SOCKS5 relay + /readyz info endpoint.

Mimics the parts of wireproxy (https://github.com/pufferffish/wireproxy) that
HeaderProxy relies on:

    fake_wireproxy.py -c <wrapper-config> -i 127.0.0.1:<info-port>

* parses the wrapper config minimally — ``WGConfig`` must reference an
  existing file, ``[Socks5] BindAddress = host:port`` selects the SOCKS port;
* serves RFC1928 no-auth CONNECT on the SOCKS port and actually relays TCP to
  the requested target; every CONNECT target host is appended to the file in
  ``FAKE_SOCKS_LOG`` (one host per line, when the env var is set);
* serves ``GET /readyz`` on the info port with 503 until the SOCKS listener is
  bound, then 200 ``{"ready": true}`` (real wireproxy keeps it 503 until the
  tunnel handshakes; the fake has no tunnel, so binding is "ready").

Stdlib only, blocking sockets in threads — it runs as a separate process.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Set once the SOCKS5 listener is bound; gates /readyz.
_ready = threading.Event()
_socks_log: str | None = None
_log_lock = threading.Lock()


def _log_target(host: str) -> None:
    if not _socks_log:
        return
    with _log_lock:
        with open(_socks_log, "a") as f:
            f.write(host + "\n")


# -- wrapper config parsing ----------------------------------------------------


def parse_config(path: str) -> tuple[str, int]:
    """Return (bind_host, bind_port) from a minimal wireproxy config."""
    wgconfig: str | None = None
    bind: str | None = None
    section = ""
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key, value = key.strip().lower(), value.strip()
            if key == "wgconfig":
                wgconfig = value
            elif section == "socks5" and key == "bindaddress":
                bind = value
    if not wgconfig:
        _fail("config has no WGConfig line")
    if not os.path.isfile(wgconfig):
        _fail(f"WGConfig {wgconfig!r} does not exist")
    if not bind:
        _fail("config has no [Socks5] BindAddress")
    host, _, port = bind.rpartition(":")
    if not host or not port.isdigit():
        _fail(f"invalid [Socks5] BindAddress: {bind!r}")
    return host, int(port)


def _fail(message: str) -> None:
    print(f"fake_wireproxy: {message}", file=sys.stderr)
    sys.exit(1)


# -- info endpoint ----------------------------------------------------------------


class InfoHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        if self.path.split("?")[0] == "/readyz":
            ready = _ready.is_set()
            body = b'{"ready": true}' if ready else b'{"ready": false}'
            self.send_response(200 if ready else 503)
        else:
            body = b'{"error": "not found"}'
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# -- SOCKS5 server (RFC1928 no-auth CONNECT) -----------------------------------------


def _socks_handle(conn: socket.socket) -> None:
    try:
        head = conn.recv(2)
        if len(head) < 2 or head[0] != 0x05:
            return
        conn.recv(head[1])  # methods
        conn.sendall(b"\x05\x00")  # no-auth

        head = conn.recv(4)
        if len(head) < 4 or head[1] != 0x01:  # CONNECT only
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = head[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 0x03:
            host = conn.recv(conn.recv(1)[0]).decode()
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = int.from_bytes(conn.recv(2), "big")

        _log_target(host)
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            conn.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)  # general failure
            return
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        t1 = threading.Thread(target=_pipe, args=(conn, upstream), daemon=True)
        t2 = threading.Thread(target=_pipe, args=(upstream, conn), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)  # propagate EOF to the peer only
        except OSError:
            pass


def _serve_socks(bind_host: str, bind_port: int) -> socket.socket:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_host, bind_port))
    listener.listen(64)
    return listener


def main() -> None:
    global _socks_log
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", required=True)
    parser.add_argument("-i", "--info")
    args = parser.parse_args()

    _socks_log = os.environ.get("FAKE_SOCKS_LOG")

    bind_host, bind_port = parse_config(args.config)

    if args.info:
        info_host, _, info_port = args.info.rpartition(":")
        info = ThreadingHTTPServer((info_host, int(info_port)), InfoHandler)
        info.daemon_threads = True
        threading.Thread(target=info.serve_forever, daemon=True).start()

    listener = _serve_socks(bind_host, bind_port)
    _ready.set()  # socks listener is up: /readyz flips to 200
    print(f"fake_wireproxy: socks on {bind_host}:{bind_port}", file=sys.stderr, flush=True)

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            break
        threading.Thread(target=_socks_handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
