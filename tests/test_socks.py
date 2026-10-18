"""headerproxy.socks unit tests against the fake SOCKS5 server."""

from __future__ import annotations

import asyncio
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from headerproxy.socks import SocksError, socks5_connect

TESTS_DIR = Path(__file__).parent


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer:
    """Threaded TCP echo server (the relay target behind the fake proxy)."""

    def __init__(self) -> None:
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        self.server.daemon_threads = True
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture
def echo():
    server = EchoServer()
    yield server
    server.stop()


@pytest.fixture
def fake_socks(tmp_path):
    """Run tests/fake_wireproxy.py on a random port; wait until it accepts."""
    log_file = tmp_path / "socks.log"
    socks_port, info_port = _free_port(), _free_port()
    profile = tmp_path / "profile.conf"
    profile.write_text("[Interface]\n")
    config = tmp_path / "wrapper.conf"
    config.write_text(
        f"WGConfig = {profile}\n[Socks5]\nBindAddress = 127.0.0.1:{socks_port}\n"
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            str(TESTS_DIR / "fake_wireproxy.py"),
            "-c",
            str(config),
            "-i",
            f"127.0.0.1:{info_port}",
        ],
        env=dict(os.environ, FAKE_SOCKS_LOG=str(log_file)),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while True:
        try:
            socket.create_connection(("127.0.0.1", socks_port), timeout=0.5).close()
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError("fake wireproxy exited during startup")
            if time.monotonic() > deadline:
                proc.kill()
                raise RuntimeError("fake wireproxy never opened its SOCKS port")
            time.sleep(0.05)
    yield SimpleNamespace(port=socks_port, log=log_file, proc=proc)
    proc.terminate()
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()


async def _roundtrip(sock: socket.socket, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(sock=sock)
    writer.write(payload)
    await writer.drain()
    data = await reader.readexactly(len(payload))
    writer.close()
    return data


async def test_ip_literal_target_relays_data(fake_socks, echo):
    sock = await socks5_connect("127.0.0.1", fake_socks.port, "127.0.0.1", echo.port)
    assert await _roundtrip(sock, b"hello-via-ip") == b"hello-via-ip"


async def test_hostname_target_resolved_at_proxy(fake_socks, echo):
    # socks5h: "localhost" travels as DOMAINNAME and is resolved proxy-side;
    # the data path proves the relay works for name targets too.
    sock = await socks5_connect("127.0.0.1", fake_socks.port, "localhost", echo.port)
    assert await _roundtrip(sock, b"hello-via-name") == b"hello-via-name"
    assert "localhost" in fake_socks.log.read_text().splitlines()


async def test_domain_target_is_logged_even_when_unreachable(fake_socks):
    with pytest.raises(SocksError):
        await socks5_connect("127.0.0.1", fake_socks.port, "no-such-host.invalid", 80)
    assert "no-such-host.invalid" in fake_socks.log.read_text().splitlines()


async def test_unreachable_proxy_raises_socks_error():
    with pytest.raises(SocksError):
        await socks5_connect("127.0.0.1", 1, "127.0.0.1", 80)  # nothing listens on 1


async def test_proxy_rejecting_method_raises(fake_socks):
    # Connect a raw socket that answers with a bogus method selection reply.
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    threading.Thread(
        target=lambda: (
            listener.accept()[0].sendall(b"\x05\xff"),  # no acceptable methods
            listener.close(),
        ),
        daemon=True,
    ).start()
    port = listener.getsockname()[1]
    with pytest.raises(SocksError, match="no-auth"):
        await socks5_connect("127.0.0.1", port, "127.0.0.1", 80)
